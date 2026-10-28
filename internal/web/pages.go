// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package web

import (
	"errors"
	"math"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/woozymasta/guassp/internal/observability"
	"github.com/woozymasta/guassp/internal/reconcile"
	"github.com/woozymasta/guassp/internal/scheduler"
)

const statsRunsPerPage = 25

// formPageData contains safe values rendered by the manual sync page.
type formPageData struct {
	// Version identifies the current service build.
	Version string
	// Input preserves the submitted text when rendering a result.
	Input string
	// Error is a safe user-facing failure message.
	Error string
	// Project is the canonical GitLab path resolved by the API.
	Project string
	// ProjectID identifies the resolved GitLab project.
	ProjectID int64
	// Queued reports that scheduler submission succeeded.
	Queued bool
	// Coalesced reports that the request joined existing project work.
	Coalesced bool
	// ManualFullSync controls whether the full-sync action is available.
	ManualFullSync bool
	// FullSyncAccepted reports that a manual full cycle was queued by this request.
	FullSyncAccepted bool
	// FullSyncQueued reports that a manual cycle is waiting to start.
	FullSyncQueued bool
	// FullSyncRunning reports that a full discovery cycle is active.
	FullSyncRunning bool
}

// statsPageData contains aggregate operational data for the stats page.
type statsPageData struct {
	// Upstreams contains only the latest bounded adapter state.
	Upstreams map[string]observability.UpstreamStatus
	// Version identifies the current service build.
	Version string
	// Uptime is formatted for display without exposing process internals.
	Uptime string
	// Runs contains the newest bounded reconciliation summaries.
	Runs []observability.Run
	// FullSync contains the latest scheduled discovery state.
	FullSync scheduler.FullSyncStatus
	// Totals aggregates recent outcomes and permission writes.
	Totals runTotals
	// Scheduler contains current queue and worker counts.
	Scheduler scheduler.Stats
	// RunPage is the one-based selected run-history page.
	RunPage int
	// RunPages is the number of pages in the retained run history.
	RunPages int
	// PreviousRunPage is the page containing newer runs.
	PreviousRunPage int
	// NextRunPage is the page containing older runs.
	NextRunPage int
	// RunTotal is the number of runs retained in memory.
	RunTotal int
	// RunFirst is the first displayed run's position in retained history.
	RunFirst int
	// RunLast is the last displayed run's position in retained history.
	RunLast int
	// HasPreviousRunPage reports whether newer history is available.
	HasPreviousRunPage bool
	// HasNextRunPage reports whether older history is available.
	HasNextRunPage bool
	// HasScheduler reports whether the scheduler exposes queue statistics.
	HasScheduler bool
	// HasFullSync reports whether scheduled discovery is configured.
	HasFullSync bool
}

// runTotals summarizes recent runs without exposing per-user data.
type runTotals struct {
	// Success counts recent successful reconciliations.
	Success int
	// Partial counts recent partial reconciliations.
	Partial int
	// Failed counts recent failed reconciliations.
	Failed int
	// Skipped counts recent skipped reconciliations.
	Skipped int
	// Grants counts successful grants across recent runs.
	Grants int
	// Revokes counts successful revocations across recent runs.
	Revokes int
}

// home renders the manual sync form after optional Basic authentication.
func (server *Server) home(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	if !server.authorizeWeb(writer, request) {
		return
	}

	server.renderFormPage(writer, http.StatusOK, formPageData{Version: server.buildVersion})
}

// homeSubmit accepts a bounded form request and queues one manual sync.
func (server *Server) homeSubmit(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	if !server.authorizeWeb(writer, request) {
		return
	}

	if !isFormContentType(request.Header.Get("Content-Type")) {
		server.renderFormPage(writer, http.StatusUnsupportedMediaType, formPageData{
			Version: server.buildVersion,
			Error:   "form encoded project input is required",
		})

		return
	}

	request.Body = http.MaxBytesReader(writer, request.Body, maxManualBodyBytes)
	if err := request.ParseForm(); err != nil {
		status, message := http.StatusBadRequest, "invalid form input"
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			status, message = http.StatusRequestEntityTooLarge, "project input is too large"
		}
		server.renderFormPage(writer, status, formPageData{
			Version: server.buildVersion,
			Error:   message,
		})
		return
	}

	if request.PostForm.Get("action") == "full_sync" {
		if !server.enableManualFullSync {
			http.NotFound(writer, request)
			return
		}

		accepted := server.queueFullSync("web")
		data := formPageData{
			Version:          server.buildVersion,
			FullSyncAccepted: accepted,
		}
		status := http.StatusAccepted
		if !accepted {
			status = http.StatusConflict
			data.Error = "full synchronization is already queued or running"
		}
		server.renderFormPage(writer, status, data)
		return
	}

	if !server.allowHTMLRequest(writer, request) {
		return
	}

	project := strings.TrimSpace(request.PostForm.Get("project"))
	if project == "" {
		server.renderFormPage(writer, http.StatusBadRequest, formPageData{
			Version: server.buildVersion,
			Error:   "GitLab project input is required",
		})
		return
	}

	response, status, message := server.queueManual(request.Context(), project)
	data := formPageData{
		Version:   server.buildVersion,
		Input:     project,
		Error:     message,
		Project:   response.Project,
		ProjectID: response.ProjectID,
		Queued:    status == http.StatusAccepted,
		Coalesced: response.Coalesced,
	}

	pageStatus := http.StatusOK
	if status != http.StatusAccepted {
		pageStatus = status
	}

	server.renderFormPage(writer, pageStatus, data)
}

// renderFormPage adds the current full-sync state to the manual operation page.
func (server *Server) renderFormPage(writer http.ResponseWriter, status int, data formPageData) {
	data.ManualFullSync = server.enableManualFullSync
	if server.enableManualFullSync {
		fullSyncStatus := server.fullSync.Status()
		data.FullSyncQueued = fullSyncStatus.Queued
		data.FullSyncRunning = fullSyncStatus.Running
	}
	server.renderPage(writer, status, "form", data)
}

// isFormContentType accepts standard URL-encoded forms with optional parameters.
func isFormContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/x-www-form-urlencoded"
}

// statsPage renders aggregate state and the bounded recent run list.
func (server *Server) statsPage(writer http.ResponseWriter, request *http.Request) {
	if !server.authorizeWeb(writer, request) {
		return
	}

	history := server.observability.Runs(server.observability.RunCapacity())
	pageCount := max(1, (len(history)+statsRunsPerPage-1)/statsRunsPerPage)
	currentPage := 1
	if requestedPage, err := strconv.Atoi(request.URL.Query().Get("page")); err == nil && requestedPage > 1 {
		currentPage = min(requestedPage, pageCount)
	}
	firstRun := (currentPage - 1) * statsRunsPerPage
	lastRun := min(firstRun+statsRunsPerPage, len(history))

	page := statsPageData{
		Version:            server.buildVersion,
		Uptime:             time.Since(server.startedAt).Round(time.Second).String(),
		Upstreams:          server.observability.Upstreams(),
		Runs:               history[firstRun:lastRun],
		RunPage:            currentPage,
		RunPages:           pageCount,
		PreviousRunPage:    max(1, currentPage-1),
		NextRunPage:        min(pageCount, currentPage+1),
		RunTotal:           len(history),
		RunFirst:           firstRun + 1,
		RunLast:            lastRun,
		HasPreviousRunPage: currentPage > 1,
		HasNextRunPage:     currentPage < pageCount,
	}

	if page.Uptime == "" || strings.HasPrefix(page.Uptime, "-") {
		page.Uptime = "0s"
	}
	if source, ok := server.scheduler.(interface{ Stats() scheduler.Stats }); ok {
		page.Scheduler, page.HasScheduler = source.Stats(), true
	}
	if server.fullSync != nil {
		page.FullSync, page.HasFullSync = server.fullSync.Status(), true
	}

	for _, run := range history {
		switch run.Result {
		case reconcile.StatusSuccess:
			page.Totals.Success++

		case reconcile.StatusPartial:
			page.Totals.Partial++

		case reconcile.StatusFailed:
			page.Totals.Failed++

		case reconcile.StatusSkipped:
			page.Totals.Skipped++
		}

		page.Totals.Grants += run.Counts.Grants
		page.Totals.Revokes += run.Counts.Revokes
	}

	server.renderPage(writer, http.StatusOK, "stats", page)
}

// allowHTMLRequest applies the manual per-IP rate limit and renders form errors.
func (server *Server) allowHTMLRequest(writer http.ResponseWriter, request *http.Request) bool {
	remoteIP, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil || net.ParseIP(remoteIP) == nil {
		server.renderFormPage(writer, http.StatusBadRequest, formPageData{
			Version: server.buildVersion, Error: "invalid remote address",
		})

		return false
	}

	allowed, retryAfter := server.limiter.Allow(remoteIP)
	if !allowed {
		retrySeconds := int64(math.Ceil(retryAfter.Seconds()))
		writer.Header().Set("Retry-After", strconv.FormatInt(retrySeconds, 10))
		server.renderFormPage(writer, http.StatusTooManyRequests, formPageData{
			Version: server.buildVersion, Error: "manual sync rate limit exceeded",
		})

		return false
	}

	return true
}

// renderPage executes one embedded template with restrictive response headers.
func (server *Server) renderPage(writer http.ResponseWriter, status int, name string, data any) {
	writer.Header().
		Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().
		Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	writer.WriteHeader(status)

	if err := server.templates.ExecuteTemplate(writer, name, data); err != nil {
		server.logger.Error().
			Str("component", "http").
			Str("operation", "render web page").
			Msg("template rendering failed")
	}
}
