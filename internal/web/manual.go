// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/woozymasta/guassp/internal/httpclient"
	"github.com/woozymasta/guassp/internal/scheduler"
)

// manualSync resolves a caller-provided project reference and queues it.
func (server *Server) manualSync(writer http.ResponseWriter, request *http.Request) {
	if event := server.logger.Trace(); event.Enabled() {
		event.Str("operation", "accept manual sync").
			Str("source", "manual").
			Str("path", request.URL.Path).
			Msg("HTTP request received")
	}

	if !server.authorizeWeb(writer, request) {
		return
	}
	if !server.allowManualRequest(writer, request) {
		return
	}
	if !isJSONContentType(request.Header.Get("Content-Type")) {
		writeError(writer, http.StatusUnsupportedMediaType, "JSON project input is required")
		return
	}

	request.Body = http.MaxBytesReader(writer, request.Body, maxManualBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var body manualSyncRequest
	if err := decoder.Decode(&body); err != nil {
		writeManualDecodeError(writer, err)
		return
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeManualDecodeError(writer, err)
		return
	}

	server.submitManual(writer, request, body.Project)
}

// submitManual resolves one project and submits it as high-priority manual work.
func (server *Server) submitManual(writer http.ResponseWriter, request *http.Request, reference string) {
	response, status, message := server.queueManual(request.Context(), reference)
	if status != http.StatusAccepted {
		writeError(writer, status, message)
		return
	}

	writeJSON(writer, http.StatusAccepted, response)
}

// queueManual resolves one project and submits it as high-priority manual work.
func (server *Server) queueManual(ctx context.Context, reference string) (ManualSyncResponse, int, string) {
	started := time.Now()
	project, err := server.projectResolver.Resolve(ctx, reference)
	if err != nil {
		status, message := manualResolutionFailure(err)
		server.logger.Warn().
			Str("component", "http").
			Str("operation", "resolve manual project").
			Int("http_status", status).
			Msg("manual project resolution failed")

		return ManualSyncResponse{}, status, message
	}

	submission, err := server.scheduler.Submit(project.ID, scheduler.PriorityHigh, "manual")
	if err != nil {
		server.logger.Error().
			Str("component", "http").
			Str("operation", "queue manual project reconciliation").
			Int64("gitlab_project_id", project.ID).
			Msg("manual project submission failed")

		return ManualSyncResponse{}, http.StatusInternalServerError, "unable to queue project synchronization"
	}

	if !submission.Accepted {
		return ManualSyncResponse{}, http.StatusServiceUnavailable, "service is shutting down"
	}
	server.logger.Info().
		Str("operation", "queue project synchronization").
		Str("source", "manual").
		Int64("gitlab_project_id", project.ID).
		Str("gitlab_project_path", project.PathWithNamespace).
		Dur("duration", time.Since(started)).
		Bool("coalesced", submission.Coalesced).
		Int("http_status", http.StatusAccepted).
		Msg("project synchronization request accepted")

	return ManualSyncResponse{
		ProjectID: project.ID,
		Project:   project.PathWithNamespace,
		Source:    "manual",
		Status:    "queued",
		Coalesced: submission.Coalesced,
	}, http.StatusAccepted, ""
}

// authorizeWeb checks optional Basic credentials for browser pages and manual requests.
func (server *Server) authorizeWeb(writer http.ResponseWriter, request *http.Request) bool {
	if _, apiAuthorized := request.Context().Value(apiAuthorizationContextKey{}).(struct{}); apiAuthorized {
		return true
	}
	if server.basicUser == "" {
		return true
	}

	username, password, ok := request.BasicAuth()
	if !ok ||
		subtle.ConstantTimeCompare([]byte(username), []byte(server.basicUser)) != 1 ||
		subtle.ConstantTimeCompare([]byte(password), []byte(server.basicPassword)) != 1 {
		writer.Header().Set("WWW-Authenticate", `Basic realm="guassp"`)
		if event := server.logger.Debug(); event.Enabled() {
			event.Str("operation", "authorize web request").
				Int("http_status", http.StatusUnauthorized).
				Msg("web authentication rejected")
		}
		writeError(writer, http.StatusUnauthorized, "authentication required")

		return false
	}

	return true
}

// allowManualRequest applies the configured rate limit to a remote IP address.
func (server *Server) allowManualRequest(writer http.ResponseWriter, request *http.Request) bool {
	remoteIP, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil || net.ParseIP(remoteIP) == nil {
		writeError(writer, http.StatusBadRequest, "invalid remote address")
		return false
	}

	allowed, retryAfter := server.limiter.Allow(remoteIP)
	if !allowed {
		if event := server.logger.Debug(); event.Enabled() {
			event.Str("operation", "apply manual sync rate limit").
				Int("http_status", http.StatusTooManyRequests).
				Msg("manual sync rate limit exceeded")
		}
		retrySeconds := int64(math.Ceil(retryAfter.Seconds()))
		writer.Header().Set("Retry-After", strconv.FormatInt(retrySeconds, 10))
		writeError(writer, http.StatusTooManyRequests, "manual sync rate limit exceeded")
		return false
	}

	return true
}

// writeManualDecodeError maps bounded JSON decoder failures to stable responses.
func writeManualDecodeError(writer http.ResponseWriter, err error) {
	if _, isMaxBytesError := errors.AsType[*http.MaxBytesError](err); isMaxBytesError {
		writeError(writer, http.StatusRequestEntityTooLarge, "project input is too large")
		return
	}

	if errors.Is(err, io.EOF) {
		writeError(writer, http.StatusBadRequest, "project input is required")
		return
	}

	writeError(writer, http.StatusBadRequest, "malformed project input")
}

// manualResolutionFailure maps input errors and sanitized GitLab API errors.
func manualResolutionFailure(err error) (int, string) {
	if apiError, isAPIError := errors.AsType[*httpclient.Error](err); isAPIError {
		if apiError.StatusCode == http.StatusNotFound {
			return http.StatusNotFound, "GitLab project was not found"
		}

		return http.StatusBadGateway, "unable to resolve GitLab project"
	}

	if errors.Is(err, errInvalidProjectResponse) {
		return http.StatusBadGateway, "GitLab returned an invalid project"
	}
	if errors.Is(err, errProjectLookup) {
		return http.StatusBadGateway, "unable to resolve GitLab project"
	}

	return http.StatusBadRequest, "invalid GitLab project reference"
}
