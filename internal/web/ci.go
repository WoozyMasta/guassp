// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/woozymasta/guassp/internal/scheduler"
)

// sync validates the job token and queues the project returned by GitLab.
func (server *Server) sync(writer http.ResponseWriter, request *http.Request) {
	started := time.Now()
	if event := server.logger.Trace(); event.Enabled() {
		event.Str("operation", "accept CI sync").Str("source", "ci").Str("path", request.URL.Path).Msg("HTTP request received")
	}
	token, status, message := server.jobToken(writer, request)
	if status != 0 {
		writeError(writer, status, message)
		return
	}

	job, err := server.jobValidator.CurrentJob(request.Context(), token)
	if err != nil {
		status, message := validationFailure(err)
		server.logger.Warn().
			Str("component", "http").
			Str("operation", "validate CI job token").
			Int("http_status", status).
			Msg("CI job validation failed")
		writeError(writer, status, message)
		return
	}

	if job.ID < 1 || job.Project.ID < 1 {
		server.logger.Error().
			Str("component", "http").
			Str("operation", "validate CI job response").
			Msg("GitLab returned an invalid CI job")
		writeError(writer, http.StatusBadGateway, "GitLab returned an invalid job response")
		return
	}

	submission, err := server.scheduler.Submit(job.Project.ID, scheduler.PriorityHigh, "ci")
	if err != nil {
		server.logger.Error().
			Str("component", "http").
			Str("operation", "queue CI project reconciliation").
			Int64("gitlab_project_id", job.Project.ID).
			Msg("CI project submission failed")
		writeError(writer, http.StatusInternalServerError, "unable to queue project synchronization")
		return
	}

	if !submission.Accepted {
		writeError(writer, http.StatusServiceUnavailable, "service is shutting down")
		return
	}

	writeJSON(writer, http.StatusAccepted, SyncResponse{
		ProjectID: job.Project.ID,
		Source:    "ci",
		Status:    "queued",
		Coalesced: submission.Coalesced,
	})
	server.logger.Info().
		Str("operation", "queue project synchronization").
		Str("source", "ci").
		Int64("gitlab_job_id", job.ID).
		Int64("gitlab_project_id", job.Project.ID).
		Dur("duration", time.Since(started)).
		Bool("coalesced", submission.Coalesced).
		Int("http_status", http.StatusAccepted).
		Msg("project synchronization request accepted")
}

// jobToken extracts one supported token transport without logging its value.
func (server *Server) jobToken(
	writer http.ResponseWriter,
	request *http.Request,
) (string, int, string) {
	jobTokens := request.Header.Values("JOB-TOKEN")
	authorization := request.Header.Values("Authorization")
	if server.apiToken != "" {
		authorization = nil
	}
	if len(jobTokens)+len(authorization) > 1 {
		return "", http.StatusBadRequest, "provide one CI job token transport"
	}

	if len(jobTokens) == 1 {
		token := strings.TrimSpace(jobTokens[0])
		if !singleToken(token) {
			return "", http.StatusBadRequest, "malformed CI job token"
		}
		return token, 0, ""
	}

	if len(authorization) == 1 {
		parts := strings.Fields(authorization[0])
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || !singleToken(parts[1]) {
			return "", http.StatusBadRequest, "malformed CI job token authorization"
		}
		return parts[1], 0, ""
	}

	if !server.allowJobTokenBody {
		return "", http.StatusUnauthorized, "CI job token is required"
	}

	contentType := request.Header.Get("Content-Type")
	if !isJSONContentType(contentType) {
		return "", http.StatusUnsupportedMediaType, "JSON CI job token body is required"
	}

	request.Body = http.MaxBytesReader(writer, request.Body, maxCIBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var body struct {
		JobToken string `json:"job_token"`
	}

	if err := decoder.Decode(&body); err != nil {
		if _, isMaxBytesError := errors.AsType[*http.MaxBytesError](err); isMaxBytesError {
			return "", http.StatusRequestEntityTooLarge, "CI job token body is too large"
		}

		if errors.Is(err, io.EOF) {
			return "", http.StatusUnauthorized, "CI job token is required"
		}

		return "", http.StatusBadRequest, "malformed CI job token body"
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if _, isMaxBytesError := errors.AsType[*http.MaxBytesError](err); isMaxBytesError {
			return "", http.StatusRequestEntityTooLarge, "CI job token body is too large"
		}
		return "", http.StatusBadRequest, "malformed CI job token body"
	}

	token := strings.TrimSpace(body.JobToken)
	if !singleToken(token) {
		return "", http.StatusUnauthorized, "CI job token is required"
	}

	return token, 0, ""
}
