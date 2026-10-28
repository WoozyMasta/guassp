// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package web

import "net/http"

// fullSyncAPI queues one full binding refresh and project synchronization cycle.
func (server *Server) fullSyncAPI(writer http.ResponseWriter, _ *http.Request) {
	if !server.queueFullSync("api") {
		writeError(writer, http.StatusConflict, "full synchronization is already queued or running")
		return
	}

	writeJSON(writer, http.StatusAccepted, FullSyncResponse{Status: "queued"})
}

// queueFullSync records a UI or API request and accepts at most one outstanding cycle.
func (server *Server) queueFullSync(source string) bool {
	if !server.fullSync.Trigger() {
		server.logger.Debug().
			Str("operation", "queue full synchronization").
			Str("source", source).
			Int("http_status", http.StatusConflict).
			Msg("manual full synchronization is already queued or running")
		return false
	}

	server.logger.Info().
		Str("operation", "queue full synchronization").
		Str("source", source).
		Int("http_status", http.StatusAccepted).
		Msg("manual full synchronization accepted")

	return true
}
