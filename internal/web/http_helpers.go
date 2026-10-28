// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/woozymasta/guassp/internal/httpclient"
)

// singleToken reports whether a token contains exactly one nonempty field.
func singleToken(token string) bool {
	return token != "" && len(strings.Fields(token)) == 1
}

// isJSONContentType accepts application/json with optional parameters.
func isJSONContentType(value string) bool {
	mediaType, _, _ := strings.Cut(value, ";")
	return strings.EqualFold(strings.TrimSpace(mediaType), "application/json")
}

// validationFailure maps sanitized GitLab status errors to API responses.
func validationFailure(err error) (int, string) {
	if apiError, isAPIError := errors.AsType[*httpclient.Error](err); isAPIError {
		if apiError.StatusCode == http.StatusUnauthorized || apiError.StatusCode == http.StatusForbidden {
			return http.StatusUnauthorized, "invalid CI job token"
		}
	}

	return http.StatusBadGateway, "unable to validate CI job token"
}

// writeError emits a stable JSON error without upstream details.
func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, ErrorResponse{Error: message})
}

// writeJSON writes one JSON response with a content type and status.
func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
