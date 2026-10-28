// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package web

import (
	"context"
	"net/http"
)

type apiAuthorizationContextKey struct{}

// protectAPI requires the configured bearer token before running an API handler.
func protectAPI(next http.Handler, token string) http.Handler {
	if token == "" {
		return next
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !authorizedBearer(request, token) {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="guassp API"`)
			writeError(writer, http.StatusUnauthorized, "API authentication required")
			return
		}

		ctx := context.WithValue(request.Context(), apiAuthorizationContextKey{}, struct{}{})
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}
