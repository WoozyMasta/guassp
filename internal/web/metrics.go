// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package web

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// protectMetrics guards the metrics handler with the configured bearer token or Basic credentials.
func protectMetrics(next http.Handler, token, username, password string) http.Handler {
	if token == "" && username == "" {
		return next
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case token != "":
			if authorizedBearer(request, token) {
				next.ServeHTTP(writer, request)
				return
			}

			writer.Header().Set("WWW-Authenticate", `Bearer realm="guassp metrics"`)
		case authorizedBasic(request, username, password):
			next.ServeHTTP(writer, request)
			return
		default:
			writer.Header().Set("WWW-Authenticate", `Basic realm="guassp metrics"`)
		}

		writeError(writer, http.StatusUnauthorized, "metrics authentication required")
	})
}

// authorizedBearer compares a bearer credential without logging or retaining it.
func authorizedBearer(request *http.Request, expected string) bool {
	authorization := request.Header.Values("Authorization")
	if len(authorization) != 1 {
		return false
	}
	fields := strings.Fields(authorization[0])
	return len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") &&
		subtle.ConstantTimeCompare([]byte(fields[1]), []byte(expected)) == 1
}

// authorizedBasic compares HTTP Basic credentials in constant time.
func authorizedBasic(request *http.Request, expectedUser, expectedPassword string) bool {
	username, password, ok := request.BasicAuth()
	return ok && subtle.ConstantTimeCompare([]byte(username), []byte(expectedUser)) == 1 &&
		subtle.ConstantTimeCompare([]byte(password), []byte(expectedPassword)) == 1
}
