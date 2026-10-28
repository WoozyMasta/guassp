// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package httpclient

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const (
	defaultTimeout   = 15 * time.Second
	maxResponseBytes = 4 << 20
	maxAttempts      = 3
	maxRetryAfter    = 2 * time.Second
)

var (
	// ErrCrossOriginRedirect reports that an authenticated request tried to leave its origin.
	ErrCrossOriginRedirect = errors.New("cross-origin redirect blocked")
	// ErrBasePathRedirect reports that a request tried to leave its configured API path.
	ErrBasePathRedirect = errors.New("redirect left configured base path")
	// ErrRedirectCredentials reports that a redirect URL contains user information.
	ErrRedirectCredentials = errors.New("redirect URL credentials blocked")
	// ErrWriteRedirect reports that a write request attempted to follow a redirect.
	ErrWriteRedirect = errors.New("write request redirect blocked")
	// ErrTooManyRedirects reports a redirect chain longer than the client limit.
	ErrTooManyRedirects = errors.New("too many redirects")
)

// Error describes an upstream request failure without retaining its response body.
type Error struct {
	// Err is the underlying transport or decoding error.
	Err error
	// Upstream identifies the remote service.
	Upstream string
	// Operation describes the request without sensitive values.
	Operation string
	// StatusCode is zero when no HTTP response was received.
	StatusCode int
}

// Client applies shared URL, timeout, retry, and redirect behavior.
type Client struct {
	logger   *zerolog.Logger
	observer RequestObserver
	http     *http.Client
	baseURL  *url.URL
	ua       string
	mu       sync.RWMutex
}

// RequestObserver records one logical upstream operation.
type RequestObserver interface {
	// ObserveRequest records the upstream, operation, status class, and duration.
	ObserveRequest(upstream, operation, statusClass string, duration time.Duration)
}

// responseLimitTransport bounds upstream response bodies before API decoders read them.
type responseLimitTransport struct {
	transport http.RoundTripper
}

// limitedResponseBody restricts the number of response bytes read by callers.
type limitedResponseBody struct {
	// ReadCloser is the original upstream response body.
	io.ReadCloser
	remaining int64
}
