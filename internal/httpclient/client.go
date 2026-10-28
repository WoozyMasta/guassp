// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package httpclient provides bounded, retry-aware HTTP behavior for upstream
// adapters.
package httpclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Error returns a sanitized operation error.
func (err *Error) Error() string {
	if err.StatusCode != 0 {
		return fmt.Sprintf("%s %s: HTTP %d", err.Upstream, err.Operation, err.StatusCode)
	}

	return fmt.Sprintf("%s %s: request failed", err.Upstream, err.Operation)
}

// SetLogger configures optional structured logging for upstream requests.
func (client *Client) SetLogger(logger zerolog.Logger) {
	client.mu.Lock()
	client.logger = &logger
	client.mu.Unlock()
}

// Unwrap returns the underlying transport or decoding error.
func (err *Error) Unwrap() error {
	return err.Err
}

// New constructs a client for a parsed upstream base URL.
func New(baseURL *url.URL, userAgent string) (*Client, error) {
	if baseURL == nil ||
		baseURL.Host == "" ||
		(baseURL.Scheme != "http" && baseURL.Scheme != "https") ||
		baseURL.User != nil ||
		baseURL.RawQuery != "" ||
		baseURL.ForceQuery ||
		baseURL.Fragment != "" ||
		baseURL.Opaque != "" {
		return nil, errors.New("upstream base URL must be an absolute HTTP(S) URL")
	}

	if userAgent == "" {
		return nil, errors.New("upstream user agent must not be empty")
	}

	base := *baseURL
	base.Path = strings.TrimRight(base.Path, "/")
	if base.Path != "" && path.Clean(base.Path) != base.Path {
		return nil, errors.New("upstream base URL path must not contain dot segments")
	}

	base.RawPath = strings.TrimRight(base.EscapedPath(), "/")
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Transport: &responseLimitTransport{transport: transport},
		Timeout:   defaultTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) == 0 {
				return errors.New("redirect has no originating request")
			}
			if via[0].Method != http.MethodGet || (via[0].Body != nil && via[0].Body != http.NoBody) {
				return ErrWriteRedirect
			}
			if !sameOrigin(via[len(via)-1].URL, req.URL) {
				return ErrCrossOriginRedirect
			}
			if req.URL.User != nil {
				return ErrRedirectCredentials
			}
			if !withinBasePath(base.Path, req.URL.Path) {
				return ErrBasePathRedirect
			}
			if len(via) >= 10 {
				return ErrTooManyRedirects
			}

			return nil
		},
	}

	return &Client{
		http:    client,
		baseURL: &base,
		ua:      userAgent,
	}, nil
}

// HTTPClient returns the configured standard HTTP client for upstream adapters.
func (client *Client) HTTPClient() *http.Client {
	return client.http
}

// SetObserver configures an optional request observer before the client is used.
func (client *Client) SetObserver(observer RequestObserver) {
	client.mu.Lock()
	client.observer = observer
	client.mu.Unlock()
}

// Endpoint returns a URL below the configured base path, escaping each segment.
func (client *Client) Endpoint(segments ...string) *url.URL {
	endpoint := *client.baseURL
	basePath := strings.TrimRight(endpoint.Path, "/")
	baseRawPath := strings.TrimRight(endpoint.EscapedPath(), "/")

	var pathBuilder strings.Builder
	var rawPathBuilder strings.Builder
	pathBuilder.Grow(len(basePath) + len(segments)*8)
	rawPathBuilder.Grow(len(baseRawPath) + len(segments)*8)
	pathBuilder.WriteString(basePath)
	rawPathBuilder.WriteString(baseRawPath)

	for _, segment := range segments {
		pathBuilder.WriteByte('/')
		pathBuilder.WriteString(segment)
		rawPathBuilder.WriteByte('/')
		rawPathBuilder.WriteString(url.PathEscape(segment))
	}

	endpoint.Path = pathBuilder.String()
	endpoint.RawPath = rawPathBuilder.String()

	return &endpoint
}

// Get performs a context-bound GET with bounded retries for transient failures.
func (client *Client) Get(
	ctx context.Context,
	requestURL *url.URL,
	headers http.Header,
	upstream, operation string,
) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, &Error{
			Upstream:  upstream,
			Operation: operation,
			Err:       err,
		}
	}

	req.Header = headers.Clone()
	return client.Do(req, upstream, operation)
}

// Do executes a request and reports its bounded outcome to the configured observer.
func (client *Client) Do(request *http.Request, upstream, operation string) (*http.Response, error) {
	started := time.Now()
	response, err := client.do(request, upstream, operation)
	client.mu.RLock()
	observer := client.observer
	logger := client.logger
	client.mu.RUnlock()
	status := 0
	if response != nil {
		status = response.StatusCode
	} else if err != nil {
		if requestError, ok := errors.AsType[*Error](err); ok {
			status = requestError.StatusCode
		}
	}

	if logger != nil {
		level := zerolog.DebugLevel
		if status == http.StatusUnauthorized || status == http.StatusForbidden ||
			status == http.StatusTooManyRequests || status >= http.StatusInternalServerError {
			level = zerolog.WarnLevel
		}
		if event := logger.WithLevel(level); event.Enabled() {
			result := "success"
			if err != nil {
				result = "error"
			}
			event.Str("component", "http_client").
				Str("upstream", upstream).
				Str("operation", operation).
				Int("http_status", status).
				Dur("duration", time.Since(started)).
				Str("result", result).
				Msg("upstream request completed")
		}
	}

	if observer != nil {
		statusClass := "error"
		if response != nil {
			statusClass = strconv.Itoa(response.StatusCode/100) + "xx"
		} else {
			var apiError *Error
			if errors.As(err, &apiError) && apiError.StatusCode != 0 {
				statusClass = strconv.Itoa(apiError.StatusCode/100) + "xx"
			}
		}

		observer.ObserveRequest(upstream, operation, statusClass, time.Since(started))
	}

	return response, err
}

// do executes a request, retrying only bodyless GET requests on transient errors.
func (client *Client) do(request *http.Request, upstream, operation string) (*http.Response, error) {
	if request == nil || request.URL == nil {
		return nil, &Error{
			Upstream:  upstream,
			Operation: operation,
			Err:       errors.New("request URL is required"),
		}
	}

	if request.Header == nil {
		request.Header = make(http.Header)
	}

	request.Header.Set("User-Agent", client.ua)
	attempts := 1
	if request.Method == http.MethodGet && (request.Body == nil || request.Body == http.NoBody) {
		attempts = maxAttempts
	}

	for attempt := 0; attempt < attempts; attempt++ {
		client.logAttempt(request, upstream, operation, attempt+1, attempts)
		response, err := client.http.Do(request.Clone(request.Context()))

		if err != nil {
			if attempt+1 < attempts && retryableTransportError(err) {
				delay := retryBackoff(attempt)
				client.logRetry(upstream, operation, attempt+1, delay, 0)

				if waitErr := wait(request.Context(), delay); waitErr != nil {
					return nil, &Error{
						Upstream:  upstream,
						Operation: operation,
						Err:       waitErr,
					}
				}

				continue
			}
			return nil, &Error{
				Upstream:  upstream,
				Operation: operation,
				Err:       err,
			}
		}

		if retryableStatus(response.StatusCode) && attempt+1 < attempts {
			delay := retryBackoff(attempt)
			if retryAfter := parseRetryAfter(response.Header.Get("Retry-After"), time.Now()); retryAfter > delay {
				delay = retryAfter
			}
			client.logRetry(upstream, operation, attempt+1, delay, response.StatusCode)

			_ = response.Body.Close()
			if waitErr := wait(request.Context(), delay); waitErr != nil {
				return nil, &Error{
					Upstream:  upstream,
					Operation: operation,
					Err:       waitErr,
				}
			}

			continue
		}

		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			_ = response.Body.Close()
			return nil, &Error{
				Upstream:   upstream,
				Operation:  operation,
				StatusCode: response.StatusCode,
			}
		}

		return response, nil
	}

	return nil, &Error{
		Upstream:  upstream,
		Operation: operation,
	}
}

// logAttempt records a request attempt without its query, headers, or body.
func (client *Client) logAttempt(request *http.Request, upstream, operation string, attempt, maxAttempts int) {
	client.mu.RLock()
	logger := client.logger
	client.mu.RUnlock()
	if logger == nil {
		return
	}

	event := logger.Trace()
	if !event.Enabled() {
		return
	}

	path := ""
	method := ""
	if request != nil {
		method = request.Method
		if request.URL != nil {
			path = request.URL.EscapedPath()
		}
	}

	event.Str("component", "http_client").
		Str("upstream", upstream).
		Str("operation", operation).
		Str("method", method).
		Str("path", path).
		Int("attempt", attempt).
		Int("max_attempts", maxAttempts).
		Msg("upstream request attempt")
}

// logRetry records retry timing without emitting upstream error text or headers.
func (client *Client) logRetry(upstream, operation string, attempt int, delay time.Duration, status int) {
	client.mu.RLock()
	logger := client.logger
	client.mu.RUnlock()
	if logger == nil {
		return
	}

	event := logger.Trace()
	if !event.Enabled() {
		return
	}

	event.Str("component", "http_client").
		Str("upstream", upstream).
		Str("operation", operation).
		Int("attempt", attempt).
		Int("http_status", status).
		Dur("retry_delay", delay).
		Msg("retrying upstream request")
}

// DecodeJSON reads a bounded JSON response into destination.
func DecodeJSON(body io.Reader, destination any) error {
	data, err := ReadBody(body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("decode JSON response: %w", err)
	}

	return nil
}

// ReadBody reads a bounded upstream response body.
func ReadBody(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxResponseBytes)
	}

	return data, nil
}

// sameOrigin compares scheme and authority while ignoring URL paths.
func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

// withinBasePath reports whether a path stays below the configured prefix.
func withinBasePath(basePath, requestPath string) bool {
	basePath = path.Clean(basePath)
	requestPath = path.Clean(requestPath)
	if basePath == "." || basePath == "/" {
		return true
	}

	basePath = strings.TrimRight(basePath, "/")
	return requestPath == basePath || strings.HasPrefix(requestPath, basePath+"/")
}
