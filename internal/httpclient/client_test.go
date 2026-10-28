// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package httpclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type requestObserverCapture struct {
	mu          sync.Mutex
	upstream    string
	operation   string
	statusClass string
	duration    time.Duration
}

// ObserveRequest captures one request observation for assertions.
func (capture *requestObserverCapture) ObserveRequest(upstream, operation, statusClass string, duration time.Duration) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.upstream, capture.operation, capture.statusClass, capture.duration = upstream, operation, statusClass, duration
}

func TestDoReportsRequestObservation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test base URL: %v", err)
	}
	client, err := New(baseURL, "guassp/test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	observer := &requestObserverCapture{}
	client.SetObserver(observer)
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, client.Endpoint("api").String(), nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	response, err := client.Do(request, "gitlab", "get project")
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = response.Body.Close()
	if observer.upstream != "gitlab" || observer.operation != "get project" ||
		observer.statusClass != "2xx" || observer.duration <= 0 {
		t.Fatalf("request observation = %+v", observer)
	}
}

func TestDoDoesNotRetryWrites(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	baseURL, err := url.Parse(server.URL + "/gitlab")
	if err != nil {
		t.Fatalf("parse test base URL: %v", err)
	}
	client, err := New(baseURL, "guassp/test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	request, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		client.Endpoint("api", "v4", "write").String(),
		strings.NewReader("value=1"),
	)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}

	response, err := client.Do(request, "gitlab", "write project")
	if response != nil {
		_ = response.Body.Close()
	}
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Do error = %#v", err)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("write attempts = %d, want 1", got)
	}
}

func TestDoBlocksWriteRedirects(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		attempts.Add(1)
		http.Redirect(w, req, "/gitlab/api/v4/redirect-target", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)

	baseURL, err := url.Parse(server.URL + "/gitlab")
	if err != nil {
		t.Fatalf("parse test base URL: %v", err)
	}
	client, err := New(baseURL, "guassp/test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	request, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		client.Endpoint("api", "v4", "write").String(),
		strings.NewReader("value=1"),
	)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}

	response, err := client.Do(request, "gitlab", "write project")
	if response != nil {
		_ = response.Body.Close()
	}
	if !errors.Is(err, ErrWriteRedirect) {
		t.Fatalf("Do error = %v", err)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("write attempts = %d, want 1", got)
	}
}

func TestHTTPClientLimitsResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(maxResponseBytes+1))
		_, _ = io.WriteString(w, strings.Repeat("a", maxResponseBytes+1))
	}))
	t.Cleanup(server.Close)

	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test base URL: %v", err)
	}
	client, err := New(baseURL, "guassp/test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	response, err := client.HTTPClient().Get(server.URL)
	if err == nil {
		if response != nil {
			_ = response.Body.Close()
		}
		t.Fatal("HTTPClient.Get error = nil, want response size error")
	}
	if !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("HTTPClient.Get error = %v, want response size error", err)
	}
}

func TestHTTPClientStopsChunkedResponseAtBodyLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, strings.Repeat("a", maxResponseBytes+1))
	}))
	t.Cleanup(server.Close)

	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test base URL: %v", err)
	}
	client, err := New(baseURL, "guassp/test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	response, err := client.HTTPClient().Get(server.URL)
	if err != nil {
		t.Fatalf("HTTPClient.Get: %v", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	data, err := io.ReadAll(response.Body)
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("read response error = %v, want response size error", err)
	}
	if len(data) != maxResponseBytes {
		t.Fatalf("read response bytes = %d, want %d", len(data), maxResponseBytes)
	}
}

func TestHTTPClientAllowsResponseAtBodyLimit(t *testing.T) {
	body := strings.Repeat("a", maxResponseBytes)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)

	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test base URL: %v", err)
	}
	client, err := New(baseURL, "guassp/test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	response, err := client.HTTPClient().Get(server.URL)
	if err != nil {
		t.Fatalf("HTTPClient.Get: %v", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if len(data) != maxResponseBytes {
		t.Fatalf("response body length = %d, want %d", len(data), maxResponseBytes)
	}
}
