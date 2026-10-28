// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package httpclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"
)

// retryableTransportError allows retries only for transient network failures.
func retryableTransportError(err error) bool {
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrCrossOriginRedirect) ||
		errors.Is(err, ErrBasePathRedirect) ||
		errors.Is(err, ErrRedirectCredentials) ||
		errors.Is(err, ErrWriteRedirect) ||
		errors.Is(err, ErrTooManyRedirects) {
		return false
	}

	var networkError net.Error
	return errors.As(err, &networkError)
}

// retryableStatus reports HTTP statuses that permit a bodyless GET retry.
func retryableStatus(status int) bool {
	switch status {
	case
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true

	default:
		return false
	}
}

// retryBackoff returns the bounded exponential delay for a retry attempt.
func retryBackoff(attempt int) time.Duration {
	return 50 * time.Millisecond * time.Duration(1<<attempt)
}

// parseRetryAfter parses either Retry-After format and caps the resulting wait.
func parseRetryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}

		if seconds > int(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}

		return time.Duration(seconds) * time.Second
	}

	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}

	delay := when.Sub(now)
	if delay > maxRetryAfter {
		return maxRetryAfter
	}

	return delay
}

// wait sleeps for delay or returns when the request context is canceled.
func wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
