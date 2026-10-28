// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package rate defines request rate limits used by the application.
package rate

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// NewLimiter creates a per-key fixed-window limiter.
func NewLimiter(limit Limit) (*Limiter, error) {
	if !limit.Disabled && (limit.Requests < 1 || limit.Window <= 0) {
		return nil, errors.New("enabled rate limit requires a positive count and window")
	}

	return &Limiter{buckets: make(map[string]bucket), limit: limit, now: time.Now}, nil
}

// Allow reports whether a request is allowed and its retry delay when limited.
func (limiter *Limiter) Allow(key string) (bool, time.Duration) {
	if limiter.limit.Disabled {
		return true, 0
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	now := limiter.now()
	if now.Sub(limiter.lastCleanup) >= limiter.limit.Window {
		limiter.removeStale(now)
		limiter.lastCleanup = now
	}
	current, exists := limiter.buckets[key]
	if !exists || !now.Before(current.start.Add(limiter.limit.Window)) {
		if !exists && len(limiter.buckets) >= maxBuckets {
			return false, limiter.limit.Window
		}

		limiter.buckets[key] = bucket{start: now, count: 1}
		return true, 0
	}

	if current.count >= limiter.limit.Requests {
		return false, current.start.Add(limiter.limit.Window).Sub(now)
	}

	current.count++
	limiter.buckets[key] = current
	return true, 0
}

// ParseLimit parses 0 or a positive count followed by /s, /m, or /h.
func ParseLimit(raw string) (Limit, error) {
	if raw == "0" {
		return Limit{Disabled: true}, nil
	}

	countText, unit, ok := strings.Cut(raw, "/")
	if !ok || strings.Contains(unit, "/") {
		return Limit{}, errors.New("must be 0, N/s, N/m, or N/h")
	}

	count, err := strconv.Atoi(countText)
	if err != nil || count < 1 {
		return Limit{}, errors.New("request count must be a positive integer")
	}

	var window time.Duration
	switch unit {
	case "s":
		window = time.Second

	case "m":
		window = time.Minute

	case "h":
		window = time.Hour

	default:
		return Limit{}, errors.New("unit must be s, m, or h")
	}

	return Limit{Requests: count, Window: window}, nil
}

// removeStale discards expired keys and bounds memory under high IP churn.
func (limiter *Limiter) removeStale(now time.Time) {
	for key, current := range limiter.buckets {
		if !now.Before(current.start.Add(limiter.limit.Window)) {
			delete(limiter.buckets, key)
		}
	}
}
