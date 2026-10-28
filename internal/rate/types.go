// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package rate defines request rate limits used by the application.
package rate

import (
	"sync"
	"time"
)

const maxBuckets = 10_000

// Limit describes a request count within a fixed time window.
type Limit struct {
	// Requests is the maximum allowed requests within Window.
	Requests int
	// Window is the fixed duration for each key's request counter.
	Window time.Duration
	// Disabled bypasses request counting when true.
	Disabled bool
}

// Limiter applies a fixed-window limit independently to each key.
type Limiter struct {
	lastCleanup time.Time
	buckets     map[string]bucket
	now         func() time.Time
	limit       Limit
	mu          sync.Mutex
}

// bucket stores one key's current fixed window.
type bucket struct {
	start time.Time
	count int
}
