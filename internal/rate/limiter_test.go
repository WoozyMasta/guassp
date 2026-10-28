// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package rate

import (
	"sync"
	"testing"
	"time"
)

func TestParseLimit(t *testing.T) {
	tests := []struct {
		value string
		want  Limit
	}{
		{value: "0", want: Limit{Disabled: true}},
		{value: "5/s", want: Limit{Requests: 5, Window: time.Second}},
		{value: "10/m", want: Limit{Requests: 10, Window: time.Minute}},
		{value: "20/h", want: Limit{Requests: 20, Window: time.Hour}},
	}
	for _, test := range tests {
		got, err := ParseLimit(test.value)
		if err != nil || got != test.want {
			t.Errorf("ParseLimit(%q) = %#v, %v; want %#v", test.value, got, err, test.want)
		}
	}

	for _, value := range []string{"", "-1/m", "0/m", "1/d", "1/m/s", "x/s"} {
		if _, err := ParseLimit(value); err == nil {
			t.Errorf("ParseLimit(%q) succeeded", value)
		}
	}
}

func TestLimiterAllowsLimitAndStartsNewWindow(t *testing.T) {
	limiter, err := NewLimiter(Limit{Requests: 2, Window: time.Minute})
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	now := time.Date(2026, time.October, 22, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }

	for range 2 {
		allowed, retryAfter := limiter.Allow("192.0.2.1")
		if !allowed || retryAfter != 0 {
			t.Fatalf("Allow() = %t, %s; want allowed", allowed, retryAfter)
		}
	}
	allowed, retryAfter := limiter.Allow("192.0.2.1")
	if allowed || retryAfter != time.Minute {
		t.Fatalf("limited Allow() = %t, %s; want denied for 1m", allowed, retryAfter)
	}
	if allowed, _ := limiter.Allow("192.0.2.2"); !allowed {
		t.Fatal("different key was denied")
	}

	now = now.Add(time.Minute)
	if allowed, _ := limiter.Allow("192.0.2.1"); !allowed {
		t.Fatal("request was denied after the window expired")
	}
	if len(limiter.buckets) != 1 {
		t.Fatalf("bucket count = %d, want 1 after stale cleanup", len(limiter.buckets))
	}
}

func TestLimiterCanBeDisabled(t *testing.T) {
	limiter, err := NewLimiter(Limit{Disabled: true})
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	for range maxBuckets + 1 {
		if allowed, retryAfter := limiter.Allow("same"); !allowed || retryAfter != 0 {
			t.Fatalf("Allow() = %t, %s; want allowed", allowed, retryAfter)
		}
	}
}

func TestNewLimiterRejectsInvalidEnabledLimit(t *testing.T) {
	if _, err := NewLimiter(Limit{}); err == nil {
		t.Fatal("NewLimiter accepted an empty enabled limit")
	}
}

func TestLimiterBoundsBucketCount(t *testing.T) {
	limiter, err := NewLimiter(Limit{Requests: 1, Window: time.Minute})
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	for index := range maxBuckets {
		if allowed, _ := limiter.Allow(string(rune(index + 1))); !allowed {
			t.Fatalf("key %d was denied before capacity", index)
		}
	}
	if allowed, _ := limiter.Allow("overflow"); allowed {
		t.Fatal("new key was allowed after bucket capacity")
	}
}

func TestLimiterConcurrentAccess(t *testing.T) {
	limiter, err := NewLimiter(Limit{Requests: 10, Window: time.Minute})
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	var group sync.WaitGroup
	for range 20 {
		group.Go(func() {
			limiter.Allow("192.0.2.1")
		})
	}
	group.Wait()
	if got := limiter.buckets["192.0.2.1"].count; got != 10 {
		t.Fatalf("request count = %d, want 10", got)
	}
}
