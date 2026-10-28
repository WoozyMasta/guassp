// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// DailyTime is an optional local daily schedule in HH:MM format.
type DailyTime string

// Enabled reports whether a daily schedule is configured.
func (schedule DailyTime) Enabled() bool {
	return schedule != ""
}

// HourMinute returns the parsed schedule hour and minute.
func (schedule DailyTime) HourMinute() (int, int) {
	parsed, _ := time.Parse("15:04", string(schedule))
	return parsed.Hour(), parsed.Minute()
}

// parseBaseURL validates and normalizes an HTTP(S) service base URL.
func parseBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}

	if parsed.Host == "" ||
		parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.ForceQuery ||
		parsed.Fragment != "" ||
		parsed.Opaque != "" {
		return nil, errors.New("must be an http or https base URL without credentials, query, or fragment")
	}

	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if parsed.Path != "" && path.Clean(parsed.Path) != parsed.Path {
		return nil, errors.New("base URL path must not contain dot segments or duplicate separators")
	}

	parsed.RawPath = ""
	return parsed, nil
}

// validateListenAddress checks TCP host:port syntax without binding the address.
func validateListenAddress(address string) error {
	if strings.TrimSpace(address) != address || address == "" {
		return errors.New("must be a non-empty TCP host:port address")
	}

	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("must be a valid TCP host:port address: %w", err)
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return errors.New("port must be an integer between 0 and 65535")
	}

	return nil
}
