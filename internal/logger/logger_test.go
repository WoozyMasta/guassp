// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package logger

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSetupJSONWithoutTimestamp(t *testing.T) {
	var stdout, stderr bytes.Buffer

	log, closeOutput, err := Setup(Options{
		Format:          "json",
		Output:          "stdout",
		Level:           "info",
		TimestampFormat: "none",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	defer func() { _ = closeOutput() }()

	log.Info().Msg("ready")

	var event map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &event); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if event["level"] != "info" || event["message"] != "ready" {
		t.Fatalf("event = %#v", event)
	}
	if _, ok := event["time"]; ok {
		t.Fatalf("event unexpectedly has a timestamp: %#v", event)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestSetupTextDoesNotColorBufferOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	log, closeOutput, err := Setup(Options{
		Format:          "text",
		Output:          "stdout",
		Level:           "info",
		TimestampFormat: "none",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	defer func() { _ = closeOutput() }()

	log.Info().Msg("ready")
	if strings.Contains(stdout.String(), "\x1b[") {
		t.Fatalf("console output contains ANSI color codes: %q", stdout.String())
	}
}

func TestSetupRejectsInvalidLevel(t *testing.T) {
	_, _, err := Setup(Options{Output: "stderr", Level: "verbose"}, nil, &bytes.Buffer{})
	if err == nil {
		t.Fatal("Setup succeeded with an invalid level")
	}
}
