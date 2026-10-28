// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunStartsServiceWithoutLoggingCredentials(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "private-value")
	t.Setenv("SONARQUBE_TOKEN", "private-value")
	path := filepath.Join(t.TempDir(), "guassp.yaml")
	data := []byte("gitlab:\n  url: https://gitlab.example.com\n  token: ${GITLAB_TOKEN}\n" +
		"sonarqube:\n  url: https://sonar.example.com\n  token: ${SONARQUBE_TOKEN}\n" +
		"runtime:\n  listen: 127.0.0.1:0\ndiscovery:\n  full_sync_at: ''\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stderr := &startupWriter{cancel: cancel}
	if err := run(ctx, []string{path}, &stdout, stderr); err != nil {
		t.Fatalf("run: %v", err)
	}

	output := stderr.String()
	if !strings.Contains(output, "service started") || !strings.Contains(output, "service stopped") {
		t.Fatalf("startup output = %q", output)
	}
	for _, field := range []string{
		`"project":"GUASSP"`,
		`"url":`,
		`"version":`,
		`"commit":`,
		`"build_time":`,
	} {
		if !strings.Contains(output, field) {
			t.Errorf("startup output does not contain %s: %q", field, output)
		}
	}

	buildInfoAt := strings.Index(output, "starting service")
	serviceStartedAt := strings.Index(output, "service started")
	if buildInfoAt < 0 || buildInfoAt > serviceStartedAt {
		t.Fatalf("build information was not logged before service startup: %q", output)
	}
	if strings.Contains(output, "private-value") {
		t.Fatal("startup output contains a credential")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

type startupWriter struct {
	output bytes.Buffer
	cancel context.CancelFunc
}

func (writer *startupWriter) Write(data []byte) (int, error) {
	written, err := writer.output.Write(data)
	if bytes.Contains(data, []byte("service started")) {
		writer.cancel()
	}

	return written, err
}

func (writer *startupWriter) String() string {
	return writer.output.String()
}

func TestRunRejectsApplicationFlags(t *testing.T) {
	if err := run(context.Background(), []string{"--help"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "command-line options are not supported") {
		t.Fatalf("run --help error = %v", err)
	}
}
