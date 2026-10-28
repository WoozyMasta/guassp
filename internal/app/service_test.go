// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package app

import (
	"io"
	"net"
	"testing"

	"github.com/rs/zerolog"
	"github.com/woozymasta/guassp/internal/config"
	"github.com/woozymasta/guassp/internal/domain"
	"github.com/woozymasta/guassp/internal/logger"
)

func TestNewRejectsInvalidSchedulerBeforeStarting(t *testing.T) {
	serviceConfig := validRuntimeConfig(t)
	serviceConfig.Runtime.Workers = 0
	if _, err := New(serviceConfig, zerolog.New(io.Discard)); err == nil {
		t.Fatal("New accepted a zero worker count")
	}
}

func TestServiceRunWithNilContextClosesListener(t *testing.T) {
	service, err := New(validRuntimeConfig(t), zerolog.New(io.Discard))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	address := service.listener.Addr().String()
	//nolint:staticcheck // Verify that Run rejects nil and releases the listener.
	if err := service.Run(nil); err == nil {
		t.Fatal("Run accepted a nil context")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("listener remained open after Run(nil): %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close verification listener: %v", err)
	}
}

func validRuntimeConfig(t *testing.T) config.RuntimeConfig {
	t.Helper()

	compiled, err := config.Compile(config.Config{
		GitLab:    config.GitLabOptions{URL: "https://gitlab.example.com", Token: "gitlab-token"},
		SonarQube: config.SonarQubeOptions{URL: "https://sonar.example.com", Token: "sonar-token"},
		Log:       logger.Options{Format: "json", Output: "stderr", Level: "info", TimestampFormat: "rfc3339"},
		Runtime:   config.RuntimeOptions{Listen: "127.0.0.1:0", Workers: 1},
		Users:     config.UserOptions{Match: domain.UserMatchExternal},
		Discovery: config.DiscoveryOptions{FullSyncAt: ""},
		Web:       config.WebOptions{Enabled: true, SyncRate: "10/m"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	return compiled
}
