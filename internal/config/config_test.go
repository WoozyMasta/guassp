// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package config

import (
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/woozymasta/guassp/internal/domain"
	"github.com/woozymasta/guassp/internal/logger"
	"github.com/woozymasta/guassp/internal/rate"
)

func validConfig() Config {
	return Config{
		GitLab: GitLabOptions{
			URL:   "https://gitlab.example.com/gitlab/",
			Token: "placeholder",
		},
		SonarQube: SonarQubeOptions{
			URL:    "https://sonar.example.com/sonar/",
			Token:  "placeholder",
			ALMKey: "gitlab",
		},
		Runtime: RuntimeOptions{
			Listen:  ":8080",
			Workers: 4,
		},
		Log: logger.Options{
			Format:          "json",
			Output:          "stderr",
			Level:           "info",
			TimestampFormat: "rfc3339",
		},
		Permissions: PermissionMapping{
			"10": {"user"},
			"20": {"user", "codeviewer"},
			"30": {"user", "codeviewer", "issueadmin"},
			"40": {"user", "codeviewer", "issueadmin", "securityhotspotadmin"},
			"50": {"user", "codeviewer", "issueadmin", "securityhotspotadmin", "admin"},
		},
		Visibility: VisibilityOptions{
			Enabled: true,
			Map: map[domain.GitLabVisibility]domain.SonarVisibility{
				"public": "public", "internal": "private", "private": "private",
			},
		},
		Users:     UserOptions{Match: domain.UserMatchExternal},
		Discovery: DiscoveryOptions{FullSyncAt: "03:00"},
		Web:       WebOptions{Enabled: true, SyncRate: "10/m"},
	}
}

func TestCompileConfig(t *testing.T) {
	config := validConfig()
	config.GitLab.SkipUsers = []int64{1, 42}
	config.SonarQube.SkipGroups = []string{"guests", "external"}
	config.Web.Username = "operator"
	config.Web.Password = "secret"

	compiled, err := Compile(config)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if compiled.GitLabURL.String() != "https://gitlab.example.com/gitlab" {
		t.Fatalf("GitLab URL = %q", compiled.GitLabURL)
	}
	if compiled.SonarQubeURL.String() != "https://sonar.example.com/sonar" {
		t.Fatalf("SonarQube URL = %q", compiled.SonarQubeURL)
	}
	if compiled.Runtime.Listen != ":8080" || compiled.Runtime.Workers != 4 {
		t.Fatalf("runtime = %#v", compiled.Runtime)
	}
	if !compiled.WebAuthEnabled ||
		compiled.WebSyncRate != (rate.Limit{Requests: 10, Window: time.Minute}) {
		t.Fatalf(
			"web runtime options = auth:%t rate:%#v",
			compiled.WebAuthEnabled, compiled.WebSyncRate)
	}

	if got, want := compiled.ManagedPermissions.Sorted(), []string{
		"admin", "codeviewer", "issueadmin", "securityhotspotadmin", "user",
	}; !slices.Equal(got, want) {
		t.Fatalf("managed permissions = %v, want %v", got, want)
	}
	if target, apply, err := compiled.VisibilityPolicy.Resolve("internal"); err != nil ||
		!apply || target != "private" {
		t.Fatalf("visibility Resolve(internal) = %q, %t, %v", target, apply, err)
	}
}

func TestValidateSchemaRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name   string
		update func(*Config)
	}{
		{name: "unsupported user match", update: func(config *Config) {
			config.Users.Match = "legacy"
		}},
		{name: "empty GitLab token", update: func(config *Config) {
			config.GitLab.Token = ""
		}},
		{name: "blank skipped group", update: func(config *Config) {
			config.SonarQube.SkipGroups = []string{" \t"}
		}},
		{name: "non-positive skipped user", update: func(config *Config) {
			config.GitLab.SkipUsers = []int64{0}
		}},
		{name: "invalid rate syntax", update: func(config *Config) {
			config.Web.SyncRate = "1/d"
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig()
			test.update(&config)
			if err := validateSchema(config); err == nil {
				t.Fatal("validateSchema succeeded")
			}
		})
	}
}

func TestValidateSchemaAcceptsUserMatchModes(t *testing.T) {
	for _, mode := range []domain.UserMatchMode{
		domain.UserMatchExternal,
		domain.UserMatchEmail,
		domain.UserMatchName,
	} {
		t.Run(string(mode), func(t *testing.T) {
			config := validConfig()
			config.Users.Match = mode
			if err := validateSchema(config); err != nil {
				t.Fatalf("validateSchema: %v", err)
			}
		})
	}
}

func TestCompilePermissionMappingIsAuthoritative(t *testing.T) {
	config := validConfig()
	config.Permissions = PermissionMapping{"15": {"user"}, "25": {}}

	compiled, err := Compile(config)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(compiled.PermissionMap) != 2 {
		t.Fatalf("permission map contains defaults: %#v", compiled.PermissionMap)
	}
	if permissions, exists := compiled.PermissionMap[25]; !exists || len(permissions) != 0 {
		t.Fatalf("explicit empty mapping = %#v, exists %t", permissions, exists)
	}
}

func TestCompileUsesDefaultPolicyMapsWhenAbsent(t *testing.T) {
	config := validConfig()
	config.Permissions = nil
	config.Visibility.Map = nil

	compiled, err := Compile(config)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(compiled.PermissionMap) != 5 || !compiled.PermissionMap[50].Has("admin") {
		t.Fatalf("default permission map = %#v", compiled.PermissionMap)
	}
	if got, want := compiled.VisibilityPolicy.Mapping, domain.DefaultVisibilityMap(); !maps.Equal(got, want) {
		t.Fatalf("default visibility map = %#v, want %#v", got, want)
	}
}

func TestCompileRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		update func(*Config)
	}{
		{name: "missing GitLab token", update: func(config *Config) {
			config.GitLab.Token = ""
		}},
		{name: "URL credentials", update: func(config *Config) {
			config.GitLab.URL = "https://user:secret@gitlab.example.com"
		}},
		{name: "unsupported URL scheme", update: func(config *Config) {
			config.GitLab.URL = "ftp://gitlab.example.com"
		}},
		{name: "URL empty query", update: func(config *Config) {
			config.GitLab.URL = "https://gitlab.example.com?"
		}},
		{name: "URL dot segments", update: func(config *Config) {
			config.GitLab.URL = "https://gitlab.example.com/api/../admin"
		}},
		{name: "invalid listen address", update: func(config *Config) {
			config.Runtime.Listen = "not-an-address"
		}},
		{name: "zero workers", update: func(config *Config) {
			config.Runtime.Workers = 0
		}},
		{name: "invalid schedule", update: func(config *Config) {
			config.Discovery.FullSyncAt = "24:00"
		}},
		{name: "invalid log format", update: func(config *Config) {
			config.Log.Format = "yaml"
		}},
		{name: "invalid user match", update: func(config *Config) {
			config.Users.Match = "unknown"
		}},
		{name: "incomplete Basic auth", update: func(config *Config) {
			config.Web.Username = "operator"
		}},
		{name: "invalid permission level", update: func(config *Config) {
			config.Permissions = PermissionMapping{"0": {"user"}}
		}},
		{name: "non-canonical permission level", update: func(config *Config) {
			config.Permissions = PermissionMapping{"010": {"user"}}
		}},
		{name: "invalid permission value", update: func(config *Config) {
			config.Permissions = PermissionMapping{"10": {""}}
		}},
		{name: "invalid visibility target", update: func(config *Config) {
			config.Visibility.Map["internal"] = "internal"
		}},
		{name: "invalid rate limit", update: func(config *Config) {
			config.Web.SyncRate = "1/d"
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig()
			test.update(&config)
			if _, err := Compile(config); err == nil {
				t.Fatal("Compile succeeded")
			}
		})
	}
}

func TestCompileAllowsDisabledSchedulesAndVisibility(t *testing.T) {
	config := validConfig()
	config.Discovery.FullSyncAt = ""
	config.Visibility.Enabled = false
	config.Web.SyncRate = "0"

	compiled, err := Compile(config)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if compiled.Discovery.FullSyncAt.Enabled() {
		t.Fatal("empty schedule is enabled")
	}
	if compiled.VisibilityPolicy.Mode != domain.VisibilityIgnore {
		t.Fatalf("visibility mode = %q", compiled.VisibilityPolicy.Mode)
	}
	if !compiled.WebSyncRate.Disabled {
		t.Fatal("zero web rate is enabled")
	}
}
