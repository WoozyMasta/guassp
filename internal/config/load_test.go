// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/woozymasta/jamle"
)

const testConfigYAML = `gitlab:
  url: https://gitlab.example.com
  token: ${GITLAB_TOKEN:?set GITLAB_TOKEN}
sonarqube:
  url: https://sonar.example.com
  token: ${SONARQUBE_TOKEN:?set SONARQUBE_TOKEN}
`

func writeConfig(t *testing.T, data string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "guassp.yaml")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	return path
}

func setConfigTokens(t *testing.T) {
	t.Helper()
	t.Setenv("GITLAB_TOKEN", "test-value")
	t.Setenv("SONARQUBE_TOKEN", "test-value")
	t.Setenv("WEB_PASSWORD", "test-value")
}

func TestLoadYAMLExpandsEnvironmentAndAppliesDefaults(t *testing.T) {
	setConfigTokens(t)
	path := writeConfig(t, testConfigYAML)

	config, err := Load(path, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if config.GitLab.Token != "test-value" || config.SonarQube.Token != "test-value" {
		t.Fatal("environment values were not expanded")
	}
	if config.Runtime.Listen != ":8080" || config.Runtime.Workers != 4 {
		t.Fatalf("runtime defaults = %#v", config.Runtime)
	}
	if config.Log.Format != "json" || config.Log.Output != "stderr" || config.Log.Level != "info" {
		t.Fatalf("logging defaults = %#v", config.Log)
	}
	if config.Users.Match != "external" || !config.Web.Enabled || config.Web.SyncRate != "10/m" {
		t.Fatalf("application defaults = users:%#v web:%#v", config.Users, config.Web)
	}
	if len(config.PermissionMap) != 5 || config.VisibilityPolicy.Mapping["internal"] != "private" {
		t.Fatalf(
			"policy defaults = permissions:%#v visibility:%#v",
			config.PermissionMap, config.VisibilityPolicy.Mapping)
	}
}

func TestGeneratedExampleDecodesWithDefaults(t *testing.T) {
	setConfigTokens(t)

	var config Config
	if err := jamle.UnmarshalWithOptions([]byte(ExampleYAML()), &config, jamle.UnmarshalOptions{
		DefaultSources: []jamle.DefaultSource{jamle.DefaultSourceJSONSchema},
		Strict:         true,
	}); err != nil {
		t.Fatalf("decode generated example: %v", err)
	}
	if config.Runtime.Listen != ":8080" || config.Runtime.Workers != 4 {
		t.Fatalf("runtime defaults = %#v", config.Runtime)
	}
	if config.Log.Format != "json" || config.Log.Level != "info" {
		t.Fatalf("logging defaults = %#v", config.Log)
	}
}

func TestLoadJSON(t *testing.T) {
	setConfigTokens(t)
	path := writeConfig(t, `{
  "gitlab": {"url": "https://gitlab.example.com", "token": "${GITLAB_TOKEN}"},
  "sonarqube": {"url": "https://sonar.example.com", "token": "${SONARQUBE_TOKEN}"},
  "permissions": {"15": [], "25": ["user"]}
}`)

	config, err := Load(path, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(config.PermissionMap) != 2 || len(config.PermissionMap[15]) != 0 ||
		!config.PermissionMap[25].Has("user") {
		t.Fatalf("permission map = %#v", config.PermissionMap)
	}
	if config.Runtime.Workers != 4 {
		t.Fatalf("workers default = %d", config.Runtime.Workers)
	}
}

func TestLoadYAMLPermissionMapUsesNumericKeys(t *testing.T) {
	setConfigTokens(t)
	path := writeConfig(t, testConfigYAML+"permissions:\n  15: []\n  25: [user, codeviewer]\n")

	config, err := Load(path, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(config.PermissionMap) != 2 || len(config.PermissionMap[15]) != 0 ||
		!config.PermissionMap[25].Has("user") || !config.PermissionMap[25].Has("codeviewer") {
		t.Fatalf("permission map = %#v", config.PermissionMap)
	}
}

func TestLoadRejectsUnknownFieldsAndMissingEnvironment(t *testing.T) {
	setConfigTokens(t)
	unknownField := writeConfig(t, strings.Replace(testConfigYAML, "sonarqube:\n", "unknown: true\nsonarqube:\n", 1))
	if _, err := Load(unknownField, true); err == nil ||
		!strings.Contains(err.Error(), "unknown") {
		t.Fatalf("Load unknown field error = %v", err)
	}

	missingTokenData := strings.Replace(
		testConfigYAML,
		"${GITLAB_TOKEN:?set GITLAB_TOKEN}",
		"${MISSING_GITLAB_TOKEN:?set GITLAB_TOKEN}",
		1,
	)
	missingToken := writeConfig(t, missingTokenData)
	t.Setenv("MISSING_GITLAB_TOKEN", "")
	if _, err := Load(missingToken, true); err == nil ||
		!strings.Contains(err.Error(), "set GITLAB_TOKEN") {
		t.Fatalf("Load missing environment error = %v", err)
	}
}

func TestLoadImplicitMissingAndEmptyFilesDoNotWrite(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "guassp.yaml")
	if _, err := Load(missing, false); err == nil ||
		!strings.Contains(err.Error(), "create it") {
		t.Fatalf("Load missing implicit path error = %v", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("implicit config was created: %v", err)
	}

	empty := writeConfig(t, " \n\t")
	if _, err := Load(empty, false); err == nil ||
		!strings.Contains(err.Error(), "pass") {
		t.Fatalf("Load empty implicit path error = %v", err)
	}
	data, err := os.ReadFile(empty)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != " \n\t" {
		t.Fatalf("implicit empty config changed to %q", data)
	}
}

func TestLoadExplicitMissingBootstrapsExample(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guassp.yaml")
	if _, err := Load(path, true); !errors.Is(err, ErrConfigBootstrapped) {
		t.Fatalf("Load missing explicit path error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != ExampleYAML() {
		t.Fatalf("bootstrapped config = %q", data)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("config permissions = %o, want 600", got)
		}
	}
}

func TestLoadExplicitEmptyBootstrapsWithoutCreatingDirectories(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(empty, true); !errors.Is(err, ErrConfigBootstrapped) {
		t.Fatalf("Load empty explicit path error = %v", err)
	}
	data, err := os.ReadFile(empty)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != ExampleYAML() {
		t.Fatalf("bootstrapped config = %q", data)
	}

	missingParent := filepath.Join(dir, "missing", "guassp.yaml")
	if _, err := Load(missingParent, true); err == nil {
		t.Fatal("Load created a missing parent directory")
	}
}

func TestLoadPreservesExplicitZeroValues(t *testing.T) {
	setConfigTokens(t)
	path := writeConfig(t, testConfigYAML+"runtime:\n  workers: 0\nweb:\n  enabled: false\n")
	if _, err := Load(path, true); err == nil ||
		!strings.Contains(err.Error(), "runtime/workers") {
		t.Fatalf("Load explicit zero value error = %v", err)
	}
}

func TestLoadPreservesExplicitEmptyMapsAndFalseValues(t *testing.T) {
	setConfigTokens(t)
	path := writeConfig(t, testConfigYAML+
		"permissions: {}\nweb:\n  enabled: false\ndiscovery:\n  full_sync_at: \"\"\n")

	config, err := Load(path, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(config.PermissionMap) != 0 {
		t.Fatalf("empty permission map became defaults: %#v", config.PermissionMap)
	}
	if config.Web.Enabled || config.Discovery.FullSyncAt.Enabled() {
		t.Fatalf(
			"explicit zero values were replaced: web:%t schedule:%q",
			config.Web.Enabled, config.Discovery.FullSyncAt)
	}
}

func TestLoadScheduledTimeDefaultIsValid(t *testing.T) {
	setConfigTokens(t)
	path := writeConfig(t, testConfigYAML)
	config, err := Load(path, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if hour, minute := config.Discovery.FullSyncAt.HourMinute(); hour != 3 || minute != 0 {
		t.Fatalf("full sync time = %02d:%02d", hour, minute)
	}
	if config.WebSyncRate.Window != time.Minute {
		t.Fatalf("web sync rate = %#v", config.WebSyncRate)
	}
}
