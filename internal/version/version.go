// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package version holds build metadata for Guassp.
package version

import (
	"fmt"
	"io"
)

// Build metadata injected with -ldflags.
var (
	// Version is the release version injected at build time.
	Version = "dev"
	// Commit is the source revision injected at build time.
	Commit = "unknown"
	// BuildTime is the RFC3339 build timestamp injected at build time.
	BuildTime = "unknown"
	// URL is the project URL injected at build time.
	URL = "https://github.com/WoozyMasta/guassp"
)

// Print writes the project identity and build metadata to output.
func Print(output io.Writer) error {
	_, err := fmt.Fprintf(
		output,
		`GUASSP - GitLab User Access Synchronization for SonarQube Projects
URL:        %s
Version:    %s
Commit:     %s
Build time: %s
`,
		URL,
		Version,
		Commit,
		BuildTime,
	)

	return err
}
