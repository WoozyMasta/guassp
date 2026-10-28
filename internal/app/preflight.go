// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package app

import (
	"context"
	"fmt"
)

type upstreamPreflight interface {
	Preflight(context.Context) error
}

type preflight struct {
	gitLab upstreamPreflight
	sonar  upstreamPreflight
}

func (check preflight) Check(ctx context.Context) error {
	if err := check.gitLab.Preflight(ctx); err != nil {
		return fmt.Errorf("GitLab: %w", err)
	}
	if err := check.sonar.Preflight(ctx); err != nil {
		return fmt.Errorf("SonarQube: %w", err)
	}

	return nil
}
