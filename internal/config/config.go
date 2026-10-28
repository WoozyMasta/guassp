// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package config defines the user configuration and compiles it for runtime use.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/woozymasta/guassp/internal/domain"
	"github.com/woozymasta/guassp/internal/rate"
)

// RuntimeConfig contains validated settings and values derived from Config.
type RuntimeConfig struct {
	GitLabURL          *url.URL
	SonarQubeURL       *url.URL
	PermissionMap      domain.PermissionMap
	ManagedPermissions domain.PermissionSet
	VisibilityPolicy   domain.VisibilityPolicy
	Config
	WebSyncRate    rate.Limit
	WebAuthEnabled bool
}

// Compile validates user configuration and derives values used by runtime components.
func Compile(config Config) (RuntimeConfig, error) {
	if err := validateSchema(config); err != nil {
		return RuntimeConfig{}, fmt.Errorf("config schema: %w", err)
	}

	gitLabURL, err := parseBaseURL(config.GitLab.URL)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("gitlab.url: %w", err)
	}

	sonarQubeURL, err := parseBaseURL(config.SonarQube.URL)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("sonarqube.url: %w", err)
	}
	if err := validateListenAddress(config.Runtime.Listen); err != nil {
		return RuntimeConfig{}, fmt.Errorf("runtime.listen: %w", err)
	}
	if (config.Web.Username == "") != (config.Web.Password == "") {
		return RuntimeConfig{}, errors.New("web.username and web.password must be specified together")
	}
	if (config.Metrics.Username == "") != (config.Metrics.Password == "") {
		return RuntimeConfig{}, errors.New("metrics.username and metrics.password must be specified together")
	}
	if config.Metrics.Token != "" && config.Metrics.Username != "" {
		return RuntimeConfig{}, errors.New("configure either metrics.token or metrics Basic credentials, not both")
	}

	permissionMap, err := compilePermissionMap(config.Permissions)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("permissions: %w", err)
	}

	visibilityPolicy, err := compileVisibility(config.Visibility)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("visibility: %w", err)
	}

	webSyncRate, err := rate.ParseLimit(config.Web.SyncRate)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("web.sync_rate: %w", err)
	}

	return RuntimeConfig{
		Config:             config,
		GitLabURL:          gitLabURL,
		SonarQubeURL:       sonarQubeURL,
		PermissionMap:      permissionMap,
		ManagedPermissions: permissionMap.ManagedPermissions(),
		VisibilityPolicy:   visibilityPolicy,
		WebSyncRate:        webSyncRate,
		WebAuthEnabled:     config.Web.Username != "",
	}, nil
}

// compilePermissionMap converts config lists to domain permission sets.
func compilePermissionMap(mapping PermissionMapping) (domain.PermissionMap, error) {
	if mapping == nil {
		return domain.DefaultPermissionMap(), nil
	}

	compiled := make(domain.PermissionMap, len(mapping))
	for rawLevel, names := range mapping {
		parsedLevel, err := strconv.Atoi(rawLevel)
		if err != nil {
			return nil, fmt.Errorf("invalid access level %q: %w", rawLevel, err)
		}
		if parsedLevel < 1 {
			return nil, fmt.Errorf("access level %d must be positive", parsedLevel)
		}
		if strconv.Itoa(parsedLevel) != rawLevel {
			return nil, fmt.Errorf("access level %q must be a canonical positive integer", rawLevel)
		}
		level := domain.AccessLevel(parsedLevel)

		permissions := make(domain.PermissionSet, len(names))
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" {
				return nil, fmt.Errorf("access level %d contains an empty permission", level)
			}

			permissions[name] = struct{}{}
		}
		compiled[level] = permissions
	}

	return compiled, nil
}

// compileVisibility validates and converts visibility configuration to a domain policy.
func compileVisibility(options VisibilityOptions) (domain.VisibilityPolicy, error) {
	if options.Map == nil {
		options.Map = domain.DefaultVisibilityMap()
	}
	for source, target := range options.Map {
		if source != "public" && source != "internal" && source != "private" {
			return domain.VisibilityPolicy{}, fmt.Errorf("unsupported source visibility %q", source)
		}
		if target != "public" && target != "private" {
			return domain.VisibilityPolicy{}, fmt.Errorf("unsupported target visibility %q", target)
		}
	}

	policy := domain.VisibilityPolicy{Mode: domain.VisibilityMap, Mapping: options.Map}
	if !options.Enabled {
		policy.Mode = domain.VisibilityIgnore
	}

	return policy, nil
}
