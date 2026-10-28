// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package web

import (
	"errors"
	"path"
	"strings"
)

// validateBasePath accepts a clean absolute URL path without a trailing slash.
func validateBasePath(basePath string) error {
	if basePath == "" {
		return nil
	}
	if basePath[0] != '/' || basePath == "/" || path.Clean(basePath) != basePath {
		return errors.New("web base path must be a clean absolute path without a trailing slash")
	}

	for _, char := range basePath[1:] {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("/_-", char) {
			continue
		}

		return errors.New("web base path contains an unsupported character")
	}

	return nil
}
