// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package config

import (
	"errors"
	"strings"
)

const defaultConfigPath = "./guassp.yaml"

// ResolvePath validates the CLI arguments and returns the selected config path.
func ResolvePath(args []string) (string, bool, error) {
	switch len(args) {
	case 0:
		return defaultConfigPath, false, nil

	case 1:
		if strings.HasPrefix(args[0], "-") {
			return "", false, errors.New(
				"guassp accepts only an optional config path; command-line options are not supported",
			)
		}
		if strings.TrimSpace(args[0]) == "" {
			return "", false, errors.New("config path must not be empty")
		}

		return args[0], true, nil

	default:
		return "", false, errors.New("usage: guassp [CONFIG_PATH]")
	}
}
