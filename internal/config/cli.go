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
// An explicit path takes precedence over the environment value.
func ResolvePath(args []string, environmentPath string) (string, bool, error) {
	switch len(args) {
	case 0:
		if environmentPath == "" {
			return defaultConfigPath, false, nil
		}
		if strings.TrimSpace(environmentPath) == "" {
			return "", false, errors.New("config path must not be empty")
		}

		return environmentPath, true, nil

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
