// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/woozymasta/jamle"
)

// ErrConfigBootstrapped reports that an explicit path now contains an example config.
var ErrConfigBootstrapped = errors.New("example config created; configure it before starting Guassp")

// Load reads a config file, applies defaults and environment expansion, and validates it.
func Load(path string, explicit bool) (RuntimeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return RuntimeConfig{}, fmt.Errorf("read config %q: %w", path, err)
		}

		if !explicit {
			return RuntimeConfig{}, fmt.Errorf(
				"config %q does not exist; create it or pass its path explicitly",
				path,
			)
		}

		return RuntimeConfig{}, bootstrapConfig(path, false)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		if !explicit {
			return RuntimeConfig{}, fmt.Errorf(
				"config %q is empty; pass %q explicitly to bootstrap an example",
				path,
				path,
			)
		}

		return RuntimeConfig{}, bootstrapConfig(path, true)
	}

	var config Config
	if err := jamle.UnmarshalWithOptions(data, &config, jamle.UnmarshalOptions{
		DefaultSources: []jamle.DefaultSource{jamle.DefaultSourceJSONSchema},
		Strict:         true,
	}); err != nil {
		return RuntimeConfig{}, fmt.Errorf("decode config %q: %w", path, err)
	}

	compiled, err := Compile(config)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("validate config %q: %w", path, err)
	}

	return compiled, nil
}

// bootstrapConfig writes the example without creating parent directories.
func bootstrapConfig(path string, existing bool) error {
	flags := os.O_WRONLY
	if existing {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_CREATE | os.O_EXCL
	}

	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return fmt.Errorf("create config example %q: %w", path, err)
	}

	data := []byte(ExampleYAML())
	written, err := file.Write(data)
	if err == nil && written != len(data) {
		err = fmt.Errorf("short write: wrote %d of %d bytes", written, len(data))
	}
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("write config example %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close config example %q: %w", path, err)
	}

	return fmt.Errorf("%w at %q", ErrConfigBootstrapped, path)
}
