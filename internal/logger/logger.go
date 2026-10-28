// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package logger configures command diagnostics.
package logger

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/term"
)

// Options configures the process log format, destination, and verbosity.
type Options struct {
	// Format selects structured JSON for log processing or readable text for interactive terminal use.
	Format string `json:"format,omitempty" jsonschema:"enum=json,enum=text,default=json" jsonschema_extras:"x-order=10"`
	// Output sends logs to stderr, stdout, or the named file.
	// File output is useful when the runtime does not collect process streams directly.
	Output string `json:"output,omitempty" jsonschema:"default=stderr" jsonschema_extras:"x-order=30"`
	// Level sets the least severe events to emit.
	// Use debug or trace while investigating behavior, then return to a quieter level for routine operation.
	Level string `json:"level,omitempty" jsonschema:"enum=trace,enum=debug,enum=info,enum=warn,enum=error,enum=disabled,default=info" jsonschema_extras:"x-order=20"`
	// TimestampFormat controls how each log entry records its time.
	// Choose a format that matches the log collector or omit timestamps when the runtime adds them.
	TimestampFormat string `json:"timestamp,omitempty" jsonschema:"enum=rfc3339,enum=unix,enum=unixms,enum=none,default=rfc3339" jsonschema_extras:"x-order=40"`
	// FileTruncate clears the selected log file on startup instead of preserving earlier entries and appending new ones.
	FileTruncate bool `json:"truncate,omitempty" jsonschema_extras:"x-order=50"`
}

// Setup builds a logger and returns a function that closes a file output.
func Setup(opts Options, stdout, stderr io.Writer) (zerolog.Logger, func() error, error) {
	w, closeOutput, err := openOutput(opts.Output, opts.FileTruncate, stdout, stderr)
	if err != nil {
		return zerolog.Nop(), nil, fmt.Errorf("open log output %q: %w", opts.Output, err)
	}

	level, err := zerolog.ParseLevel(opts.Level)
	if err != nil {
		_ = closeOutput()
		return zerolog.Nop(), nil, fmt.Errorf("parse log level %q: %w", opts.Level, err)
	}

	timeFormat, timestamps := resolveTimestampFormat(opts.TimestampFormat)
	zerolog.TimeFieldFormat = timeFormat

	if opts.Format == "json" {
		logger := zerolog.New(w).Level(level)
		if timestamps {
			logger = logger.With().Timestamp().Logger()
		}

		return logger, closeOutput, nil
	}

	console := zerolog.ConsoleWriter{
		Out:        w,
		TimeFormat: timeFormat,
		NoColor:    !supportsColor(w),
	}
	if !timestamps {
		console.PartsExclude = []string{zerolog.TimestampFieldName}
	}

	logger := zerolog.New(console).Level(level)
	if timestamps {
		logger = logger.With().Timestamp().Logger()
	}

	return logger, closeOutput, nil
}

// supportsColor enables console colors only when output targets a terminal.
func supportsColor(output io.Writer) bool {
	file, ok := output.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

// openOutput resolves a logger destination and returns its cleanup function.
func openOutput(output string, truncate bool, stdout, stderr io.Writer) (io.Writer, func() error, error) {
	switch output {
	case "", "stderr":
		return stderr, func() error { return nil }, nil

	case "stdout":
		return stdout, func() error { return nil }, nil
	}

	openFlags := os.O_CREATE | os.O_WRONLY
	if truncate {
		openFlags |= os.O_TRUNC
	} else {
		openFlags |= os.O_APPEND
	}
	file, err := os.OpenFile(output, openFlags, 0o600)
	if err != nil {
		return nil, nil, err
	}

	return file, file.Close, nil
}

// resolveTimestampFormat maps a user-facing timestamp mode to logger format.
func resolveTimestampFormat(value string) (string, bool) {
	switch value {
	case "none":
		return "", false

	case "unix":
		return zerolog.TimeFormatUnix, true

	case "unixms":
		return zerolog.TimeFormatUnixMs, true

	default:
		return time.RFC3339, true
	}
}
