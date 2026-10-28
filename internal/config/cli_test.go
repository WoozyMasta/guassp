// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package config

import (
	"strings"
	"testing"
)

func TestResolvePath(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantPath string
		wantSet  bool
		wantErr  string
	}{
		{name: "default path", wantPath: "./guassp.yaml"},
		{name: "explicit path", args: []string{"settings.json"}, wantPath: "settings.json", wantSet: true},
		{
			name:    "option is not supported",
			args:    []string{"--help"},
			wantErr: "guassp accepts only an optional config path; command-line options are not supported",
		},
		{name: "empty path", args: []string{" "}, wantErr: "config path must not be empty"},
		{name: "extra arguments", args: []string{"one.yaml", "two.yaml"}, wantErr: "usage: guassp [CONFIG_PATH]"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotPath, gotSet, err := ResolvePath(test.args)
			if gotPath != test.wantPath || gotSet != test.wantSet {
				t.Fatalf("ResolvePath() = %q, %t; want %q, %t", gotPath, gotSet, test.wantPath, test.wantSet)
			}
			if test.wantErr == "" && err != nil {
				t.Fatalf("ResolvePath() error = %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("ResolvePath() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}
