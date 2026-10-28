// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package ui embeds the server-rendered pages and their static assets.
package ui

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
)

// content contains the HTML templates and static files served by the web UI.
//
//go:embed templates/*.html assets/*
var content embed.FS

// Templates parses the embedded HTML templates with the configured public path prefix.
func Templates(basePath string) (*template.Template, error) {
	pages, err := template.New("pages").Funcs(template.FuncMap{
		"publicPath": func(route string) string {
			return basePath + route
		},
	}).ParseFS(content, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse embedded UI templates: %w", err)
	}

	return pages, nil
}

// Assets returns a handler for the embedded static assets.
func Assets() (http.Handler, error) {
	assets, err := fs.Sub(content, "assets")
	if err != nil {
		return nil, fmt.Errorf("open embedded UI assets: %w", err)
	}

	return http.StripPrefix("/assets/", http.FileServer(http.FS(assets))), nil
}
