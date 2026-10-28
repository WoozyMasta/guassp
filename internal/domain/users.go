// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package domain

// UserMatchMode selects how a GitLab member is matched to a SonarQube user.
type UserMatchMode string

const (
	// UserMatchExternal uses the GitLab username or numeric ID as external identity.
	UserMatchExternal UserMatchMode = "external"
	// UserMatchEmail uses a verified GitLab email match.
	UserMatchEmail UserMatchMode = "email"
	// UserMatchName uses a verified member name match.
	UserMatchName UserMatchMode = "name"
)
