// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package sonar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/woozymasta/guassp/internal/httpclient"
)

// directPermissionsResponse contains the compatibility-sensitive internal API
// shape.
type directPermissionsResponse struct {
	// Users contains direct user permission entries.
	Users json.RawMessage `json:"users"`
	// Paging controls page traversal when present.
	Paging pageInfo `json:"paging"`
}

// directPermissionEntry is one user's direct project permission record.
type directPermissionEntry struct {
	// Login identifies the SonarQube user.
	Login *string `json:"login"`
	// Permissions must be a string array.
	Permissions json.RawMessage `json:"permissions"`
}

// DirectUserPermissions lists only permissions assigned directly to users.
func (client *Client) DirectUserPermissions(ctx context.Context, projectKey string) ([]UserPermissions, error) {
	if projectKey == "" {
		return nil, errors.New("SonarQube project key must not be empty")
	}

	permissions := make([]UserPermissions, 0)
	for page := 1; ; page++ {
		requestURL := client.http.Endpoint("api", "permissions", "users")
		query := requestURL.Query()
		query.Set("projectKey", projectKey)
		query.Set("p", strconv.Itoa(page))
		query.Set("ps", strconv.Itoa(apiPageSize))
		requestURL.RawQuery = query.Encode()

		response, err := client.get(ctx, requestURL, "list direct user permissions")
		if err != nil {
			var apiError *httpclient.Error
			if errors.As(err, &apiError) &&
				(apiError.StatusCode == 404 || apiError.StatusCode == 400) {
				return nil, fmt.Errorf("%w: endpoint unavailable", ErrUnsupportedPermissionsAPI)
			}

			return nil, err
		}

		data, readErr := httpclient.ReadBody(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			return nil, unsupportedPermissionsError(readErr)
		}

		pagePermissions, paging, decodeErr := decodeDirectPermissions(data)
		if decodeErr != nil {
			return nil, unsupportedPermissionsError(decodeErr)
		}

		permissions = append(permissions, pagePermissions...)
		if !hasNextPage(paging, len(pagePermissions), page) {
			return permissions, nil
		}
	}
}

// decodeDirectPermissions validates and converts one internal API page.
func decodeDirectPermissions(data []byte) ([]UserPermissions, pageInfo, error) {
	var response directPermissionsResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, pageInfo{}, err
	}
	if len(response.Users) == 0 || string(response.Users) == "null" {
		return nil, pageInfo{}, errors.New("response does not contain a users array")
	}

	var entries []json.RawMessage
	if err := json.Unmarshal(response.Users, &entries); err != nil {
		return nil, pageInfo{}, errors.New("users field is not an array")
	}

	permissions := make([]UserPermissions, 0, len(entries))
	for _, entry := range entries {
		var item directPermissionEntry
		if err := json.Unmarshal(entry, &item); err != nil {
			return nil, pageInfo{}, errors.New("user permission entry has an invalid shape")
		}

		if item.Login == nil ||
			*item.Login == "" ||
			len(item.Permissions) == 0 ||
			string(item.Permissions) == "null" {
			return nil, pageInfo{}, errors.New("user permission entry is missing login or permissions")
		}

		var values []string
		if err := json.Unmarshal(item.Permissions, &values); err != nil {
			return nil, pageInfo{}, errors.New("permissions field is not a string array")
		}

		permissions = append(permissions, UserPermissions{
			Login:       *item.Login,
			Permissions: values,
		})
	}

	return permissions, response.Paging, nil
}

// unsupportedPermissionsError wraps response failures with a compatibility sentinel.
func unsupportedPermissionsError(err error) error {
	return fmt.Errorf("%w: %v", ErrUnsupportedPermissionsAPI, err)
}
