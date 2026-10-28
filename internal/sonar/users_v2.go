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
	"strings"

	"github.com/woozymasta/guassp/internal/httpclient"
)

// supportsUserManagementV2 reports whether the server supports the user management API.
func (client *Client) supportsUserManagementV2(ctx context.Context) (bool, error) {
	client.userManagementMu.Lock()
	defer client.userManagementMu.Unlock()
	if client.userManagementModeChecked {
		return client.userManagementSupported, nil
	}

	version, err := client.Version(ctx)
	if err != nil {
		return false, err
	}
	supported, err := supportsUserManagementVersion(version)
	if err != nil {
		return false, &httpclient.Error{
			Upstream:  upstream,
			Operation: "detect user management API",
			Err:       err,
		}
	}

	client.userManagementSupported = supported
	client.userManagementModeChecked = true
	return supported, nil
}

// userManagementUsers returns all users through the current Web API v2 endpoint.
func (client *Client) userManagementUsers(ctx context.Context) ([]User, error) {
	users := make([]User, 0)
	for page := 1; ; page++ {
		requestURL := client.http.Endpoint("api", "v2", "users-management", "users")
		query := requestURL.Query()
		query.Set("pageIndex", strconv.Itoa(page))
		query.Set("pageSize", strconv.Itoa(userPageSize))
		requestURL.RawQuery = query.Encode()

		response, err := client.get(ctx, requestURL, "search users")
		if err != nil {
			return nil, err
		}

		data, readErr := httpclient.ReadBody(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			return nil, &httpclient.Error{
				Upstream:  upstream,
				Operation: "search users",
				Err:       readErr,
			}
		}

		if closeErr != nil {
			return nil, &httpclient.Error{
				Upstream:  upstream,
				Operation: "search users",
				Err:       closeErr,
			}
		}

		pageUsers, pageInfo, err := decodeUserManagementPage(data)
		if err != nil {
			return nil, &httpclient.Error{
				Upstream:  upstream,
				Operation: "search users",
				Err:       err,
			}
		}

		users = append(users, pageUsers...)
		if pageInfo.Total > 0 && pageInfo.Size > 0 {
			pageIndex := pageInfo.Index
			if pageIndex < 1 {
				pageIndex = page
			}
			if pageIndex*pageInfo.Size >= pageInfo.Total {
				return users, nil
			}

			continue
		}

		if len(pageUsers) < userPageSize {
			return users, nil
		}
	}
}

// decodeUserManagementPage accepts the documented page envelope and array response shape.
func decodeUserManagementPage(data []byte) ([]User, userManagementPageInfo, error) {
	if strings.TrimSpace(string(data)) == "null" {
		return nil, userManagementPageInfo{}, errors.New("user list is null")
	}

	var users []User
	if err := json.Unmarshal(data, &users); err == nil {
		return users, userManagementPageInfo{}, nil
	}

	var response userManagementResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, userManagementPageInfo{}, fmt.Errorf("decode user list: %w", err)
	}
	if response.Users == nil {
		return nil, userManagementPageInfo{}, errors.New("user list has no users field")
	}

	return response.Users, response.Page, nil
}

// supportsUserManagementVersion reports whether the version is 10.4 or newer.
func supportsUserManagementVersion(version string) (bool, error) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false, fmt.Errorf("invalid SonarQube version %q", version)
	}

	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil || major < 1 || minor < 0 {
		return false, fmt.Errorf("invalid SonarQube version %q", version)
	}

	return major > 10 || major == 10 && minor >= 4, nil
}
