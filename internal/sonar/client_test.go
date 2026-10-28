// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package sonar

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestProjectsPaginationAndBearerAuth(t *testing.T) {
	t.Parallel()

	pages := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/sonar/api/server/version" {
			_, _ = writer.Write([]byte("10.3.0"))
			return
		}
		pages++
		if request.URL.Path != "/sonar/api/projects/search" {
			t.Errorf("unexpected path %q", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("missing bearer authorization")
		}
		if request.URL.Query().Get("ps") != "100" {
			t.Errorf("page size = %q", request.URL.Query().Get("ps"))
		}
		if request.URL.Query().Get("p") == "1" {
			_, _ = writer.Write([]byte(`{
				"components": [{"key":"a","name":"A","visibility":"private"}],
				"paging": {"pageIndex":1,"pageSize":1,"total":2}
			}`))
			return
		}
		_, _ = writer.Write([]byte(`{
			"components": [{"key":"b","name":"B","visibility":"public"}],
			"paging": {"pageIndex":2,"pageSize":1,"total":2}
		}`))
	}))
	defer server.Close()

	client := testClient(t, server.URL+"/sonar")
	projects, err := client.Projects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pages != 2 || len(projects) != 2 || projects[1].Key != "b" {
		t.Fatalf("pages=%d projects=%+v", pages, projects)
	}
}

func TestVersionAndBinding(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/sonar/api/server/version" {
			_, _ = writer.Write([]byte("10.8.1.99999\n"))
			return
		}
		if request.URL.Path != "/sonar/api/alm_settings/get_binding" ||
			request.URL.Query().Get("project") != "team:project a" {
			t.Errorf("unexpected binding request: %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		_, _ = writer.Write([]byte(`{
			"key":"GitLab",
			"alm":"gitlab",
			"repository":"15457528",
			"url":"https://gitlab.example/api/v4",
			"monorepo":false
		}`))
	}))
	defer server.Close()
	client := testClient(t, server.URL+"/sonar")

	version, err := client.Version(context.Background())
	if err != nil || version != "10.8.1.99999" {
		t.Fatalf("version=%q err=%v", version, err)
	}

	binding, err := client.Binding(context.Background(), "team:project a")
	if err != nil || binding.ProjectID != 15457528 || binding.Key != "GitLab" {
		t.Fatalf("binding=%+v err=%v", binding, err)
	}
}

func TestProjectVisibilityReadsCurrentState(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/sonar/api/components/show" ||
			request.URL.Query().Get("component") != "team:project" {
			t.Errorf("unexpected request: %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		if request.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing bearer authorization")
		}
		_, _ = writer.Write([]byte(`{"component":{"key":"team:project","visibility":"private"}}`))
	}))
	defer server.Close()

	visibility, err := testClient(t, server.URL+"/sonar").ProjectVisibility(context.Background(), "team:project")
	if err != nil || visibility != "private" {
		t.Fatalf("ProjectVisibility = %q, %v; want private", visibility, err)
	}
}

func TestProjectVisibilityRejectsIncompleteResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"component":{"key":"team:project"}}`))
	}))
	defer server.Close()

	if _, err := testClient(t, server.URL).ProjectVisibility(context.Background(), "team:project"); err == nil {
		t.Fatal("ProjectVisibility accepted a response without visibility")
	}
}

func TestUpdateProjectVisibilityRejectsUnsupportedTarget(t *testing.T) {
	t.Parallel()

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := testClient(t, server.URL).UpdateProjectVisibility(context.Background(), "team:project", "internal"); err == nil {
		t.Fatal("UpdateProjectVisibility accepted internal visibility")
	}
	if requests != 0 {
		t.Fatalf("sent %d requests for unsupported visibility", requests)
	}
}

func TestBindingNotBoundAndMalformedRepository(t *testing.T) {
	t.Parallel()

	t.Run("not bound", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()
		_, err := testClient(t, server.URL).Binding(context.Background(), "project")
		if !errors.Is(err, ErrNotBound) {
			t.Fatalf("expected ErrNotBound, got %v", err)
		}
	})
	t.Run("malformed repository", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write([]byte(`{"alm":"gitlab","repository":"../42"}`))
		}))
		defer server.Close()
		_, err := testClient(t, server.URL).Binding(context.Background(), "project")
		if err == nil ||
			!strings.Contains(err.Error(), "get ALM binding") ||
			strings.Contains(err.Error(), "../42") {
			t.Fatalf("expected sanitized malformed repository error, got %v", err)
		}
	})
}

func TestUsersPagination(t *testing.T) {
	t.Parallel()

	pages := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/sonar/api/server/version" {
			_, _ = writer.Write([]byte("10.3.0"))
			return
		}
		pages++
		if request.URL.Path != "/sonar/api/users/search" {
			t.Errorf("unexpected path %q", request.URL.Path)
		}
		if request.URL.Query().Get("p") == "1" {
			_, _ = writer.Write([]byte(`{
				"users":[{"login":"alice","externalProvider":"gitlab","groups":["sonar-users"]}],
				"paging":{"pageIndex":1,"pageSize":1,"total":2}
			}`))
			return
		}
		_, _ = writer.Write([]byte(`{
			"users":[{"login":"bob","active":false}],
			"paging":{"pageIndex":2,"pageSize":1,"total":2}
		}`))
	}))
	defer server.Close()

	users, err := testClient(t, server.URL+"/sonar").Users(context.Background())
	if err != nil || pages != 2 || len(users) != 2 || users[0].ExternalProvider != "gitlab" {
		t.Fatalf("users=%+v pages=%d err=%v", users, pages, err)
	}
}

func TestDirectUserPermissionsFixture(t *testing.T) {
	t.Parallel()

	fixture, err := os.ReadFile("testdata/direct_permissions.json")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/sonar/api/permissions/users" ||
			request.URL.Query().Get("projectKey") != "team:project" {
			t.Errorf("unexpected request: %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		_, _ = writer.Write(fixture)
	}))
	defer server.Close()
	permissions, err := testClient(t, server.URL+"/sonar").DirectUserPermissions(context.Background(), "team:project")
	if err != nil {
		t.Fatal(err)
	}
	expected := []UserPermissions{
		{
			Login:       "alice",
			Permissions: []string{"user", "codeviewer"},
		},
		{
			Login:       "bob",
			Permissions: []string{},
		},
	}
	if !reflect.DeepEqual(permissions, expected) {
		t.Fatalf("permissions=%+v, want %+v", permissions, expected)
	}
}

func TestDirectUserPermissionsShapeMismatch(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"users":[{"login":"alice","permissionKeys":["user"]}]}`))
	}))
	defer server.Close()
	_, err := testClient(t, server.URL).DirectUserPermissions(context.Background(), "project")
	if !errors.Is(err, ErrUnsupportedPermissionsAPI) ||
		!strings.Contains(err.Error(), "unsupported Sonar permissions API") {
		t.Fatalf("expected explicit compatibility error, got %v", err)
	}
}

func TestWritesUseFormEncodingAndSubpath(t *testing.T) {
	t.Parallel()

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/sonar/api/server/version" {
			_, _ = writer.Write([]byte("10.3.0\n"))
			return
		}
		requests++
		if !strings.HasPrefix(request.URL.Path, "/sonar/api/") {
			t.Errorf("base path lost: %q", request.URL.Path)
		}
		if request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
			request.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("missing headers: %+v", request.Header)
		}
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		switch request.URL.Path {
		case "/sonar/api/permissions/add_user", "/sonar/api/permissions/remove_user":
			if request.Form.Get("login") != "alice+ops@example.com" ||
				request.Form.Get("permission") != "code viewer" ||
				request.Form.Get("projectKey") != "team:project" {
				t.Errorf("unexpected permission form: %v", request.Form)
			}
		case "/sonar/api/projects/update_visibility":
			if request.Form.Get("project") != "team:project" ||
				request.Form.Get("visibility") != "private" {
				t.Errorf("unexpected visibility form: %v", request.Form)
			}
		case "/sonar/api/users/deactivate":
			if request.Form.Get("login") != "alice+ops@example.com" {
				t.Errorf("unexpected deactivate form: %v", request.Form)
			}
		default:
			t.Errorf("unexpected path %q", request.URL.Path)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := testClient(t, server.URL+"/sonar")
	ctx := context.Background()
	if err := client.GrantUserPermission(ctx, "alice+ops@example.com", "code viewer", "team:project"); err != nil {
		t.Fatal(err)
	}
	if err := client.RevokeUserPermission(ctx, "alice+ops@example.com", "code viewer", "team:project"); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateProjectVisibility(ctx, "team:project", "private"); err != nil {
		t.Fatal(err)
	}
	if err := client.DeactivateUser(ctx, User{Login: "alice+ops@example.com"}); err != nil {
		t.Fatal(err)
	}
	if requests != 4 {
		t.Fatalf("got %d requests, want 4", requests)
	}
}

func TestUsersLoadsV2IDsForCurrentDeactivationAPI(t *testing.T) {
	t.Parallel()

	versionRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/sonar/api/server/version":
			versionRequests++
			_, _ = writer.Write([]byte("10.4.0.87286"))

		case "/sonar/api/v2/users-management/users":
			if request.URL.Query().Get("pageIndex") != "1" ||
				request.URL.Query().Get("pageSize") != "100" {
				t.Errorf("unexpected v2 pagination: %s", request.URL.RawQuery)
			}
			_, _ = writer.Write([]byte(`[{"id":"user-uuid","login":"alice","active":true}]`))

		default:
			t.Errorf("unexpected path %q", request.URL.Path)
		}
	}))
	defer server.Close()

	client := testClient(t, server.URL+"/sonar")
	users, err := client.Users(context.Background())
	if err != nil || len(users) != 1 || users[0].ID != "user-uuid" {
		t.Fatalf("Users() = %+v, %v; want ID user-uuid", users, err)
	}
	if _, err := client.supportsUserManagementV2(context.Background()); err != nil || versionRequests != 1 {
		t.Fatalf("version requests=%d, err=%v; want one cached request", versionRequests, err)
	}
}

func TestDeactivateUserUsesWebAPIV2(t *testing.T) {
	t.Parallel()

	versionRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/sonar/api/server/version":
			versionRequests++
			_, _ = writer.Write([]byte("2025.1.0.102418"))

		case "/sonar/api/v2/users-management/users/user-uuid":
			if request.Method != http.MethodDelete || request.Header.Get("Authorization") != "Bearer secret" {
				t.Errorf("unexpected deactivate request: %s %s", request.Method, request.URL.Path)
			}
			writer.WriteHeader(http.StatusNoContent)

		default:
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()

	err := testClient(t, server.URL+"/sonar").DeactivateUser(context.Background(), User{
		ID:    "user-uuid",
		Login: "alice",
	})
	if err != nil || versionRequests != 1 {
		t.Fatalf("DeactivateUser() err=%v versionRequests=%d", err, versionRequests)
	}
}

func TestDeactivateUserRequiresV2Identifier(t *testing.T) {
	t.Parallel()

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path == "/sonar/api/server/version" {
			_, _ = writer.Write([]byte("10.4.0"))
			return
		}
		t.Errorf("unexpected request: %s", request.URL.Path)
	}))
	defer server.Close()

	err := testClient(t, server.URL+"/sonar").DeactivateUser(context.Background(), User{Login: "alice"})
	if err == nil || requests != 1 {
		t.Fatalf("DeactivateUser() err=%v requests=%d; want missing ID error without DELETE", err, requests)
	}
}

func TestSupportsUserManagementVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version   string
		supported bool
		wantError bool
	}{
		{version: "9.9.9"},
		{version: "10.3.0"},
		{version: "10.4.0", supported: true},
		{version: "2025.1.0", supported: true},
		{version: "invalid", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			t.Parallel()
			supported, err := supportsUserManagementVersion(test.version)
			if supported != test.supported || (err != nil) != test.wantError {
				t.Fatalf("supportsUserManagementVersion(%q) = %t, %v", test.version, supported, err)
			}
		})
	}
}

func TestSearchProjectsUsesLegacyQuery(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("q") != "group/project" {
			t.Errorf("query = %q", request.URL.Query().Get("q"))
		}
		_, _ = writer.Write([]byte(`{"components":[{"key":"group:project"}]}`))
	}))
	defer server.Close()
	projects, err := testClient(t, server.URL).SearchProjects(context.Background(), "group/project")
	if err != nil || len(projects) != 1 || projects[0].Key != "group:project" {
		t.Fatalf("projects=%+v err=%v", projects, err)
	}
}

// testClient constructs a SonarQube client for an httptest server URL.
func testClient(t *testing.T, rawURL string) *Client {
	t.Helper()
	baseURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(baseURL, "secret", "guassp/test")
	if err != nil {
		t.Fatal(err)
	}
	return client
}
