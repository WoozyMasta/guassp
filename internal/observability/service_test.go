// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package observability

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/woozymasta/guassp/internal/reconcile"
	"github.com/woozymasta/guassp/internal/scheduler"
)

func TestRunStoreIsBoundedAndSanitizesFields(t *testing.T) {
	service := New("1.2.3", "commit", false)
	for index := range runCapacity + 1 {
		errors := make([]string, maxRunErrors+2)
		for errorIndex := range errors {
			errors[errorIndex] = strings.Repeat("x", maxStoredTextSize+10)
		}
		service.RecordRun(scheduler.Run{
			ProjectID:  int64(index + 1),
			Source:     "manual",
			StartedAt:  time.Now(),
			FinishedAt: time.Now().Add(time.Second),
			Result: reconcile.Result{
				Status:        reconcile.StatusPartial,
				GitLabProject: strings.Repeat("p", 800),
				SonarProjects: []string{"sonar-key"},
				Errors:        errors,
				Stages: reconcile.StageResults{
					Permissions: reconcile.StageResult{
						Status:    reconcile.StagePartial,
						Attempts:  2,
						Succeeded: 1,
						Failed:    1,
					},
				},
			},
		})
	}

	runs := service.Runs(runCapacity + 5)
	if len(runs) != runCapacity ||
		runs[0].GitLabProjectID != runCapacity+1 {
		t.Fatalf("store length=%d newest project=%d", len(runs), runs[0].GitLabProjectID)
	}

	if len(runs[0].Errors) != maxRunErrors ||
		runs[0].ErrorsOmitted != 2 ||
		len(runs[0].Errors[0]) != maxStoredTextSize {
		t.Fatalf("stored errors=%d omitted=%d text bytes=%d",
			len(runs[0].Errors), runs[0].ErrorsOmitted, len(runs[0].Errors[0]))
	}
	if len(runs[0].GitLabProject) != maxStoredTextSize || runs[0].ID == "" {
		t.Fatalf("project bytes=%d run ID empty=%t", len(runs[0].GitLabProject), runs[0].ID == "")
	}

	if runs[0].Stages.Permissions.Status != reconcile.StagePartial ||
		runs[0].Stages.Permissions.Failed != 1 {
		t.Fatalf("stored stage result = %+v", runs[0].Stages.Permissions)
	}
}

func TestMetricsUseBoundedLabels(t *testing.T) {
	service := New("1", "commit", false)
	service.ObserveRequest("gitlab", "get project", "2xx", time.Millisecond)
	service.ObserveRequest("gitlab", "project/secret/123", "200", time.Millisecond)
	service.ObservePermission("grant", "admin", "success")
	service.ObserveFullSyncStatus(scheduler.FullSyncStatus{
		StartedAt:     time.Now(),
		FinishedAt:    time.Now().Add(time.Second),
		ProjectsFound: 2,
		SonarProjects: 3,
		SnapshotReady: true,
	})
	service.RecordRun(scheduler.Run{
		ProjectID:  123,
		Source:     "manual",
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
		Result: reconcile.Result{
			Status: reconcile.StatusSuccess,
			Stages: reconcile.StageResults{
				Permissions: reconcile.StageResult{
					Status:    reconcile.StageSuccess,
					Attempts:  1,
					Succeeded: 1,
				},
			},
		},
	})
	recorder := httptest.NewRecorder()
	service.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	body := recorder.Body.String()
	for _, required := range []string{
		"guassp_sync_total",
		"guassp_sync_stage_total{result=\"success\",source=\"manual\",stage=\"permissions\"} 1",
		"status_class=\"2xx\"",
		"operation=\"get project\"",
		"operation=\"other\"",
		"guassp_sync_queue",
		"guassp_sync_inflight",
		"guassp_permission_changes_total",
		"guassp_full_sync_total",
		"guassp_full_sync_duration_seconds",
		"guassp_discovered_gitlab_projects 2",
		"guassp_discovered_sonar_projects 3",
		"guassp_build_info",
	} {
		if !strings.Contains(body, required) {
			t.Errorf("metrics missing %q", required)
		}
	}
	if strings.Contains(body, "123") || strings.Contains(body, "secret") {
		t.Fatalf("metric output contains unbounded request data: %s", body)
	}
}
