// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package reconcile

// targetStages records independent outcomes for one SonarQube target.
type targetStages struct {
	Permissions StageStatus
	Visibility  StageStatus
}

// newStageResults initializes every stage to an explicit not-run state.
func newStageResults() StageResults {
	return StageResults{
		Permissions: StageResult{Status: StageNotRun},
		Visibility:  StageResult{Status: StageNotRun},
		Deactivation: StageResult{
			Status: StageNotRun,
		},
	}
}

// operationStatus classifies a stage unit from its successful and failed operations.
func operationStatus(succeeded, failed int) StageStatus {
	switch {
	case failed == 0:
		return StageSuccess

	case succeeded == 0:
		return StageFailed

	default:
		return StagePartial
	}
}

// recordStage adds one stage unit and refreshes its aggregate status.
func recordStage(stage *StageResult, status StageStatus) {
	switch status {
	case StageSuccess:
		stage.Attempts++
		stage.Succeeded++

	case StagePartial:
		stage.Attempts++
		stage.Partial++

	case StageFailed:
		stage.Attempts++
		stage.Failed++

	case StageSkipped:
		stage.Skipped++

	default:
		return
	}

	switch {
	case stage.Attempts == 0:
		stage.Status = StageSkipped

	case stage.Failed == stage.Attempts:
		stage.Status = StageFailed

	case stage.Failed > 0 || stage.Partial > 0:
		stage.Status = StagePartial

	default:
		stage.Status = StageSuccess
	}
}

// summarizeResult derives the project outcome without letting optional stages mask permission failure.
func summarizeResult(result Result) Status {
	if result.Counts.Targets == 0 {
		switch {
		case result.Counts.Errors > 0:
			return StatusFailed

		case len(result.Warnings) > 0:
			return StatusPartial

		default:
			return StatusSkipped
		}
	}

	if result.Counts.Errors == 0 {
		if len(result.Warnings) > 0 {
			return StatusPartial
		}

		return StatusSuccess
	}

	if result.Stages.Permissions.Succeeded+result.Stages.Permissions.Partial > 0 ||
		result.Stages.Deactivation.Succeeded+result.Stages.Deactivation.Partial > 0 {
		return StatusPartial
	}

	return StatusFailed
}
