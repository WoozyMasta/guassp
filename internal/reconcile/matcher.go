// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package reconcile

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/woozymasta/guassp/internal/domain"
	"github.com/woozymasta/guassp/internal/gitlab"
	"github.com/woozymasta/guassp/internal/sonar"
)

// GitLabUserLookup loads GitLab user details for legacy email matching.
type GitLabUserLookup interface {
	User(context.Context, int64) (gitlab.User, error)
}

// MatchStatus describes the outcome of matching a GitLab member.
type MatchStatus string

const (
	// MatchUnmatched means no eligible SonarQube user was found.
	MatchUnmatched MatchStatus = "unmatched"
	// MatchMatched means one eligible SonarQube user was found.
	MatchMatched MatchStatus = "matched"
	// MatchAmbiguous means multiple distinct SonarQube logins matched.
	MatchAmbiguous MatchStatus = "ambiguous"
	// MatchSkipped means the matched user belongs to a configured skip group.
	MatchSkipped MatchStatus = "skipped"
)

// MatchResult contains a match status and the user when one was identified.
type MatchResult struct {
	// Status reports whether the member matched, was skipped, or was ambiguous.
	Status MatchStatus
	// Candidates contains the distinct eligible users for ambiguous matches.
	Candidates []sonar.User
	// User is set for matched and skipped results.
	User sonar.User
}

// UserMatcher matches GitLab members to the cached SonarQube directory.
type UserMatcher struct {
	gitlabUsers GitLabUserLookup
	directory   *UserDirectory
	skipGroups  map[string]struct{}
	mode        domain.UserMatchMode
}

// NewUserMatcher creates a matcher for the selected user identity policy.
func NewUserMatcher(
	directory *UserDirectory,
	mode domain.UserMatchMode,
	skipGroups []string,
	gitlabUsers GitLabUserLookup,
) (*UserMatcher, error) {
	if directory == nil {
		return nil, errors.New("SonarQube user directory is required")
	}
	if mode != domain.UserMatchExternal &&
		mode != domain.UserMatchEmail &&
		mode != domain.UserMatchName {
		return nil, errors.New("unsupported user match mode")
	}
	if mode == domain.UserMatchEmail && gitlabUsers == nil {
		return nil, errors.New("GitLab user lookup is required for legacy email matching")
	}

	skipped := make(map[string]struct{}, len(skipGroups))
	for _, group := range skipGroups {
		if group != "" {
			skipped[group] = struct{}{}
		}
	}

	return &UserMatcher{
		directory:   directory,
		mode:        mode,
		gitlabUsers: gitlabUsers,
		skipGroups:  skipped,
	}, nil
}

// Match resolves a GitLab member and refreshes the directory once on a miss.
func (matcher *UserMatcher) Match(ctx context.Context, member gitlab.Member) (MatchResult, error) {
	identity := identityForMember(member)
	if !identity.hasValue() {
		return MatchResult{Status: MatchUnmatched}, nil
	}

	lookupValue, err := matcher.lookupValue(ctx, member)
	if err != nil {
		return MatchResult{}, err
	}
	if (matcher.mode == domain.UserMatchEmail || matcher.mode == domain.UserMatchName) &&
		lookupValue == "" {
		return MatchResult{Status: MatchUnmatched}, nil
	}

	index, err := matcher.directory.load(ctx, false)
	if err != nil {
		return MatchResult{}, fmt.Errorf("load SonarQube user directory: %w", err)
	}
	result := matcher.match(index, identity, lookupValue)
	if result.Status != MatchUnmatched {
		return result, nil
	}

	index, err = matcher.directory.refreshOnMiss(ctx, index)
	if err != nil {
		return MatchResult{}, fmt.Errorf("refresh SonarQube user directory: %w", err)
	}

	return matcher.match(index, identity, lookupValue), nil
}

func (matcher *UserMatcher) lookupValue(ctx context.Context, member gitlab.Member) (string, error) {
	switch matcher.mode {
	case domain.UserMatchExternal:
		return "", nil

	case domain.UserMatchEmail:
		user, err := matcher.gitlabUsers.User(ctx, member.ID)
		if err != nil {
			return "", fmt.Errorf("get GitLab user %d for email match: %w", member.ID, err)
		}

		return normalizeEmail(user.Email), nil

	case domain.UserMatchName:
		return normalizeName(member.Name), nil

	default:
		return "", errors.New("unsupported user match mode")
	}
}

// match selects eligible users from the immutable directory indexes.
func (matcher *UserMatcher) match(index *userIndex, identity memberIdentity, lookupValue string) MatchResult {
	users := make(map[string]sonar.User)
	if matcher.mode == domain.UserMatchExternal {
		for key := range identity.keys {
			for _, user := range index.byExternalID[key] {
				addCandidate(users, user)
			}
		}
	} else {
		var candidates []sonar.User
		if matcher.mode == domain.UserMatchEmail {
			candidates = index.byEmail[lookupValue]
		} else {
			candidates = index.byName[lookupValue]
		}
		for _, user := range candidates {
			if user.ExternalProvider == "gitlab" && identity.matches(user.ExternalIdentity) {
				addCandidate(users, user)
			}
		}
	}

	if len(users) == 0 {
		return MatchResult{Status: MatchUnmatched}
	}

	if len(users) > 1 {
		candidates := make([]sonar.User, 0, len(users))
		for _, user := range users {
			candidates = append(candidates, cloneUser(user))
		}
		slices.SortFunc(candidates, func(left, right sonar.User) int {
			return cmp.Compare(left.Login, right.Login)
		})

		return MatchResult{Status: MatchAmbiguous, Candidates: candidates}
	}

	for _, user := range users {
		if containsGroup(user.Groups, matcher.skipGroups) {
			return MatchResult{Status: MatchSkipped, User: cloneUser(user)}
		}

		return MatchResult{Status: MatchMatched, User: cloneUser(user)}
	}

	return MatchResult{Status: MatchUnmatched}
}

// memberIdentity contains the accepted external identity values for one member.
type memberIdentity struct {
	keys map[string]struct{}
}

// identityForMember builds the accepted identity keys for a GitLab member.
func identityForMember(member gitlab.Member) memberIdentity {
	keys := make(map[string]struct{}, 2)
	if member.Username != "" {
		keys[member.Username] = struct{}{}
	}
	if member.ID > 0 {
		keys[strconv.FormatInt(member.ID, 10)] = struct{}{}
	}

	return memberIdentity{keys: keys}
}

// hasValue reports whether an identity key can be used to verify a match.
func (identity memberIdentity) hasValue() bool {
	return len(identity.keys) != 0
}

// matches reports whether an external identity is one of the accepted keys.
func (identity memberIdentity) matches(externalIdentity string) bool {
	_, exists := identity.keys[externalIdentity]
	return exists
}

// addCandidate deduplicates matching records by SonarQube login.
func addCandidate(users map[string]sonar.User, user sonar.User) {
	if existing, exists := users[user.Login]; exists {
		existing.Groups = append(append([]string(nil), existing.Groups...), user.Groups...)
		users[user.Login] = existing
		return
	}
	users[user.Login] = user
}

// containsGroup reports whether a SonarQube user belongs to any excluded group.
func containsGroup(groups []string, excluded map[string]struct{}) bool {
	for _, group := range groups {
		if _, exists := excluded[group]; exists {
			return true
		}
	}

	return false
}
