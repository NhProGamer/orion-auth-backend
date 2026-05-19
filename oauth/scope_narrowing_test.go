package oauth

import (
	"reflect"
	"testing"

	"orion-auth-backend/model"
)

// TestSplitResourceScopes_PreservesOIDCStandardScopes makes sure that
// resource-permission scopes can be narrowed by RBAC without touching the
// OIDC standard scopes that govern /userinfo and the ID token
// (OIDC Core §5.3/§5.4, RFC 8707 §2).
func TestSplitResourceScopes_PreservesOIDCStandardScopes(t *testing.T) {
	perms := []model.ResourcePermission{{Name: "perm1"}, {Name: "perm2"}}
	got, other := splitResourceScopes(
		[]string{"openid", "profile", "email", "roles", "perm1", "perm2"},
		perms,
	)
	wantResource := []string{"perm1", "perm2"}
	wantOther := []string{"openid", "profile", "email", "roles"}
	if !reflect.DeepEqual(got, wantResource) {
		t.Errorf("resourceScopes = %v, want %v", got, wantResource)
	}
	if !reflect.DeepEqual(other, wantOther) {
		t.Errorf("otherScopes = %v, want %v", other, wantOther)
	}
}

func TestSplitResourceScopes_NoResourcePerms_AllOther(t *testing.T) {
	got, other := splitResourceScopes(
		[]string{"openid", "profile"},
		nil,
	)
	if got != nil {
		t.Errorf("resourceScopes = %v, want nil", got)
	}
	want := []string{"openid", "profile"}
	if !reflect.DeepEqual(other, want) {
		t.Errorf("otherScopes = %v, want %v", other, want)
	}
}

func TestSplitResourceScopes_PreservesOrderWithinGroups(t *testing.T) {
	perms := []model.ResourcePermission{{Name: "perm2"}, {Name: "perm1"}}
	got, other := splitResourceScopes(
		[]string{"openid", "perm1", "profile", "perm2"},
		perms,
	)
	wantResource := []string{"perm1", "perm2"}
	wantOther := []string{"openid", "profile"}
	if !reflect.DeepEqual(got, wantResource) {
		t.Errorf("resourceScopes = %v, want %v", got, wantResource)
	}
	if !reflect.DeepEqual(other, wantOther) {
		t.Errorf("otherScopes = %v, want %v", other, wantOther)
	}
}

func TestSplitResourceScopes_OnlyResourceScopes(t *testing.T) {
	perms := []model.ResourcePermission{{Name: "perm1"}, {Name: "perm2"}}
	got, other := splitResourceScopes(
		[]string{"perm1", "perm2"},
		perms,
	)
	wantResource := []string{"perm1", "perm2"}
	if !reflect.DeepEqual(got, wantResource) {
		t.Errorf("resourceScopes = %v, want %v", got, wantResource)
	}
	if other != nil {
		t.Errorf("otherScopes = %v, want nil", other)
	}
}

// TestNarrowing_FinalScopes_UserHasAllPerms is the smoke test for the
// composition (splitResourceScopes → ValidateUserScopes → unionScopes) that
// mirrors what issueTokensWithOpts now does.
func TestNarrowing_FinalScopes_UserHasAllPerms(t *testing.T) {
	scopes := []string{"openid", "profile", "email", "roles", "perm1", "perm2"}
	perms := []model.ResourcePermission{{Name: "perm1"}, {Name: "perm2"}}

	resourceScopes, otherScopes := splitResourceScopes(scopes, perms)
	allowed := resourceScopes // user has both
	final := unionScopes(otherScopes, allowed)

	want := []string{"openid", "profile", "email", "roles", "perm1", "perm2"}
	if !reflect.DeepEqual(final, want) {
		t.Errorf("final = %v, want %v", final, want)
	}
}

func TestNarrowing_FinalScopes_UserHasSubsetOfPerms(t *testing.T) {
	scopes := []string{"openid", "profile", "email", "roles", "perm1", "perm2"}
	perms := []model.ResourcePermission{{Name: "perm1"}, {Name: "perm2"}}

	_, otherScopes := splitResourceScopes(scopes, perms)
	allowed := []string{"perm1"} // RBAC denies perm2
	final := unionScopes(otherScopes, allowed)

	want := []string{"openid", "profile", "email", "roles", "perm1"}
	if !reflect.DeepEqual(final, want) {
		t.Errorf("final = %v, want %v", final, want)
	}
}

func TestNarrowing_FinalScopes_UserHasNoPerms(t *testing.T) {
	scopes := []string{"openid", "profile", "email", "perm1", "perm2"}
	perms := []model.ResourcePermission{{Name: "perm1"}, {Name: "perm2"}}

	_, otherScopes := splitResourceScopes(scopes, perms)
	allowed := []string(nil) // RBAC denies everything
	final := unionScopes(otherScopes, allowed)

	want := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(final, want) {
		t.Errorf("final = %v, want %v", final, want)
	}
}
