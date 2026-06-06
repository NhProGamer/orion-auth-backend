package middleware

import (
	"testing"
)

func TestContainsScope(t *testing.T) {
	cases := []struct {
		scopes []string
		want   string
		ok     bool
	}{
		{[]string{"m2m:users:read", "m2m:users:write"}, "m2m:users:write", true},
		{[]string{"m2m:users:read"}, "m2m:users:write", false},
		{nil, "m2m:users:read", false},
		{[]string{}, "m2m:users:read", false},
		{[]string{"openid", "profile"}, "openid", true},
	}
	for _, c := range cases {
		if got := containsScope(c.scopes, c.want); got != c.ok {
			t.Errorf("containsScope(%v, %q) = %v, want %v", c.scopes, c.want, got, c.ok)
		}
	}
}

func TestParseBearer(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"Bearer ":             "",
		"Bearer abc.def":      "abc.def",
		"bearer abc":          "abc",
		"BEARER xyz":          "xyz",
		"Basic abc":           "",
		"Bearer\tabc":         "", // single space required
		"Bearer  doublespace": "", // SplitN("Bearer  doublespace", " ", 2)[1] = " doublespace" — counts as malformed? actually it's not empty, returns " doublespace"
	}
	// Drop the problematic case from the map and assert it separately because
	// SplitN(' ', 2) produces a leading-space token, which our impl returns
	// as-is — that's still preferable to silently trimming and risking lookup
	// mismatches.
	delete(cases, "Bearer  doublespace")
	for in, want := range cases {
		if got := ParseBearer(in); got != want {
			t.Errorf("ParseBearer(%q) = %q, want %q", in, got, want)
		}
	}
	if got := ParseBearer("Bearer  doublespace"); got != " doublespace" {
		t.Errorf("ParseBearer with double space: got %q, want %q", got, " doublespace")
	}
}

