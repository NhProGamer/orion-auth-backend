package pkg

import "testing"

func TestIsOriginAllowed(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		bases    []string
		expected bool
	}{
		{
			name:     "spa origin matches an extra base",
			target:   "https://dev.clown.school/profile",
			bases:    []string{"https://devauth.clown.school/ui", "https://dev.clown.school"},
			expected: true,
		},
		{
			name:     "authui base still accepted alongside extras",
			target:   "https://devauth.clown.school/ui/x",
			bases:    []string{"https://devauth.clown.school/ui", "https://dev.clown.school"},
			expected: true,
		},
		{
			name:     "unknown origin rejected",
			target:   "https://evil.com/x",
			bases:    []string{"https://devauth.clown.school/ui", "https://dev.clown.school"},
			expected: false,
		},
		{
			name:     "empty target rejected",
			target:   "",
			bases:    []string{"https://devauth.clown.school/ui", "https://dev.clown.school"},
			expected: false,
		},
		{
			name:     "spa rejected when no extra origins configured",
			target:   "https://dev.clown.school/profile",
			bases:    []string{"https://devauth.clown.school/ui"},
			expected: false,
		},
		{
			name:     "case-insensitive host and scheme match",
			target:   "HTTPS://DEV.CLOWN.SCHOOL/profile",
			bases:    []string{"https://devauth.clown.school/ui", "https://dev.clown.school"},
			expected: true,
		},
		{
			name:     "empty base entries are skipped",
			target:   "https://dev.clown.school/profile",
			bases:    []string{"", "https://dev.clown.school"},
			expected: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsOriginAllowed(tc.target, tc.bases...)
			if got != tc.expected {
				t.Fatalf("IsOriginAllowed(%q, %v) = %v, want %v", tc.target, tc.bases, got, tc.expected)
			}
		})
	}
}
