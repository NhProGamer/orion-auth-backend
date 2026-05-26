package password

import (
	"strings"
	"testing"
)

type fixedProvider struct{ p Policy }

func (f fixedProvider) Get() Policy { return f.p }

func TestValidator_StructuralRules(t *testing.T) {
	cases := []struct {
		name     string
		policy   Policy
		password string
		want     []string // substrings expected in error message; empty = no error
	}{
		{
			name:     "default policy accepts 8 chars",
			policy:   DefaultPolicy(),
			password: "abcdefgh",
			want:     nil,
		},
		{
			name:     "default policy rejects 7 chars",
			policy:   DefaultPolicy(),
			password: "abcdefg",
			want:     []string{"at least 8"},
		},
		{
			name:     "require uppercase missing",
			policy:   Policy{MinLength: 4, RequireUpper: true},
			password: "abcd1234",
			want:     []string{"uppercase"},
		},
		{
			name:     "require lowercase missing",
			policy:   Policy{MinLength: 4, RequireLower: true},
			password: "ABCD1234",
			want:     []string{"lowercase"},
		},
		{
			name:     "require digit missing",
			policy:   Policy{MinLength: 4, RequireDigit: true},
			password: "abcdefgh",
			want:     []string{"digit"},
		},
		{
			name:     "require symbol missing",
			policy:   Policy{MinLength: 4, RequireSymbol: true},
			password: "Abcd1234",
			want:     []string{"symbol"},
		},
		{
			name:     "symbol satisfied by punctuation",
			policy:   Policy{MinLength: 4, RequireSymbol: true},
			password: "Abcd!234",
			want:     nil,
		},
		{
			name:     "max length enforced",
			policy:   Policy{MinLength: 4, MaxLength: 6},
			password: "abcdefghij",
			want:     []string{"at most 6"},
		},
		{
			name:     "all char-class rules combined",
			policy:   Policy{MinLength: 8, RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSymbol: true},
			password: "Abcd1234!",
			want:     nil,
		},
		{
			name:     "multiple rules reported together",
			policy:   Policy{MinLength: 12, RequireUpper: true, RequireDigit: true},
			password: "abc",
			want:     []string{"at least 12", "uppercase", "digit"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := NewValidator(fixedProvider{p: tc.policy})
			err := v.Validate(tc.password)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %v, got nil", tc.want)
			}
			msg := err.Error()
			for _, sub := range tc.want {
				if !strings.Contains(msg, sub) {
					t.Errorf("error %q missing expected substring %q", msg, sub)
				}
			}
		})
	}
}

func TestValidator_ZxcvbnScore(t *testing.T) {
	v := NewValidator(fixedProvider{p: Policy{MinLength: 1, MinScore: 3}})

	if err := v.Validate("password"); err == nil {
		t.Fatalf("expected weak password to be rejected by min_score=3")
	}
	if err := v.Validate("correct horse battery staple"); err != nil {
		t.Fatalf("expected strong passphrase to pass min_score=3, got %v", err)
	}
}

func TestValidator_ZxcvbnUserInputsPenalised(t *testing.T) {
	v := NewValidator(fixedProvider{p: Policy{MinLength: 1, MinScore: 3}})

	// Without user input context, "Alice2024" might pass.
	// With Alice's email as input, zxcvbn should penalise it.
	err := v.Validate("Alice2024", "alice@example.com")
	if err == nil {
		t.Fatalf("expected password containing user inputs to be rejected at min_score=3")
	}
}

func TestValidator_NilReceiverFallsBackToDefault(t *testing.T) {
	var v *Validator
	if err := v.Validate("abcdefgh"); err != nil {
		t.Fatalf("nil validator should fall back to default policy; got %v", err)
	}
	if err := v.Validate("abc"); err == nil {
		t.Fatalf("nil validator should still enforce default min length")
	}
}

func TestValidator_NilProviderFallsBackToDefault(t *testing.T) {
	v := NewValidator(nil)
	if err := v.Validate("abc"); err == nil {
		t.Fatalf("expected default policy to reject 3-char password")
	}
}

func TestPolicy_Normalize(t *testing.T) {
	cases := []struct {
		name string
		in   Policy
		out  Policy
	}{
		{"clamp min length up", Policy{MinLength: 0}, Policy{MinLength: 1, MaxLength: 0, MinScore: 0}},
		{"clamp min length down", Policy{MinLength: 9999}, Policy{MinLength: 256, MaxLength: 0, MinScore: 0}},
		{"max raised to min when smaller", Policy{MinLength: 10, MaxLength: 4}, Policy{MinLength: 10, MaxLength: 10, MinScore: 0}},
		{"max length unchanged when zero", Policy{MinLength: 8, MaxLength: 0}, Policy{MinLength: 8, MaxLength: 0, MinScore: 0}},
		{"score clamped", Policy{MinLength: 8, MinScore: 9}, Policy{MinLength: 8, MaxLength: 0, MinScore: 4}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.Normalize()
			if got != tc.out {
				t.Errorf("Normalize() = %+v, want %+v", got, tc.out)
			}
		})
	}
}
