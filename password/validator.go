package password

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/trustelem/zxcvbn"

	"orion-auth-backend/pkg"
)

type Provider interface {
	Get() Policy
}

type Validator struct {
	provider Provider
}

func NewValidator(p Provider) *Validator {
	return &Validator{provider: p}
}

// Validate runs every active rule of the configured policy against the
// given password. userInputs (email, display name…) are fed to zxcvbn so
// that "alice@example.com" → password "alice123" is properly penalised.
//
// All failing rules are returned at once in the error message so the
// caller can show the full feedback rather than a single rule at a time.
func (v *Validator) Validate(password string, userInputs ...string) error {
	policy := DefaultPolicy()
	if v != nil && v.provider != nil {
		policy = v.provider.Get().Normalize()
	}

	var problems []string

	if len(password) < policy.MinLength {
		problems = append(problems, fmt.Sprintf("must be at least %d characters", policy.MinLength))
	}
	if policy.MaxLength > 0 && len(password) > policy.MaxLength {
		problems = append(problems, fmt.Sprintf("must be at most %d characters", policy.MaxLength))
	}

	hasUpper, hasLower, hasDigit, hasSymbol := classify(password)
	if policy.RequireUpper && !hasUpper {
		problems = append(problems, "must contain an uppercase letter")
	}
	if policy.RequireLower && !hasLower {
		problems = append(problems, "must contain a lowercase letter")
	}
	if policy.RequireDigit && !hasDigit {
		problems = append(problems, "must contain a digit")
	}
	if policy.RequireSymbol && !hasSymbol {
		problems = append(problems, "must contain a symbol")
	}

	if policy.MinScore > 0 && len(password) > 0 {
		inputs := sanitizeInputs(userInputs)
		score := zxcvbn.PasswordStrength(password, inputs).Score
		if score < policy.MinScore {
			problems = append(problems, fmt.Sprintf("must reach a strength score of at least %d (currently %d)", policy.MinScore, score))
		}
	}

	if len(problems) == 0 {
		return nil
	}
	return pkg.ErrBadRequest("password " + strings.Join(problems, "; "))
}

func classify(password string) (upper, lower, digit, symbol bool) {
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r) || unicode.IsSpace(r):
			symbol = true
		}
	}
	return
}

func sanitizeInputs(inputs []string) []string {
	out := make([]string, 0, len(inputs))
	for _, in := range inputs {
		s := strings.TrimSpace(in)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
