package pkg

import (
	"net/url"
	"strings"
)

// IsOriginAllowed enforces a minimal allowlist: the target's scheme+host
// must match one of the allowed bases. Empty/unparsable bases are
// skipped silently so callers can pass an optional canonical base plus
// an arbitrary list of trusted SPA origins without pre-filtering.
func IsOriginAllowed(target string, allowedBases ...string) bool {
	if target == "" {
		return false
	}
	t, err := url.Parse(target)
	if err != nil {
		return false
	}
	for _, raw := range allowedBases {
		if raw == "" {
			continue
		}
		base, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if strings.EqualFold(t.Scheme, base.Scheme) && strings.EqualFold(t.Host, base.Host) {
			return true
		}
	}
	return false
}
