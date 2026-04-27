package oauth

import (
	"encoding/json"

	"github.com/lib/pq"
)

// readModifyBool extracts a boolean value from a policy Modify map.
// Returns (v, true) only if the value is present and is a bool.
func readModifyBool(modify map[string]any, key string) (bool, bool) {
	if modify == nil {
		return false, false
	}
	if v, ok := modify[key].(bool); ok {
		return v, true
	}
	return false, false
}

// readModifyInt extracts an integer value from a policy Modify map. The map is
// untyped JSON so values may arrive as json.Number or float64 depending on the
// decoder. Returns (n, true) only if the value is present and convertible.
func readModifyInt(modify map[string]any, key string) (int, bool) {
	raw, ok := modify[key]
	if !ok {
		return 0, false
	}
	switch v := raw.(type) {
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, false
		}
		return int(n), true
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	}
	return 0, false
}

// readModifyScopes extracts a "scopes" downscope from Modify and intersects it
// with the originally requested scopes. The intersection is one-way: a policy
// can never grant a scope the caller did not ask for, only narrow the set.
// Returns (narrowed, true) when modify.scopes is present and well-formed.
func readModifyScopes(modify map[string]any, requested pq.StringArray) (pq.StringArray, bool) {
	raw, ok := modify["scopes"]
	if !ok {
		return nil, false
	}
	allowed, ok := stringSetFromAny(raw)
	if !ok {
		return nil, false
	}
	narrowed := make(pq.StringArray, 0, len(requested))
	for _, s := range requested {
		if allowed[s] {
			narrowed = append(narrowed, s)
		}
	}
	return narrowed, true
}

func stringSetFromAny(raw any) (map[string]bool, bool) {
	arr, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	set := make(map[string]bool, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			set[s] = true
		}
	}
	return set, true
}
