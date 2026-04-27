package inputs

// FieldDef describes a single addressable path inside a policy input or
// supported modify map. Paths are relative — the consuming UI prepends
// "input." for input fields. Types are JSON-friendly: string, number,
// boolean, array, object.
type FieldDef struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// TypeSchema lists every readable input field and every settable modify
// field for one policy type.
type TypeSchema struct {
	Input  []FieldDef `json:"input"`
	Modify []FieldDef `json:"modify"`
}

var (
	timeFieldDefs = []FieldDef{
		{Path: "time.hour", Type: "number", Description: "Hour of day in server local time, 0-23"},
		{Path: "time.weekday", Type: "string", Description: "Weekday name, e.g. \"Monday\""},
		{Path: "time.weekday_n", Type: "number", Description: "Weekday number, 0=Sunday..6=Saturday"},
		{Path: "time.unix", Type: "number", Description: "Unix timestamp in seconds"},
	}
	userFieldDefs = []FieldDef{
		{Path: "user.id", Type: "string"},
		{Path: "user.email", Type: "string"},
		{Path: "user.email_verified", Type: "boolean"},
		{Path: "user.active", Type: "boolean"},
	}
	clientFieldDefs = []FieldDef{
		{Path: "client.id", Type: "string"},
		{Path: "client.name", Type: "string"},
		{Path: "client.is_public", Type: "boolean"},
		{Path: "client.is_first_party", Type: "boolean"},
	}
)

// Schemas returns the per-type field catalog used by the admin UI for
// autocomplete and inline help. Hand-maintained alongside the Build*Input
// helpers in this package — keep them in sync.
func Schemas() map[string]TypeSchema {
	return map[string]TypeSchema{
		"login": {
			Input: concat(
				userFieldDefs,
				clientFieldDefs,
				[]FieldDef{
					{Path: "ip_address", Type: "string"},
					{Path: "user_agent", Type: "string"},
				},
				timeFieldDefs,
			),
		},
		"token_issuance": {
			Input: concat(
				clientFieldDefs,
				userFieldDefs,
				[]FieldDef{
					{Path: "scopes", Type: "array", Description: "Requested scopes (array of strings)"},
					{Path: "ip_address", Type: "string"},
				},
				timeFieldDefs,
			),
			Modify: []FieldDef{
				{Path: "access_token_ttl", Type: "number", Description: "Access token TTL in seconds (overrides client default)"},
				{Path: "refresh_token_ttl", Type: "number", Description: "Refresh token TTL in seconds (overrides client default)"},
				{Path: "scopes", Type: "array", Description: "Narrow granted scopes (intersected with requested)"},
				{Path: "claims", Type: "object", Description: "Custom claims merged into the ID token (reserved JWT claims protected)"},
			},
		},
		"consent": {
			Input: concat(
				userFieldDefs,
				clientFieldDefs,
				[]FieldDef{
					{Path: "scopes_requested", Type: "array"},
					{Path: "scopes_granted", Type: "array"},
					{Path: "ip_address", Type: "string"},
					{Path: "user_agent", Type: "string"},
				},
				timeFieldDefs,
			),
			Modify: []FieldDef{
				{Path: "scopes", Type: "array", Description: "Narrow granted scopes further before storing consent"},
			},
		},
		"refresh": {
			Input: concat(
				clientFieldDefs,
				userFieldDefs,
				[]FieldDef{
					{Path: "scopes_requested", Type: "array"},
					{Path: "scopes_granted", Type: "array"},
					{Path: "session_id", Type: "string"},
					{Path: "ip_address", Type: "string"},
				},
				timeFieldDefs,
			),
			Modify: []FieldDef{
				{Path: "scopes", Type: "array", Description: "Narrow granted scopes (intersected with current grant)"},
			},
		},
		"client_auth": {
			Input: concat(
				clientFieldDefs,
				[]FieldDef{
					{Path: "auth_method", Type: "string", Description: "client_secret_basic | client_secret_post | private_key_jwt | none"},
					{Path: "request.method", Type: "string"},
					{Path: "request.path", Type: "string"},
					{Path: "ip_address", Type: "string"},
					{Path: "user_agent", Type: "string"},
				},
				timeFieldDefs,
			),
		},
		"admin_api": {
			Input: concat(
				[]FieldDef{
					{Path: "user.id", Type: "string"},
					{Path: "user.permissions", Type: "array", Description: "Effective permission strings, e.g. \"clients:read\""},
					{Path: "request.method", Type: "string"},
					{Path: "request.path", Type: "string"},
					{Path: "ip_address", Type: "string"},
				},
				timeFieldDefs,
			),
		},
		"introspect": {
			Input: concat(
				[]FieldDef{
					{Path: "token.type", Type: "string", Description: "access_token or refresh_token"},
					{Path: "token.client_id", Type: "string"},
					{Path: "token.user_id", Type: "string", Description: "Absent for client_credentials tokens"},
					{Path: "token.scopes", Type: "array"},
					{Path: "token.audience", Type: "string"},
					{Path: "requesting_client.id", Type: "string", Description: "Client introspecting (the caller)"},
					{Path: "ip_address", Type: "string"},
				},
				timeFieldDefs,
			),
		},
		"device_approval": {
			Input: concat(
				userFieldDefs,
				clientFieldDefs,
				[]FieldDef{
					{Path: "scopes", Type: "array"},
					{Path: "user_code", Type: "string"},
					{Path: "ip_address", Type: "string"},
					{Path: "user_agent", Type: "string"},
				},
				timeFieldDefs,
			),
		},
		"mfa": {
			Input: concat(
				userFieldDefs,
				clientFieldDefs,
				[]FieldDef{
					{Path: "scopes", Type: "array"},
					{Path: "has_mfa", Type: "boolean", Description: "Whether the user has actually enrolled MFA"},
					{Path: "ip_address", Type: "string"},
					{Path: "user_agent", Type: "string"},
				},
				timeFieldDefs,
			),
			Modify: []FieldDef{
				{Path: "require_mfa", Type: "boolean", Description: "Override default \"needsMFA = has_mfa\". If true and has_mfa is false, login is denied."},
			},
		},
		"custom": {},
	}
}

func concat(parts ...[]FieldDef) []FieldDef {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]FieldDef, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
