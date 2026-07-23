// Package logto implements importer.Source for a Logto Postgres database. It
// reads (read-only) the users, roles and users_roles tables of a single Logto
// tenant and maps them onto OrionAuth's canonical import model.
package logto

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	_ "github.com/lib/pq" // registers the "postgres" driver

	"orion-auth-backend/crypto"
	"orion-auth-backend/importer"
	"orion-auth-backend/model"
)

// Source reads users from a Logto Postgres database.
type Source struct {
	db     *sql.DB
	tenant string
}

// Open connects to the Logto database at dsn (a lib/pq connection string or
// URL) and scopes the read to the given tenant (Logto OSS uses "default").
func Open(ctx context.Context, dsn, tenant string) (*Source, error) {
	if tenant == "" {
		tenant = "default"
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open logto db: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping logto db: %w", err)
	}
	return &Source{db: db, tenant: tenant}, nil
}

func (s *Source) Name() string { return "logto" }

func (s *Source) Close() error { return s.db.Close() }

// Users reads the tenant's users and joins their roles.
func (s *Source) Users(ctx context.Context) ([]importer.CanonicalUser, error) {
	rolesByUser, err := s.rolesByUser(ctx)
	if err != nil {
		return nil, err
	}

	const q = `
		SELECT id, username, primary_email, primary_phone, name, avatar,
		       password_encrypted, password_encryption_method,
		       profile, custom_data, identities, is_suspended
		FROM users
		WHERE tenant_id = $1`
	rows, err := s.db.QueryContext(ctx, q, s.tenant)
	if err != nil {
		return nil, fmt.Errorf("query logto users: %w", err)
	}
	defer rows.Close()

	var out []importer.CanonicalUser
	for rows.Next() {
		var (
			id                                   string
			username, email, phone, name, avatar sql.NullString
			passwordEncrypted, passwordMethod    sql.NullString
			profileRaw, customRaw, identitiesRaw []byte
			isSuspended                          bool
		)
		if err := rows.Scan(
			&id, &username, &email, &phone, &name, &avatar,
			&passwordEncrypted, &passwordMethod,
			&profileRaw, &customRaw, &identitiesRaw, &isSuspended,
		); err != nil {
			return nil, fmt.Errorf("scan logto user: %w", err)
		}

		hash, unsupported := normalizePassword(passwordMethod, passwordEncrypted)

		cu := importer.CanonicalUser{
			ExternalID:          id,
			Email:               strings.TrimSpace(email.String),
			DisplayName:         displayName(name, username),
			AvatarURL:           nullToPtr(avatar),
			Phone:               nullToPtr(phone),
			Username:            nullToPtr(username),
			EmailVerified:       email.Valid && email.String != "",
			PasswordHash:        hash,
			PasswordUnsupported: unsupported,
			Active:              !isSuspended,
			Profile:             buildProfile(profileRaw, username),
			CustomData:          decodeCustomData(customRaw),
			Identities:          decodeIdentities(identitiesRaw),
			Roles:               rolesByUser[id],
		}
		out = append(out, cu)
	}
	return out, rows.Err()
}

// rolesByUser returns source role names keyed by Logto user id.
func (s *Source) rolesByUser(ctx context.Context) (map[string][]string, error) {
	const q = `
		SELECT ur.user_id, r.name
		FROM users_roles ur
		JOIN roles r ON r.id = ur.role_id
		WHERE ur.tenant_id = $1`
	rows, err := s.db.QueryContext(ctx, q, s.tenant)
	if err != nil {
		return nil, fmt.Errorf("query logto roles: %w", err)
	}
	defer rows.Close()

	out := map[string][]string{}
	for rows.Next() {
		var userID, roleName string
		if err := rows.Scan(&userID, &roleName); err != nil {
			return nil, fmt.Errorf("scan logto role: %w", err)
		}
		out[userID] = append(out[userID], roleName)
	}
	return out, rows.Err()
}

// normalizePassword maps Logto's (password_encryption_method, password_encrypted)
// pair onto a self-describing hash string OrionAuth can verify, or reports it as
// unsupported. Argon2i and Bcrypt strings are already self-describing; the SHA*
// / MD5 modes store a bare hex digest we wrap; Legacy (and anything else) is
// unsupported.
func normalizePassword(method, encrypted sql.NullString) (hash *string, unsupported bool) {
	if !encrypted.Valid || encrypted.String == "" || !method.Valid {
		return nil, false
	}
	switch method.String {
	case "Argon2i", "Argon2id", "Bcrypt":
		h := encrypted.String
		return &h, false
	case "SHA256", "SHA1", "MD5":
		enc, err := crypto.EncodeForeignHash(strings.ToLower(method.String), encrypted.String)
		if err != nil {
			return nil, true
		}
		return &enc, false
	default: // "Legacy" or an unknown method
		return nil, true
	}
}

// logtoProfile mirrors the standard-claim keys of Logto's users.profile JSONB.
type logtoProfile struct {
	FamilyName        *string `json:"familyName"`
	GivenName         *string `json:"givenName"`
	MiddleName        *string `json:"middleName"`
	Nickname          *string `json:"nickname"`
	PreferredUsername *string `json:"preferredUsername"`
	Profile           *string `json:"profile"`
	Website           *string `json:"website"`
	Gender            *string `json:"gender"`
	Birthdate         *string `json:"birthdate"`
	Zoneinfo          *string `json:"zoneinfo"`
	Locale            *string `json:"locale"`
}

func buildProfile(raw []byte, username sql.NullString) model.ProfileMetadata {
	var lp logtoProfile
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &lp)
	}
	meta := model.ProfileMetadata{
		GivenName:         lp.GivenName,
		FamilyName:        lp.FamilyName,
		MiddleName:        lp.MiddleName,
		Nickname:          lp.Nickname,
		PreferredUsername: lp.PreferredUsername,
		ProfileURL:        lp.Profile,
		Website:           lp.Website,
		Gender:            lp.Gender,
		Birthdate:         lp.Birthdate,
		Zoneinfo:          lp.Zoneinfo,
		Locale:            lp.Locale,
	}
	// Logto's top-level username has no OIDC home; surface it as
	// preferred_username when the profile did not already set one.
	if meta.PreferredUsername == nil && username.Valid && username.String != "" {
		u := username.String
		meta.PreferredUsername = &u
	}
	return meta
}

func decodeCustomData(raw []byte) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || len(m) == 0 {
		return nil
	}
	return m
}

// logtoIdentity is one entry of the users.identities JSONB map, keyed by target.
type logtoIdentity struct {
	UserID  string          `json:"userId"`
	Details json.RawMessage `json:"details"`
}

func decodeIdentities(raw []byte) []importer.CanonicalIdentity {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]logtoIdentity
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	var out []importer.CanonicalIdentity
	for target, id := range m {
		if id.UserID == "" {
			continue
		}
		out = append(out, importer.CanonicalIdentity{
			Target:     target,
			ExternalID: id.UserID,
		})
	}
	return out
}

// displayName prefers Logto's name, falling back to username so display_name is
// populated for accounts that only set a login handle.
func displayName(name, username sql.NullString) *string {
	if p := nullToPtr(name); p != nil {
		return p
	}
	return nullToPtr(username)
}

func nullToPtr(ns sql.NullString) *string {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	s := ns.String
	return &s
}
