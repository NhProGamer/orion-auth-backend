package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/model"
)

// Mapping is operator-supplied migration configuration, loaded from the
// --mapping JSON file. It bridges source-specific names to OrionAuth entities
// and sets the policy for edge cases.
type Mapping struct {
	// Providers maps a source identity target (e.g. "discord") to an OrionAuth
	// federation_providers.name. Identities whose target is absent are skipped
	// and reported.
	Providers map[string]string `json:"providers"`
	// Roles maps a source role name to an OrionAuth roles.name. Unmapped roles
	// are skipped and reported.
	Roles map[string]string `json:"roles"`
	// AssumeVerifiedEmail marks every imported user with an email as verified,
	// regardless of what the source reported. Most IAMs only keep verified
	// primary emails, so this defaults on in the CLI.
	AssumeVerifiedEmail bool `json:"assume_verified_email"`
	// DefaultRole (an OrionAuth role name) is assigned to a user who ends up
	// with no mapped role. Empty means "assign nothing".
	DefaultRole string `json:"default_role"`
	// OnUnsupportedPassword controls what happens when a user had a password the
	// source could not normalize: "reset" (default — import password-less, user
	// must reset), "skip" (do not import the user at all), or "fail" (abort).
	OnUnsupportedPassword string `json:"on_unsupported_password"`
}

const (
	onUnsupportedReset = "reset"
	onUnsupportedSkip  = "skip"
	onUnsupportedFail  = "fail"
)

// Report is the outcome of an import run.
type Report struct {
	Total             int
	Created           int
	SkippedExisting   int
	SkippedNoEmail    int
	SkippedNoPassword int // skipped because of on_unsupported_password=skip
	ForcedReset       int // imported password-less (unsupported hash → reset)
	SocialOnly        int // imported password-less (genuinely had no password)
	LinksCreated      int
	RolesAssigned     int
	UnmappedProviders map[string]int
	UnmappedRoles     map[string]int
	Warnings          []string
}

func newReport() *Report {
	return &Report{
		UnmappedProviders: map[string]int{},
		UnmappedRoles:     map[string]int{},
	}
}

// Engine writes canonical users into an OrionAuth database.
type Engine struct {
	db         *gorm.DB
	mapping    Mapping
	dryRun     bool
	sourceName string

	providerIDs map[string]uuid.UUID // orion provider name → id
	roleIDs     map[string]uuid.UUID // orion role name → id
}

// NewEngine resolves the mapping against the target database up front so a
// typo in --mapping fails fast instead of mid-migration. It errors if any
// referenced OrionAuth provider or role does not exist.
func NewEngine(db *gorm.DB, mapping Mapping, sourceName string, dryRun bool) (*Engine, error) {
	if mapping.OnUnsupportedPassword == "" {
		mapping.OnUnsupportedPassword = onUnsupportedReset
	}
	switch mapping.OnUnsupportedPassword {
	case onUnsupportedReset, onUnsupportedSkip, onUnsupportedFail:
	default:
		return nil, fmt.Errorf("invalid on_unsupported_password %q (want reset|skip|fail)", mapping.OnUnsupportedPassword)
	}

	e := &Engine{
		db:          db,
		mapping:     mapping,
		dryRun:      dryRun,
		sourceName:  sourceName,
		providerIDs: map[string]uuid.UUID{},
		roleIDs:     map[string]uuid.UUID{},
	}

	// Resolve every distinct OrionAuth provider/role name the mapping targets.
	wantProviders := distinctValues(mapping.Providers)
	for _, name := range wantProviders {
		var p model.FederationProvider
		if err := db.Where("name = ?", name).First(&p).Error; err != nil {
			return nil, fmt.Errorf("mapping references unknown federation provider %q: %w", name, err)
		}
		e.providerIDs[name] = p.ID
	}

	wantRoles := distinctValues(mapping.Roles)
	if mapping.DefaultRole != "" {
		wantRoles = append(wantRoles, mapping.DefaultRole)
	}
	for _, name := range wantRoles {
		var r model.Role
		if err := db.Where("name = ?", name).First(&r).Error; err != nil {
			return nil, fmt.Errorf("mapping references unknown role %q: %w", name, err)
		}
		e.roleIDs[name] = r.ID
	}

	return e, nil
}

// Import applies every canonical user. It never aborts on a per-user failure
// (those are collected as warnings) except when on_unsupported_password=fail.
func (e *Engine) Import(ctx context.Context, users []CanonicalUser) (*Report, error) {
	rep := newReport()
	for i := range users {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		if err := e.importOne(&users[i], rep); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

func (e *Engine) importOne(u *CanonicalUser, rep *Report) error {
	rep.Total++

	email := strings.ToLower(strings.TrimSpace(u.Email))
	if email == "" {
		rep.SkippedNoEmail++
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("no email for source id %s — skipped", u.ExternalID))
		return nil
	}

	// Idempotency: never clobber an account that already exists locally.
	var count int64
	if err := e.db.Model(&model.User{}).Where("email = ?", email).Count(&count).Error; err != nil {
		return fmt.Errorf("check existing %s: %w", email, err)
	}
	if count > 0 {
		rep.SkippedExisting++
		return nil
	}

	// Password policy.
	passwordHash := u.PasswordHash
	mustSet := false
	if passwordHash == nil {
		if u.PasswordUnsupported {
			switch e.mapping.OnUnsupportedPassword {
			case onUnsupportedFail:
				return fmt.Errorf("user %s has an unsupported password hash and on_unsupported_password=fail", email)
			case onUnsupportedSkip:
				rep.SkippedNoPassword++
				return nil
			default:
				mustSet = true
				rep.ForcedReset++
			}
		} else {
			mustSet = true
			rep.SocialOnly++
		}
	}

	// Resolve roles.
	assignRoleIDs, unmappedRoles := e.resolveRoles(u.Roles)
	for _, rn := range unmappedRoles {
		rep.UnmappedRoles[rn]++
	}

	// Resolve identity links.
	links, unmappedProviders := e.resolveLinks(u.Identities)
	for _, t := range unmappedProviders {
		rep.UnmappedProviders[t]++
	}

	metadata, err := e.buildMetadata(u)
	if err != nil {
		return fmt.Errorf("build metadata for %s: %w", email, err)
	}

	user := &model.User{
		Email:           email,
		EmailVerified:   u.EmailVerified || (e.mapping.AssumeVerifiedEmail && email != ""),
		PasswordHash:    passwordHash,
		MustSetPassword: mustSet,
		DisplayName:     u.DisplayName,
		AvatarURL:       u.AvatarURL,
		Phone:           u.Phone,
		Active:          u.Active,
		Metadata:        metadata,
	}

	if e.dryRun {
		rep.Created++
		rep.RolesAssigned += len(assignRoleIDs)
		rep.LinksCreated += len(links)
		return nil
	}

	err = e.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		for _, rid := range assignRoleIDs {
			if err := tx.Exec(
				"INSERT INTO user_roles (user_id, role_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
				user.ID, rid,
			).Error; err != nil {
				return fmt.Errorf("assign role: %w", err)
			}
		}
		for j := range links {
			links[j].UserID = user.ID
			if err := tx.Create(&links[j]).Error; err != nil {
				return fmt.Errorf("create federation link: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("import %s failed: %v", email, err))
		return nil
	}

	rep.Created++
	rep.RolesAssigned += len(assignRoleIDs)
	rep.LinksCreated += len(links)
	return nil
}

func (e *Engine) resolveRoles(sourceRoles []string) (ids []uuid.UUID, unmapped []string) {
	matched := false
	for _, rn := range sourceRoles {
		orionName, ok := e.mapping.Roles[rn]
		if !ok {
			unmapped = append(unmapped, rn)
			continue
		}
		if id, ok := e.roleIDs[orionName]; ok {
			ids = append(ids, id)
			matched = true
		}
	}
	if !matched && e.mapping.DefaultRole != "" {
		if id, ok := e.roleIDs[e.mapping.DefaultRole]; ok {
			ids = append(ids, id)
		}
	}
	return ids, unmapped
}

func (e *Engine) resolveLinks(identities []CanonicalIdentity) (links []model.FederationLink, unmapped []string) {
	for _, id := range identities {
		orionProv, ok := e.mapping.Providers[id.Target]
		if !ok {
			unmapped = append(unmapped, id.Target)
			continue
		}
		pid, ok := e.providerIDs[orionProv]
		if !ok {
			unmapped = append(unmapped, id.Target)
			continue
		}
		links = append(links, model.FederationLink{
			ProviderID: pid,
			ExternalID: id.ExternalID,
			Email:      id.Email,
		})
	}
	return links, unmapped
}

// buildMetadata merges the OIDC profile claims with the source's custom data
// and an _import provenance block. Unknown keys survive in the JSONB column;
// GetProfileMetadata only reads the standard claim keys.
func (e *Engine) buildMetadata(u *CanonicalUser) (json.RawMessage, error) {
	metaMap := map[string]any{}

	profileBytes, err := json.Marshal(u.Profile)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(profileBytes, &metaMap); err != nil {
		return nil, err
	}

	if len(u.CustomData) > 0 {
		metaMap["custom_data"] = u.CustomData
	}
	metaMap["_import"] = map[string]any{
		"source":      e.sourceName,
		"external_id": u.ExternalID,
	}

	return json.Marshal(metaMap)
}

func distinctValues(m map[string]string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, v := range m {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
