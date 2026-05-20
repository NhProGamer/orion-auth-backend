package regform

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

type Service struct {
	repo RepositoryInterface
}

func NewService(repo RepositoryInterface) *Service {
	return &Service{repo: repo}
}

// --- Whitelists (kept here so the validation is colocated with the
// service that enforces it). Mirrored on the AuthUI / AdminUI.

var allowedKinds = map[string]struct{}{
	model.RegFieldKindStandard: {},
	model.RegFieldKindCustom:   {},
}

var allowedTypes = map[string]struct{}{
	model.RegFieldTypeText:        {},
	model.RegFieldTypeTextarea:    {},
	model.RegFieldTypeEmail:       {},
	model.RegFieldTypeURL:         {},
	model.RegFieldTypeTel:         {},
	model.RegFieldTypeNumber:      {},
	model.RegFieldTypeDate:        {},
	model.RegFieldTypeSelect:      {},
	model.RegFieldTypeMultiselect: {},
	model.RegFieldTypeCheckbox:    {},
	model.RegFieldTypeRadio:       {},
}

// StandardTargets is the canonical map of standard_target → expected
// default type. The applicator switches on the key.
var StandardTargets = map[string]string{
	model.RegStandardDisplayName:       model.RegFieldTypeText,
	model.RegStandardPhone:             model.RegFieldTypeTel,
	model.RegStandardGivenName:         model.RegFieldTypeText,
	model.RegStandardFamilyName:        model.RegFieldTypeText,
	model.RegStandardMiddleName:        model.RegFieldTypeText,
	model.RegStandardNickname:          model.RegFieldTypeText,
	model.RegStandardPreferredUsername: model.RegFieldTypeText,
	model.RegStandardProfileURL:        model.RegFieldTypeURL,
	model.RegStandardWebsite:           model.RegFieldTypeURL,
	model.RegStandardGender:            model.RegFieldTypeText,
	model.RegStandardBirthdate:         model.RegFieldTypeDate,
	model.RegStandardZoneinfo:          model.RegFieldTypeText,
	model.RegStandardLocale:            model.RegFieldTypeText,
}

var allowedContexts = map[string]struct{}{
	model.RegContextRegister:   {},
	model.RegContextFederation: {},
}

var fieldKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// FieldOption is one entry of options for select / radio / multiselect.
type FieldOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// --- Inputs

type CreateInput struct {
	FieldKey       string          `json:"field_key" binding:"required"`
	Label          string          `json:"label" binding:"required"`
	Description    *string         `json:"description"`
	Placeholder    *string         `json:"placeholder"`
	Kind           string          `json:"kind" binding:"required"`
	StandardTarget *string         `json:"standard_target"`
	Type           string          `json:"type" binding:"required"`
	Required       bool            `json:"required"`
	Enabled        *bool           `json:"enabled"`
	Options        json.RawMessage `json:"options"`
	Validation     json.RawMessage `json:"validation"`
	AppliesTo      []string        `json:"applies_to"`
}

type UpdateInput struct {
	Label          *string         `json:"label"`
	Description    *string         `json:"description"`
	Placeholder    *string         `json:"placeholder"`
	Kind           *string         `json:"kind"`
	StandardTarget *string         `json:"standard_target"`
	Type           *string         `json:"type"`
	Required       *bool           `json:"required"`
	Enabled        *bool           `json:"enabled"`
	Options        json.RawMessage `json:"options"`
	Validation     json.RawMessage `json:"validation"`
	AppliesTo      []string        `json:"applies_to"`
}

type ReorderInput struct {
	IDs []uuid.UUID `json:"ids" binding:"required"`
}

// --- Service methods

func (s *Service) List() ([]model.RegistrationField, error) {
	fields, err := s.repo.List()
	if err != nil {
		return nil, pkg.ErrInternal("failed to list registration fields")
	}
	return fields, nil
}

func (s *Service) ListForContext(context string) ([]model.RegistrationField, error) {
	if _, ok := allowedContexts[context]; !ok {
		return nil, pkg.ErrBadRequest("context must be 'register' or 'federation'")
	}
	fields, err := s.repo.ListForContext(context)
	if err != nil {
		return nil, pkg.ErrInternal("failed to list registration fields")
	}
	return fields, nil
}

func (s *Service) Get(id uuid.UUID) (*model.RegistrationField, error) {
	f, err := s.repo.FindByID(id)
	if err != nil {
		return nil, pkg.ErrInternal("failed to find registration field")
	}
	if f == nil {
		return nil, pkg.ErrNotFound("registration field not found")
	}
	return f, nil
}

func (s *Service) Create(in CreateInput) (*model.RegistrationField, error) {
	if !fieldKeyRe.MatchString(in.FieldKey) {
		return nil, pkg.ErrBadRequest("field_key must match ^[a-z][a-z0-9_]{0,63}$")
	}
	if existing, _ := s.repo.FindByKey(in.FieldKey); existing != nil {
		return nil, pkg.ErrConflict("field_key already exists")
	}
	if err := validateKindTargetType(in.Kind, in.StandardTarget, in.Type); err != nil {
		return nil, err
	}
	if err := validateOptions(in.Type, in.Options); err != nil {
		return nil, err
	}
	contexts, err := normaliseContexts(in.AppliesTo)
	if err != nil {
		return nil, err
	}

	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	options := in.Options
	if len(options) == 0 {
		options = json.RawMessage("[]")
	}
	validation := in.Validation
	if len(validation) == 0 {
		validation = json.RawMessage("{}")
	}

	// Append at the tail so an admin "Add field" lands last unless they
	// drag-drop afterwards.
	existing, _ := s.repo.List()
	displayOrder := len(existing)

	f := &model.RegistrationField{
		FieldKey:       in.FieldKey,
		Label:          in.Label,
		Description:    in.Description,
		Placeholder:    in.Placeholder,
		Kind:           in.Kind,
		StandardTarget: in.StandardTarget,
		Type:           in.Type,
		Required:       in.Required,
		Enabled:        enabled,
		DisplayOrder:   displayOrder,
		Options:        options,
		Validation:     validation,
		AppliesTo:      pq.StringArray(contexts),
	}
	if err := s.repo.Create(f); err != nil {
		slog.Error("regform create failed", "error", err)
		return nil, pkg.ErrInternal("failed to create registration field")
	}
	slog.Info("registration field created", "key", f.FieldKey, "kind", f.Kind, "type", f.Type)
	return f, nil
}

func (s *Service) Update(id uuid.UUID, in UpdateInput) (*model.RegistrationField, error) {
	f, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	if in.Label != nil {
		f.Label = *in.Label
	}
	if in.Description != nil {
		v := *in.Description
		if v == "" {
			f.Description = nil
		} else {
			f.Description = &v
		}
	}
	if in.Placeholder != nil {
		v := *in.Placeholder
		if v == "" {
			f.Placeholder = nil
		} else {
			f.Placeholder = &v
		}
	}
	if in.Kind != nil {
		f.Kind = *in.Kind
	}
	if in.StandardTarget != nil {
		v := *in.StandardTarget
		if v == "" {
			f.StandardTarget = nil
		} else {
			f.StandardTarget = &v
		}
	}
	if in.Type != nil {
		f.Type = *in.Type
	}
	if in.Required != nil {
		f.Required = *in.Required
	}
	if in.Enabled != nil {
		f.Enabled = *in.Enabled
	}
	if len(in.Options) > 0 {
		f.Options = in.Options
	}
	if len(in.Validation) > 0 {
		f.Validation = in.Validation
	}
	if in.AppliesTo != nil {
		contexts, err := normaliseContexts(in.AppliesTo)
		if err != nil {
			return nil, err
		}
		f.AppliesTo = pq.StringArray(contexts)
	}

	if err := validateKindTargetType(f.Kind, f.StandardTarget, f.Type); err != nil {
		return nil, err
	}
	if err := validateOptions(f.Type, f.Options); err != nil {
		return nil, err
	}

	if err := s.repo.Update(f); err != nil {
		return nil, pkg.ErrInternal("failed to update registration field")
	}
	return f, nil
}

func (s *Service) Delete(id uuid.UUID) error {
	if _, err := s.Get(id); err != nil {
		return err
	}
	if err := s.repo.Delete(id); err != nil {
		return pkg.ErrInternal("failed to delete registration field")
	}
	return nil
}

// Apply is a thin pass-through over the package-level Apply function so
// the Service satisfies user.RegFormProvider without exposing the
// internal applicator at the call site.
func (s *Service) Apply(u *model.User, extras map[string]any, schema []model.RegistrationField, context string) error {
	return Apply(u, extras, schema, context)
}

func (s *Service) Reorder(in ReorderInput) error {
	if len(in.IDs) == 0 {
		return pkg.ErrBadRequest("ids must be a non-empty list")
	}
	if err := s.repo.Reorder(in.IDs); err != nil {
		return pkg.ErrInternal("failed to reorder registration fields")
	}
	return nil
}

// --- Validation helpers

func validateKindTargetType(kind string, target *string, typ string) error {
	if _, ok := allowedKinds[kind]; !ok {
		return pkg.ErrBadRequest("kind must be 'standard' or 'custom'")
	}
	if _, ok := allowedTypes[typ]; !ok {
		return pkg.ErrBadRequest(fmt.Sprintf("type %q is not supported", typ))
	}
	switch kind {
	case model.RegFieldKindStandard:
		if target == nil || *target == "" {
			return pkg.ErrBadRequest("standard kind requires a standard_target")
		}
		if _, ok := StandardTargets[*target]; !ok {
			return pkg.ErrBadRequest(fmt.Sprintf("standard_target %q is not in the catalogue", *target))
		}
	case model.RegFieldKindCustom:
		if target != nil && *target != "" {
			return pkg.ErrBadRequest("custom kind must not declare a standard_target")
		}
	}
	return nil
}

func validateOptions(typ string, raw json.RawMessage) error {
	requiresOpts := typ == model.RegFieldTypeSelect || typ == model.RegFieldTypeMultiselect || typ == model.RegFieldTypeRadio
	if !requiresOpts {
		return nil
	}
	if len(raw) == 0 {
		return pkg.ErrBadRequest(fmt.Sprintf("type %q requires options", typ))
	}
	var opts []FieldOption
	if err := json.Unmarshal(raw, &opts); err != nil {
		return pkg.ErrBadRequest("options must be an array of {value, label} pairs")
	}
	if len(opts) == 0 {
		return pkg.ErrBadRequest(fmt.Sprintf("type %q requires at least one option", typ))
	}
	for _, o := range opts {
		if o.Value == "" || o.Label == "" {
			return pkg.ErrBadRequest("each option must have a non-empty value and label")
		}
	}
	return nil
}

func normaliseContexts(in []string) ([]string, error) {
	if len(in) == 0 {
		return []string{model.RegContextRegister, model.RegContextFederation}, nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, c := range in {
		if _, ok := allowedContexts[c]; !ok {
			return nil, pkg.ErrBadRequest(fmt.Sprintf("applies_to value %q is not allowed", c))
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out, nil
}
