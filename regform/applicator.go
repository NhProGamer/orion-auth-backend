package regform

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

// Apply validates the extras submitted on /register or
// /complete-account against the schema filtered for the given context
// and writes the accepted values onto the user row. Standards land on
// model.User columns or merge into ProfileMetadata; custom fields land
// in metadata.custom_fields[key].
//
// The function is pure on the schema side: it never queries the repo,
// so the caller (user.Service.Register / CreateFromFederation) loads
// the schema once and passes it in.
func Apply(u *model.User, extras map[string]any, schema []model.RegistrationField, context string) error {
	if extras == nil {
		extras = map[string]any{}
	}

	// Decode current Metadata so we can mutate ProfileMetadata fields
	// and merge custom_fields without overwriting unrelated keys.
	meta := decodeMetadata(u.Metadata)

	for _, field := range schema {
		if !field.Enabled || !containsString(field.AppliesTo, context) {
			continue
		}
		raw, present := extras[field.FieldKey]
		if !present || isZero(raw) {
			if field.Required {
				return pkg.ErrBadRequest(fmt.Sprintf("field %q is required", field.FieldKey))
			}
			continue
		}

		coerced, err := coerceValue(field, raw)
		if err != nil {
			return err
		}
		if err := validateValue(field, coerced); err != nil {
			return err
		}

		switch field.Kind {
		case model.RegFieldKindStandard:
			if field.StandardTarget == nil {
				return pkg.ErrInternal(fmt.Sprintf("field %q is standard but has no target", field.FieldKey))
			}
			if err := applyStandard(u, meta, *field.StandardTarget, coerced); err != nil {
				return err
			}
		case model.RegFieldKindCustom:
			applyCustom(meta, field.FieldKey, coerced)
		default:
			return pkg.ErrInternal(fmt.Sprintf("field %q has unsupported kind %q", field.FieldKey, field.Kind))
		}
	}

	raw, err := json.Marshal(meta)
	if err != nil {
		return pkg.ErrInternal("failed to serialise user metadata")
	}
	u.Metadata = raw
	return nil
}

// ---- helpers

func decodeMetadata(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return map[string]any{}
	}
	return m
}

func isZero(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	case []any:
		return len(t) == 0
	}
	return false
}

func containsString(arr []string, target string) bool {
	for _, v := range arr {
		if v == target {
			return true
		}
	}
	return false
}

// coerceValue normalises raw JSON values to the type expected by the
// field. JSON numbers always come back as float64 — int targets need
// extra care. Multiselect values land as []string.
func coerceValue(field model.RegistrationField, raw any) (any, error) {
	switch field.Type {
	case model.RegFieldTypeText, model.RegFieldTypeTextarea,
		model.RegFieldTypeEmail, model.RegFieldTypeURL,
		model.RegFieldTypeTel, model.RegFieldTypeDate,
		model.RegFieldTypeSelect, model.RegFieldTypeRadio:
		s, ok := raw.(string)
		if !ok {
			return nil, pkg.ErrBadRequest(fmt.Sprintf("field %q expects a string value", field.FieldKey))
		}
		return strings.TrimSpace(s), nil
	case model.RegFieldTypeNumber:
		switch t := raw.(type) {
		case float64:
			return t, nil
		case int:
			return float64(t), nil
		case string:
			f, err := strconv.ParseFloat(t, 64)
			if err != nil {
				return nil, pkg.ErrBadRequest(fmt.Sprintf("field %q expects a number", field.FieldKey))
			}
			return f, nil
		}
		return nil, pkg.ErrBadRequest(fmt.Sprintf("field %q expects a number", field.FieldKey))
	case model.RegFieldTypeCheckbox:
		b, ok := raw.(bool)
		if !ok {
			return nil, pkg.ErrBadRequest(fmt.Sprintf("field %q expects a boolean", field.FieldKey))
		}
		return b, nil
	case model.RegFieldTypeMultiselect:
		arr, ok := raw.([]any)
		if !ok {
			return nil, pkg.ErrBadRequest(fmt.Sprintf("field %q expects an array of strings", field.FieldKey))
		}
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			s, ok := item.(string)
			if !ok {
				return nil, pkg.ErrBadRequest(fmt.Sprintf("field %q expects an array of strings", field.FieldKey))
			}
			out = append(out, s)
		}
		return out, nil
	}
	return raw, nil
}

func validateValue(field model.RegistrationField, value any) error {
	// Options must contain the chosen value for select/radio/multiselect.
	switch field.Type {
	case model.RegFieldTypeSelect, model.RegFieldTypeRadio:
		opts, err := decodeOptions(field.Options)
		if err != nil {
			return err
		}
		s := value.(string)
		if !optionValues(opts).contains(s) {
			return pkg.ErrBadRequest(fmt.Sprintf("field %q value not in options", field.FieldKey))
		}
	case model.RegFieldTypeMultiselect:
		opts, err := decodeOptions(field.Options)
		if err != nil {
			return err
		}
		allowed := optionValues(opts)
		for _, v := range value.([]string) {
			if !allowed.contains(v) {
				return pkg.ErrBadRequest(fmt.Sprintf("field %q value %q not in options", field.FieldKey, v))
			}
		}
	}
	return nil
}

type optionValueSet []string

func (s optionValueSet) contains(v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func decodeOptions(raw json.RawMessage) ([]FieldOption, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var opts []FieldOption
	if err := json.Unmarshal(raw, &opts); err != nil {
		return nil, pkg.ErrInternal("invalid options blob on field")
	}
	return opts, nil
}

func optionValues(opts []FieldOption) optionValueSet {
	out := make(optionValueSet, 0, len(opts))
	for _, o := range opts {
		out = append(out, o.Value)
	}
	return out
}

// applyStandard writes value to the canonical user column or
// ProfileMetadata slot.
func applyStandard(u *model.User, meta map[string]any, target string, value any) error {
	s, _ := value.(string) // most standard targets are string-typed
	switch target {
	case model.RegStandardDisplayName:
		v := s
		u.DisplayName = &v
	case model.RegStandardPhone:
		v := s
		u.Phone = &v
	case model.RegStandardGivenName:
		meta["given_name"] = s
	case model.RegStandardFamilyName:
		meta["family_name"] = s
	case model.RegStandardMiddleName:
		meta["middle_name"] = s
	case model.RegStandardNickname:
		meta["nickname"] = s
	case model.RegStandardPreferredUsername:
		meta["preferred_username"] = s
	case model.RegStandardProfileURL:
		meta["profile"] = s
	case model.RegStandardWebsite:
		meta["website"] = s
	case model.RegStandardGender:
		meta["gender"] = s
	case model.RegStandardBirthdate:
		meta["birthdate"] = s
	case model.RegStandardZoneinfo:
		meta["zoneinfo"] = s
	case model.RegStandardLocale:
		meta["locale"] = s
	default:
		return pkg.ErrInternal(fmt.Sprintf("unsupported standard_target %q", target))
	}
	return nil
}

func applyCustom(meta map[string]any, key string, value any) {
	existing, _ := meta["custom_fields"].(map[string]any)
	if existing == nil {
		existing = map[string]any{}
	}
	existing[key] = value
	meta["custom_fields"] = existing
}
