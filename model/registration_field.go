package model

import (
	"encoding/json"

	"github.com/lib/pq"
)

// Registration field kinds.
const (
	RegFieldKindStandard = "standard"
	RegFieldKindCustom   = "custom"
)

// Registration field types — the set the AuthUI knows how to render.
const (
	RegFieldTypeText        = "text"
	RegFieldTypeTextarea    = "textarea"
	RegFieldTypeEmail       = "email"
	RegFieldTypeURL         = "url"
	RegFieldTypeTel         = "tel"
	RegFieldTypeNumber      = "number"
	RegFieldTypeDate        = "date"
	RegFieldTypeSelect      = "select"
	RegFieldTypeMultiselect = "multiselect"
	RegFieldTypeCheckbox    = "checkbox"
	RegFieldTypeRadio       = "radio"
)

// Standard targets — the whitelist of model.User / ProfileMetadata
// fields an admin can opt into via a standard field. Enforced server
// side in regform.Service validation and regform.Applicator.
const (
	RegStandardDisplayName       = "display_name"
	RegStandardPhone             = "phone"
	RegStandardGivenName         = "metadata.given_name"
	RegStandardFamilyName        = "metadata.family_name"
	RegStandardMiddleName        = "metadata.middle_name"
	RegStandardNickname          = "metadata.nickname"
	RegStandardPreferredUsername = "metadata.preferred_username"
	RegStandardProfileURL        = "metadata.profile"
	RegStandardWebsite           = "metadata.website"
	RegStandardGender            = "metadata.gender"
	RegStandardBirthdate         = "metadata.birthdate"
	RegStandardZoneinfo          = "metadata.zoneinfo"
	RegStandardLocale            = "metadata.locale"
)

// Registration context tags — values allowed inside AppliesTo.
const (
	RegContextRegister   = "register"
	RegContextFederation = "federation"
)

// RegistrationField is one row of the operator-configurable signup
// form. The AuthUI renders one component per enabled row whose
// applies_to includes the current context.
type RegistrationField struct {
	BaseModel
	FieldKey       string          `gorm:"type:varchar(64);uniqueIndex;not null" json:"field_key"`
	Label          string          `gorm:"type:varchar(255);not null" json:"label"`
	Description    *string         `gorm:"type:varchar(512)" json:"description,omitempty"`
	Placeholder    *string         `gorm:"type:varchar(255)" json:"placeholder,omitempty"`
	Kind           string          `gorm:"type:varchar(16);not null" json:"kind"`
	StandardTarget *string         `gorm:"type:varchar(64)" json:"standard_target,omitempty"`
	Type           string          `gorm:"type:varchar(16);not null" json:"type"`
	Required       bool            `gorm:"not null;default:false" json:"required"`
	Enabled        bool            `gorm:"not null;default:true" json:"enabled"`
	DisplayOrder   int             `gorm:"not null;default:0" json:"display_order"`
	Options        json.RawMessage `gorm:"type:jsonb;default:'[]'" json:"options"`
	Validation     json.RawMessage `gorm:"type:jsonb;default:'{}'" json:"validation"`
	AppliesTo      pq.StringArray  `gorm:"type:text[];default:'{register,federation}'" json:"applies_to"`
}

func (RegistrationField) TableName() string { return "registration_fields" }
