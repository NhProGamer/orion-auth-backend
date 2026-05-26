package password

type Policy struct {
	MinLength     int  `json:"min_length"`
	MaxLength     int  `json:"max_length"`
	RequireUpper  bool `json:"require_uppercase"`
	RequireLower  bool `json:"require_lowercase"`
	RequireDigit  bool `json:"require_digit"`
	RequireSymbol bool `json:"require_symbol"`
	MinScore      int  `json:"min_score"`
}

func DefaultPolicy() Policy {
	return Policy{
		MinLength:     8,
		MaxLength:     128,
		RequireUpper:  false,
		RequireLower:  false,
		RequireDigit:  false,
		RequireSymbol: false,
		MinScore:      0,
	}
}

func (p Policy) Normalize() Policy {
	if p.MinLength < 1 {
		p.MinLength = 1
	}
	if p.MinLength > 256 {
		p.MinLength = 256
	}
	if p.MaxLength != 0 && p.MaxLength < p.MinLength {
		p.MaxLength = p.MinLength
	}
	if p.MaxLength > 512 {
		p.MaxLength = 512
	}
	if p.MinScore < 0 {
		p.MinScore = 0
	}
	if p.MinScore > 4 {
		p.MinScore = 4
	}
	return p
}
