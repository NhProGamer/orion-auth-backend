package model

type Setting struct {
	Key   string `gorm:"type:varchar(100);primaryKey" json:"key"`
	Value string `gorm:"type:text;not null" json:"value"`
}

func (Setting) TableName() string {
	return "settings"
}
