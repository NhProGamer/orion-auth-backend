package templates

import "embed"

//go:embed *.gohtml
var FS embed.FS

//go:embed assets/*.svg
var Assets embed.FS
