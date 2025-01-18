package api

import (
	_ "embed"
	"html/template"
)

//go:embed templates/login.html
var loginTemplate string

// Templates returns the HTML templates.
func Templates() *template.Template {
	return template.Must(template.New("login.html").Parse(loginTemplate))
}
