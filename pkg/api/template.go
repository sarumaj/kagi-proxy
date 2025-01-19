package api

import (
	"embed"
	"encoding/json"
	"io/fs"

	htmlTemplate "html/template"
	textTemplate "text/template"
)

//go:embed templates/*.html templates/*.js
var templatesFS embed.FS

// HTMLTemplates returns the HTML templates.
func HTMLTemplates() *htmlTemplate.Template {
	subFS, _ := fs.Sub(templatesFS, "templates")

	return htmlTemplate.Must(htmlTemplate.New("").ParseFS(subFS, "*.html"))
}

// TextTemplates returns the text templates.
func TextTemplates() *textTemplate.Template {
	subFS, _ := fs.Sub(templatesFS, "templates")
	return textTemplate.Must(textTemplate.New("").Funcs(textTemplate.FuncMap{
		"json": func(v any) string {
			out, _ := json.Marshal(v)
			return string(out)
		},
	}).ParseFS(subFS, "*.js"))
}
