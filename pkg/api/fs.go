package api

import (
	"embed"
	"encoding/json"
	"io/fs"
	"sync"

	htmlTemplate "html/template"
	textTemplate "text/template"
)

var (
	funcsMap = map[string]any{
		"json": func(v any) string {
			out, _ := json.Marshal(v)
			return string(out)
		},
	}

	//go:embed templates/*.html templates/*.js templates/*.css
	templatesFS embed.FS

	syncMap sync.Map
)

// HTMLTemplates returns the HTML templates.
func HTMLTemplates() *htmlTemplate.Template {
	if v, ok := syncMap.Load("html"); ok {
		return v.(*htmlTemplate.Template)
	}

	subFS, _ := fs.Sub(templatesFS, "templates")
	tpl := htmlTemplate.Must(htmlTemplate.New("").Funcs(funcsMap).ParseFS(subFS, "*.html", "login.js", "*.css"))
	syncMap.Store("html", tpl)
	return tpl
}

// TextTemplates returns the text templates.
func TextTemplates() *textTemplate.Template {
	if v, ok := syncMap.Load("text"); ok {
		return v.(*textTemplate.Template)
	}

	subFS, _ := fs.Sub(templatesFS, "templates")
	tpl := textTemplate.Must(textTemplate.New("").Funcs(funcsMap).ParseFS(subFS, "proxy.js"))
	syncMap.Store("text", tpl)
	return tpl
}
