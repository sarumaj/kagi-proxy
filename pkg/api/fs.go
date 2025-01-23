package api

import (
	"bytes"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"sync"

	htmlTemplate "html/template"
	textTemplate "text/template"
)

var (
	funcsMap = map[string]any{
		"json": func(v any) htmlTemplate.JS {
			out, err := json.Marshal(v)
			if err != nil {
				return htmlTemplate.JS("null")
			}
			return htmlTemplate.JS(bytes.ReplaceAll(out, []byte{'\\'}, []byte(`\x5c`)))
		},
		"codeString": func(code int) string {
			txt := http.StatusText(code)
			if len(txt) > 0 {
				return txt
			}
			return "Unknown Status Code"
		},
	}

	//go:embed templates/*.html templates/*.js templates/*.css
	templatesFS embed.FS

	syncMap sync.Map
)

// HTMLTemplates returns the HTML templates.
// *.css and *.js files are also included to support template injection.
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
// At the moment, only proxy.js is included.
func TextTemplates() *textTemplate.Template {
	if v, ok := syncMap.Load("text"); ok {
		return v.(*textTemplate.Template)
	}

	subFS, _ := fs.Sub(templatesFS, "templates")
	tpl := textTemplate.Must(textTemplate.New("").Funcs(funcsMap).ParseFS(subFS, "proxy.js"))
	syncMap.Store("text", tpl)
	return tpl
}
