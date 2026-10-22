// Package webui serves the compiled React management UI.
//
// The bundle in ./dist comes from Vite (sources live in ../web) and is embedded
// into the binary, so a plain `go build` produces one self-contained executable
// that already carries the management pages. Run `make web` (or `make build`)
// to regenerate it after changing the frontend.
package webui

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed all:dist
var embedded embed.FS

// Handler serves the embedded bundle.
func Handler() http.Handler {
	assets, err := fs.Sub(embedded, "dist")
	if err != nil {
		panic("webui: embedded bundle is unreadable: " + err.Error())
	}
	return NewSPAHandler(assets)
}

// NewSPAHandler serves a single-page application from fsys.
//
// Requests for a file that exists are served directly; anything else falls back
// to index.html so client-side routes deep-link correctly. A request that names
// a missing file with an extension is a genuine 404 instead, because answering
// it with HTML turns a missing asset into a confusing MIME type error in the
// browser.
func NewSPAHandler(fsys fs.FS) http.Handler {
	files := http.FileServerFS(fsys)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" || name == "." {
			serveIndex(w, r, fsys)
			return
		}

		if info, err := fs.Stat(fsys, name); err == nil && !info.IsDir() {
			if strings.HasPrefix(name, "assets/") {
				// Asset names carry a content hash, so they never change.
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			files.ServeHTTP(w, r)
			return
		}

		if ext := path.Ext(name); ext != "" && ext != ".html" {
			http.NotFound(w, r)
			return
		}
		serveIndex(w, r, fsys)
	})
}

// serveIndex writes index.html, letting ServeContent handle HEAD and ranges.
func serveIndex(w http.ResponseWriter, r *http.Request, fsys fs.FS) {
	data, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		http.Error(w, "the frontend bundle is missing index.html", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(data))
}
