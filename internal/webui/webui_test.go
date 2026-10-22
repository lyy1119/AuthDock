package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func bundleFS() fs.FS {
	return fstest.MapFS{
		"index.html": &fstest.MapFile{
			Data: []byte(`<!doctype html><html><body><div id="root"></div>` +
				`<script type="module" src="./assets/app-123.js"></script></body></html>`),
		},
		"assets/app-123.js": &fstest.MapFile{Data: []byte("console.log('app')")},
	}
}

func get(handler http.Handler, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func TestSPAServesIndexForClientRoutes(t *testing.T) {
	handler := NewSPAHandler(bundleFS())

	for _, path := range []string{"/", "/users", "/gates", "/settings", "/deep/nested/route"} {
		rec := get(handler, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `id="root"`) {
			t.Fatalf("GET %s did not serve the app shell", path)
		}
		if cache := rec.Header().Get("Cache-Control"); cache != "no-cache" {
			t.Fatalf("GET %s Cache-Control = %q, want no-cache", path, cache)
		}
	}
}

func TestSPAServesBuiltFiles(t *testing.T) {
	handler := NewSPAHandler(bundleFS())

	rec := get(handler, "/assets/app-123.js")
	if rec.Code != http.StatusOK {
		t.Fatalf("asset = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "console.log") {
		t.Fatalf("asset body = %q", body)
	}
	if cache := rec.Header().Get("Cache-Control"); !strings.Contains(cache, "immutable") {
		t.Fatalf("asset Cache-Control = %q, want immutable", cache)
	}
}

func TestSPAMissingAssetIsNotFound(t *testing.T) {
	handler := NewSPAHandler(bundleFS())

	rec := get(handler, "/assets/missing.js")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing asset = %d, want 404 (an HTML answer would surface as a MIME error)", rec.Code)
	}
}

func TestSPARejectsOtherMethods(t *testing.T) {
	handler := NewSPAHandler(bundleFS())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/users", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
		t.Fatalf("Allow = %q", allow)
	}
}

// TestEmbeddedBundleIsPresent guards the promise that a plain `go build` ships
// the management UI: the committed bundle must contain a shell and an asset.
func TestEmbeddedBundleIsPresent(t *testing.T) {
	assets, err := fs.Sub(embedded, "dist")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}

	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		t.Fatalf("reading embedded index.html: %v", err)
	}
	html := string(index)
	if !strings.Contains(html, `id="root"`) {
		t.Errorf("index.html does not look like the app shell: %s", html)
	}
	if strings.Contains(html, "/src/main.tsx") {
		t.Error("index.html still points at the Vite development entry point")
	}
	if !strings.Contains(html, `src="./assets/`) {
		t.Errorf("index.html does not reference a relative built asset: %s", html)
	}

	entries, err := fs.ReadDir(assets, "assets")
	if err != nil {
		t.Fatalf("reading embedded assets: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("the embedded bundle has no assets")
	}

	rec := get(Handler(), "/users")
	if rec.Code != http.StatusOK {
		t.Fatalf("Handler() GET /users = %d, want 200", rec.Code)
	}
}
