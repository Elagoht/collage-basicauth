package basicauth_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	basicauth "github.com/Elagoht/collage-basicauth"
	"github.com/Elagoht/collage/pkg/collage"
	"golang.org/x/crypto/bcrypt"
)

func site(t *testing.T, opts basicauth.Options, config map[string]json.RawMessage) http.Handler {
	t.Helper()
	app, err := collage.New(&collage.Config{
		Server: collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: fstest.MapFS{
			"t/p.html": {Data: []byte(`<main>secret</main>`)},
		}, Root: "t"},
		Cache:        collage.CacheConfig{Enabled: true, Type: "memory", DefaultTTL: time.Hour},
		Plugins:      []collage.Plugin{basicauth.New(opts)},
		PluginConfig: config,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"home": "/", "admin": "/admin", "report": "/healthz-report"} {
		// Static, so collage marks it public and caches it.
		page := collage.NewPage(name).WithContent(collage.NewFragment(name, "p.html").Build()).WithPath("en", path).Static().Build()
		if err := app.RegisterPage(page); err != nil {
			t.Fatal(err)
		}
	}
	if err := app.RegisterDocument(collage.NewDocument("health", "text/plain").AtRoot("/healthz").WithBody([]byte("ok")).Build()); err != nil {
		t.Fatal(err)
	}
	return app.Handler()
}

func get(h http.Handler, path string, credentials ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if len(credentials) == 2 {
		r.SetBasicAuth(credentials[0], credentials[1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestSignIn(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("bcrypt-pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	h := site(t, basicauth.Options{Realm: "Staging", Users: map[string]string{
		"plain":   "open sesame",
		"hashed":  sha("hashed-pw"),
		"crypted": string(hash),
		"literal": "plain:sha256:not-a-hash",
	}}, nil)

	refused := get(h, "/")
	if refused.Code != http.StatusUnauthorized || refused.Header().Get("WWW-Authenticate") != `Basic realm="Staging", charset="UTF-8"` {
		t.Fatalf("no credentials: %d %v", refused.Code, refused.Header())
	}
	if strings.Contains(refused.Body.String(), "secret") || refused.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("the refusal leaks or is cacheable: %q %v", refused.Body.String(), refused.Header())
	}

	for _, c := range [][2]string{{"plain", "open sesame"}, {"hashed", "hashed-pw"}, {"crypted", "bcrypt-pw"}, {"crypted", "bcrypt-pw"}, {"literal", "sha256:not-a-hash"}} {
		if rec := get(h, "/", c[0], c[1]); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "secret") {
			t.Errorf("%s: %d", c[0], rec.Code)
		}
	}
	for _, c := range [][2]string{{"plain", "wrong"}, {"hashed", sha("hashed-pw")}, {"crypted", "wrong"}, {"nobody", "open sesame"}, {"", ""}} {
		if rec := get(h, "/", c[0], c[1]); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s/%s: %d, want 401", c[0], c[1], rec.Code)
		}
	}
}

// collage marks a cached page public, which would let a CDN keep it for anyone.
// Once signed in, it is private and varies by Authorization.
func TestResponsesArePrivate(t *testing.T) {
	h := site(t, basicauth.Options{Users: map[string]string{"team": "pw"}}, nil)
	rec := get(h, "/", "team", "pw")
	if got := rec.Header().Get("Cache-Control"); got != "private, max-age=0, must-revalidate" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Authorization") {
		t.Errorf("Vary = %q", got)
	}
	// The server's own cache now holds the page, and still nobody gets it
	// without signing in.
	if rec := get(h, "/"); rec.Code != http.StatusUnauthorized {
		t.Errorf("a cached page was served without a sign-in: %d", rec.Code)
	}
}

func TestSkipAndProtect(t *testing.T) {
	h := site(t, basicauth.Options{Users: map[string]string{"team": "pw"}}, nil)
	if rec := get(h, "/healthz"); rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("health check: %d %q", rec.Code, rec.Body.String())
	}
	for _, path := range []string{"/healthz-report", "/_collage/../admin", "//admin"} {
		if rec := get(h, path); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", path, rec.Code)
		}
	}

	h = site(t, basicauth.Options{Users: map[string]string{"team": "pw"}, Protect: []string{"/admin"}}, nil)
	if rec := get(h, "/"); rec.Code != http.StatusOK {
		t.Errorf("an unprotected page: %d", rec.Code)
	}
	if rec := get(h, "/admin"); rec.Code != http.StatusUnauthorized {
		t.Errorf("a protected page: %d", rec.Code)
	}
}

func TestDisabled(t *testing.T) {
	if rec := get(site(t, basicauth.Options{Disabled: true}, nil), "/"); rec.Code != http.StatusOK {
		t.Errorf("disabled in options: %d", rec.Code)
	}
	t.Setenv(basicauth.EnvDisabled, "true")
	if rec := get(site(t, basicauth.Options{Users: map[string]string{"team": "pw"}}, nil), "/"); rec.Code != http.StatusOK {
		t.Errorf("disabled by the environment: %d", rec.Code)
	}
	t.Setenv(basicauth.EnvDisabled, "perhaps")
	if rec := get(site(t, basicauth.Options{Users: map[string]string{"team": "pw"}}, nil), "/"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("an unreadable switch: %d, want 503", rec.Code)
	}
}

func TestEnvironmentAndConfiguration(t *testing.T) {
	t.Setenv(basicauth.EnvUsers, "ops:"+sha("ops-pw")+", dev:dev-pw")
	h := site(t, basicauth.Options{}, map[string]json.RawMessage{
		basicauth.Name: json.RawMessage(`{"users": {"cfg": "cfg-pw"}, "realm": "Preview"}`),
	})
	for _, c := range [][2]string{{"ops", "ops-pw"}, {"dev", "dev-pw"}, {"cfg", "cfg-pw"}} {
		if rec := get(h, "/", c[0], c[1]); rec.Code != http.StatusOK {
			t.Errorf("%s: %d", c[0], rec.Code)
		}
	}
	if got := get(h, "/").Header().Get("WWW-Authenticate"); !strings.Contains(got, `realm="Preview"`) {
		t.Errorf("WWW-Authenticate = %q", got)
	}
}

// A misconfigured plugin stops the application from starting.
func TestMisconfiguration(t *testing.T) {
	for name, opts := range map[string]basicauth.Options{
		"no users":        {},
		"empty password":  {Users: map[string]string{"team": ""}},
		"colon in a name": {Users: map[string]string{"a:b": "pw"}},
		"short sha256":    {Users: map[string]string{"team": "sha256:abcd"}},
		"broken bcrypt":   {Users: map[string]string{"team": "$2a$10$nope"}},
		"quoted realm":    {Users: map[string]string{"team": "pw"}, Realm: `say "hi"`},
		"relative skip":   {Users: map[string]string{"team": "pw"}, Skip: []string{"healthz"}},
	} {
		t.Run(name, func(t *testing.T) {
			if rec := get(site(t, opts, nil), "/"); rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status %d, want 503", rec.Code)
			}
		})
	}
}
