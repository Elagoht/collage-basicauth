package basicauth_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	basicauth "github.com/Elagoht/collage-basicauth"
	"github.com/Elagoht/collage/pkg/collage"
	"github.com/Elagoht/collage/pkg/collagetest"
	"golang.org/x/crypto/bcrypt"
)

// siteOptions build a site with pages at /, /admin and /healthz-report, and
// documents at /healthz and /readyz, behind basicauth.New(opts) with config as
// its plugin configuration when it is not empty.
func siteOptions(opts basicauth.Options, config string) []collagetest.SiteOption {
	items := []collage.Registrable{
		collage.NewDocument("health", "text/plain").AtRoot("/healthz").WithBody([]byte("ok")).Build(),
		collage.NewDocument("ready", "text/plain").AtRoot("/readyz").WithBody([]byte("ready")).Build(),
	}
	for name, path := range map[string]string{"home": "/", "admin": "/admin", "report": "/healthz-report"} {
		// Static, so collage marks it public and caches it.
		items = append(items, collage.NewPage(name).WithContent(collage.NewFragment(name, "p.html").Build()).WithPath("en", path).Static().Build())
	}
	options := []collagetest.SiteOption{
		collagetest.WithoutHome(),
		collagetest.WithTemplates(map[string]string{"p.html": `<main>secret</main>`}),
		collagetest.WithConfig(func(c *collage.Config) {
			c.Cache = collage.CacheConfig{Enabled: true, Type: "memory", DefaultTTL: time.Hour}
		}),
		collagetest.WithRegister(items...),
		collagetest.WithPlugins(basicauth.New(opts)),
	}
	if config != "" {
		options = append(options, collagetest.WithPluginConfig(basicauth.Name, config))
	}
	return options
}

func site(t *testing.T, opts basicauth.Options, config string) http.Handler {
	t.Helper()
	return collagetest.NewSite(t, siteOptions(opts, config)...).App.Handler()
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
	}}, "")

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
	h := site(t, basicauth.Options{Users: map[string]string{"team": "pw"}}, "")
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
	h := site(t, basicauth.Options{Users: map[string]string{"team": "pw"}}, "")
	if rec := get(h, "/healthz"); rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("health check: %d %q", rec.Code, rec.Body.String())
	}
	if rec := get(h, "/readyz"); rec.Code != http.StatusOK || rec.Body.String() != "ready" {
		t.Errorf("readiness check: %d %q", rec.Code, rec.Body.String())
	}
	for _, path := range []string{"/healthz-report", "/admin"} {
		if rec := get(h, path); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", path, rec.Code)
		}
	}
	// collage redirects a path with dot segments or doubled slashes to its
	// clean spelling before any middleware runs, so neither reaches the skip
	// list; the plugin's own refusal to skip one stays behind that.
	for _, path := range []string{"/_collage/../admin", "//admin"} {
		if rec := get(h, path); rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/admin" {
			t.Errorf("%s: %d %q, want collage's redirect to /admin", path, rec.Code, rec.Header().Get("Location"))
		}
	}

	h = site(t, basicauth.Options{Users: map[string]string{"team": "pw"}, Protect: []string{"/admin"}}, "")
	if rec := get(h, "/"); rec.Code != http.StatusOK {
		t.Errorf("an unprotected page: %d", rec.Code)
	}
	if rec := get(h, "/admin"); rec.Code != http.StatusUnauthorized {
		t.Errorf("a protected page: %d", rec.Code)
	}
}

func TestDisabled(t *testing.T) {
	if rec := get(site(t, basicauth.Options{Disabled: true}, ""), "/"); rec.Code != http.StatusOK {
		t.Errorf("disabled in options: %d", rec.Code)
	}
	t.Setenv(basicauth.EnvDisabled, "true")
	if rec := get(site(t, basicauth.Options{Users: map[string]string{"team": "pw"}}, ""), "/"); rec.Code != http.StatusOK {
		t.Errorf("disabled by the environment: %d", rec.Code)
	}
	t.Setenv(basicauth.EnvDisabled, "perhaps")
	if _, err := collagetest.TrySite(t, siteOptions(basicauth.Options{Users: map[string]string{"team": "pw"}}, "")...); err == nil {
		t.Error("an unreadable switch: the application started")
	}
}

func TestEnvironmentAndConfiguration(t *testing.T) {
	t.Setenv(basicauth.EnvUsers, "ops:"+sha("ops-pw")+", dev:dev-pw")
	h := site(t, basicauth.Options{}, `{"users": {"cfg": "cfg-pw"}, "realm": "Preview"}`)
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
			if _, err := collagetest.TrySite(t, siteOptions(opts, "")...); err == nil {
				t.Error("the application started")
			}
		})
	}
}

// With bcrypt and sha256 users mixed, a wrong password for a sha256 or plain
// user takes as long as an unknown name's refusal, which pays a bcrypt: a
// microsecond refusal would name the cheap users. bcrypt at cost 8 takes
// milliseconds against a sha256's microseconds, so the comparison is between
// orders of magnitude, not noise.
func TestRefusalTimeHidesSchemes(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("bcrypt-pw"), 8)
	if err != nil {
		t.Fatal(err)
	}
	h := site(t, basicauth.Options{Users: map[string]string{
		"crypted": string(hash), "hashed": sha("hashed-pw"), "plain": "open sesame",
	}}, "")
	fastest := func(name string) time.Duration {
		best := time.Duration(1 << 62)
		for range 5 {
			start := time.Now()
			if w := get(h, "/", name, "wrong"); w.Code != http.StatusUnauthorized {
				t.Fatalf("%s: %d, want 401", name, w.Code)
			}
			best = min(best, time.Since(start))
		}
		return best
	}
	unknown := fastest("nobody")
	for _, name := range []string{"hashed", "plain"} {
		if d := fastest(name); d < unknown/4 {
			t.Errorf("%s refused in %v, an unknown name in %v: the timing names the user", name, d, unknown)
		}
	}
}
