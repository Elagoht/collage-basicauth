// Package basicauth is a collage plugin that puts HTTP Basic authentication in
// front of a site: a staging deployment, a preview, a site not launched yet.
//
//	app, err := collage.New(&collage.Config{
//		Plugins: []collage.Plugin{basicauth.New(basicauth.Options{
//			Users: map[string]string{"team": "sha256:9f86d081884c7d65…"},
//		})},
//	})
//
// A password is given in plain text, as "sha256:" and the hex of its SHA-256, or
// as a bcrypt hash. Production turns the plugin off from its own configuration,
// or with COLLAGE_BASICAUTH_DISABLED=true, so one binary is open there and closed
// elsewhere.
//
// collage marks a cached page "public", which is what lets a CDN keep it — and a
// shared cache may store a response to a request carrying Authorization when the
// response says public. So every authenticated response is turned private on
// the way out, and sent with Vary: Authorization, and a CDN in front of the
// staging site cannot hand a protected page to someone who never signed in.
package basicauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/Elagoht/collage/pkg/collage"
	"golang.org/x/crypto/bcrypt"
)

// Name is the plugin's name, and the key its configuration is found under.
const Name = "elagoht/basicauth"

// The environment variables the plugin reads, for a deployment that keeps its
// secrets out of files.
const (
	// EnvUsers adds users: "name:password,name:sha256:…". A password in it cannot
	// contain a comma; give such a password as a hash.
	EnvUsers = "COLLAGE_BASICAUTH_USERS"
	// EnvDisabled turns the plugin off when it is "true" or "1".
	EnvDisabled = "COLLAGE_BASICAUTH_DISABLED"
)

// Options configures the plugin.
type Options struct {
	// Users maps a name to a password: in plain text, as "sha256:" and the hex
	// of its SHA-256, or as a bcrypt hash ("$2a$…", "$2b$…", "$2y$…"). A plain
	// password that happens to begin with one of those is written "plain:…".
	// Users from EnvUsers are added to these, and win on a name in both.
	Users map[string]string `json:"users"`
	// Realm is what the browser's sign-in dialog names. Default "Restricted".
	Realm string `json:"realm"`
	// Protect are the path prefixes that need a sign-in. Default ["/"],
	// everything.
	Protect []string `json:"protect"`
	// Skip are path prefixes that never do, even under Protect. Default
	// ["/healthz", "/_collage/"]: a load balancer's health check has no
	// password, and neither does collage's development reload stream.
	Skip []string `json:"skip"`
	// Disabled turns the plugin off, as EnvDisabled does. A disabled plugin
	// needs no users.
	Disabled bool `json:"disabled"`
}

var _ collage.Plugin = (*Plugin)(nil)

// Plugin asks for a name and password.
type Plugin struct {
	opts      Options
	users     []user
	hasBcrypt bool
	dummy     []byte // a bcrypt hash an unknown name is checked against
	header    string // WWW-Authenticate

	mu       sync.Mutex
	verified map[[32]byte]struct{} // bcrypt successes, so a signed-in reader is not charged bcrypt on every request
	cacheKey []byte
}

type user struct {
	name   [32]byte // SHA-256 of the name, so every comparison is the same length
	digest []byte   // SHA-256 of a plain password, or the configured one
	bcrypt []byte
}

// New returns a plugin with opts as its starting point, which the application's
// own configuration is then decoded over.
func New(opts Options) *Plugin { return &Plugin{opts: opts} }

func (p *Plugin) Name() string                   { return Name }
func (p *Plugin) Version() string                { return "0.1.4" }
func (p *Plugin) Shutdown(context.Context) error { return nil }

// Init reads and checks the configuration and, unless the plugin is disabled,
// wraps every request.
func (p *Plugin) Init(_ context.Context, host collage.Host) error {
	cfg, err := collage.PluginConfig(host, p.opts)
	if err != nil {
		return err
	}
	p.opts = cfg
	if v, ok := os.LookupEnv(EnvDisabled); ok && v != "" {
		disabled, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("basicauth: %s=%q is not true or false", EnvDisabled, v)
		}
		p.opts.Disabled = p.opts.Disabled || disabled
	}
	if p.opts.Disabled {
		host.Logger().Info("basicauth: disabled, so the site is open to everyone")
		return nil
	}
	if err := p.prepare(); err != nil {
		return err
	}
	return host.Use(p.middleware)
}

func (p *Plugin) prepare() error {
	o := &p.opts
	users := map[string]string{}
	for name, password := range o.Users {
		users[name] = password
	}
	if env := os.Getenv(EnvUsers); env != "" {
		for _, entry := range strings.Split(env, ",") {
			name, password, ok := strings.Cut(strings.TrimSpace(entry), ":")
			if !ok {
				return fmt.Errorf("basicauth: %s: an entry is not name:password", EnvUsers)
			}
			users[name] = password
		}
	}
	if len(users) == 0 {
		return errors.New("basicauth: no users, so nobody could sign in; add some, or disable the plugin")
	}
	var bcryptCost int
	for name, password := range users {
		if name == "" || strings.Contains(name, ":") {
			return fmt.Errorf("basicauth: user %q: a name cannot be empty or contain a colon", name)
		}
		if password == "" {
			return fmt.Errorf("basicauth: user %q has no password", name)
		}
		u := user{name: sha256.Sum256([]byte(name))}
		switch {
		case strings.HasPrefix(password, "plain:"):
			sum := sha256.Sum256([]byte(strings.TrimPrefix(password, "plain:")))
			u.digest = sum[:]
		case strings.HasPrefix(password, "sha256:"):
			digest, err := hex.DecodeString(strings.TrimPrefix(password, "sha256:"))
			if err != nil || len(digest) != sha256.Size {
				return fmt.Errorf("basicauth: user %q: a sha256 password is 64 hex digits", name)
			}
			u.digest = digest
		case strings.HasPrefix(password, "$2a$"), strings.HasPrefix(password, "$2b$"), strings.HasPrefix(password, "$2y$"):
			cost, err := bcrypt.Cost([]byte(password))
			if err != nil {
				return fmt.Errorf("basicauth: user %q: %w", name, err)
			}
			u.bcrypt = []byte(password)
			bcryptCost = max(bcryptCost, cost)
		default:
			sum := sha256.Sum256([]byte(password))
			u.digest = sum[:]
		}
		p.users = append(p.users, u)
	}
	if bcryptCost > 0 {
		// An unknown name is checked against a hash of the same cost, so the
		// time a refusal takes does not say whether the name exists.
		var random [16]byte
		_, _ = rand.Read(random[:])
		dummy, err := bcrypt.GenerateFromPassword(random[:], bcryptCost)
		if err != nil {
			return fmt.Errorf("basicauth: %w", err)
		}
		p.dummy = dummy
		p.hasBcrypt = true
		p.cacheKey = make([]byte, 32)
		_, _ = rand.Read(p.cacheKey)
		p.verified = map[[32]byte]struct{}{}
	}

	if o.Realm == "" {
		o.Realm = "Restricted"
	}
	if strings.ContainsAny(o.Realm, "\"\\") || strings.ContainsFunc(o.Realm, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("basicauth: realm %q cannot contain quotes, backslashes or control characters", o.Realm)
	}
	p.header = `Basic realm="` + o.Realm + `", charset="UTF-8"`
	if o.Protect == nil {
		o.Protect = []string{"/"}
	}
	if o.Skip == nil {
		o.Skip = []string{"/healthz", "/_collage/"}
	}
	for _, prefix := range append(append([]string(nil), o.Protect...), o.Skip...) {
		if !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("basicauth: path prefix %q must begin with /", prefix)
		}
	}
	return nil
}

func (p *Plugin) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.protects(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		name, password, ok := r.BasicAuth()
		if !ok || !p.check(name, password) {
			h := w.Header()
			h.Set("WWW-Authenticate", p.header)
			h.Set("Content-Type", "text/plain; charset=utf-8")
			h.Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Sign in to see this site.\n"))
			return
		}
		pw := &privateWriter{ResponseWriter: w}
		next.ServeHTTP(pw, r)
		pw.commit()
	})
}

// protects reports whether urlPath needs a sign-in.
//
// A path with dot segments or doubled slashes is never skipped, so
// /_collage/../admin is never treated as a development endpoint. collage v0.24.0
// redirects such a path before any middleware runs; this stays as a second line,
// for a handler that does not.
func (p *Plugin) protects(urlPath string) bool {
	clean := cleanPath(urlPath)
	if clean != urlPath {
		return true
	}
	for _, prefix := range p.opts.Skip {
		if under(clean, prefix) {
			return false
		}
	}
	for _, prefix := range p.opts.Protect {
		if under(clean, prefix) {
			return true
		}
	}
	return false
}

// under reports whether urlPath is prefix or below it, by whole segments:
// "/healthz" covers "/healthz" and "/healthz/db", not "/healthz-report".
func under(urlPath, prefix string) bool {
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(urlPath, prefix) || urlPath+"/" == prefix
	}
	return urlPath == prefix || strings.HasPrefix(urlPath, prefix+"/")
}

func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

// check reports whether name and password belong to a user. Every user's name is
// compared, without stopping at a match, and an unknown name is checked against a
// password nobody has: how long a refusal takes says nothing about which names
// exist.
func (p *Plugin) check(name, password string) bool {
	nameSum := sha256.Sum256([]byte(name))
	var match *user
	for i := range p.users {
		if subtle.ConstantTimeCompare(p.users[i].name[:], nameSum[:]) == 1 {
			match = &p.users[i]
		}
	}
	if match == nil {
		if p.hasBcrypt {
			_ = bcrypt.CompareHashAndPassword(p.dummy, []byte(password))
		} else {
			sum := sha256.Sum256([]byte(password))
			subtle.ConstantTimeCompare(sum[:], make([]byte, sha256.Size))
		}
		return false
	}
	if match.bcrypt == nil {
		sum := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(sum[:], match.digest) == 1
	}
	mac := hmac.New(sha256.New, p.cacheKey)
	mac.Write([]byte(name))
	mac.Write([]byte{0})
	mac.Write([]byte(password))
	var key [32]byte
	copy(key[:], mac.Sum(nil))
	p.mu.Lock()
	_, seen := p.verified[key]
	p.mu.Unlock()
	if seen {
		return true
	}
	if bcrypt.CompareHashAndPassword(match.bcrypt, []byte(password)) != nil {
		return false
	}
	p.mu.Lock()
	if len(p.verified) >= 1024 {
		clear(p.verified)
	}
	p.verified[key] = struct{}{}
	p.mu.Unlock()
	return true
}

// privateWriter makes an authenticated response one no shared cache keeps, just
// before its headers go out.
type privateWriter struct {
	http.ResponseWriter
	committed bool
}

func (w *privateWriter) commit() {
	if w.committed {
		return
	}
	w.committed = true
	h := w.Header()
	h.Set("Cache-Control", private(h.Get("Cache-Control")))
	for _, v := range h.Values("Vary") {
		for _, name := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(name), "Authorization") || strings.TrimSpace(name) == "*" {
				return
			}
		}
	}
	h.Add("Vary", "Authorization")
}

// private turns a Cache-Control value into one for a single reader: public and
// s-maxage go, private is added, and what the browser may do is left alone.
func private(value string) string {
	out := []string{"private"}
	for _, directive := range strings.Split(value, ",") {
		d := strings.TrimSpace(directive)
		lower := strings.ToLower(d)
		switch {
		case d == "", lower == "public", lower == "private", strings.HasPrefix(lower, "s-maxage"):
			continue
		case lower == "no-store":
			return value
		}
		out = append(out, d)
	}
	return strings.Join(out, ", ")
}

func (w *privateWriter) WriteHeader(status int) {
	w.commit()
	w.ResponseWriter.WriteHeader(status)
}

func (w *privateWriter) Write(b []byte) (int, error) {
	w.commit()
	return w.ResponseWriter.Write(b)
}

// Flush passes a flush through.
func (w *privateWriter) Flush() {
	w.commit()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the connection: a stream's write
// deadline, a WebSocket's hijack.
func (w *privateWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
