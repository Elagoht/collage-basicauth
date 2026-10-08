package basicauth_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"

	basicauth "github.com/Elagoht/collage-basicauth"
	"github.com/Elagoht/collage/pkg/collage"
)

var _ collage.BuildFinishedHook = (*basicauth.Plugin)(nil)

// buildReader reads a finished build, as elagoht/deploy does; with one
// registered, the build asks the handler for every file to capture its headers.
type buildReader struct{ files []collage.BuiltFile }

func (*buildReader) Name() string                             { return "test/buildreader" }
func (*buildReader) Version() string                          { return "0" }
func (*buildReader) Init(context.Context, collage.Host) error { return nil }
func (*buildReader) Shutdown(context.Context) error           { return nil }
func (b *buildReader) OnBuildFinished(_ context.Context, ev *collage.BuildFinishedEvent) error {
	b.files = ev.Files
	return nil
}

// build builds a site with pages at paths behind opts, and returns the files
// the build wrote and its findings.
func build(t *testing.T, opts basicauth.Options, paths ...string) ([]collage.BuiltFile, []collage.Finding) {
	t.Helper()
	reader := &buildReader{}
	app, err := collage.New(&collage.Config{
		Server: collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: fstest.MapFS{
			"t/p.html": {Data: []byte(`<main>secret</main>`)},
		}, Root: "t"},
		Plugins: []collage.Plugin{basicauth.New(opts), reader},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, path := range paths {
		page := collage.NewPage("p"+string(rune('a'+i))).WithContent(collage.NewFragment("p", "p.html").Build()).WithPath("en", path).Static().Build()
		if err := app.RegisterPage(page); err != nil {
			t.Fatal(err)
		}
	}
	builder, err := collage.NewBuilder(app, collage.BuildOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	report, err := builder.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return reader.files, report.Findings
}

func exported(findings []collage.Finding) []collage.Finding {
	var out []collage.Finding
	for _, f := range findings {
		if f.Rule == "basicauth-exported" {
			out = append(out, f)
		}
	}
	return out
}

// A static build's header capture is let through: the deployed file carries
// the page's own headers, not a 401's, nor the private ones a signed-in reader
// is sent.
func TestBuildCaptureIsLetThrough(t *testing.T) {
	files, _ := build(t, basicauth.Options{Users: map[string]string{"team": "secret"}, Protect: []string{"/admin"}}, "/", "/admin")
	captured := 0
	for _, f := range files {
		if !f.Captured {
			continue
		}
		captured++
		if f.Status != http.StatusOK {
			t.Errorf("%s: status %d, want 200", f.Path, f.Status)
		}
		if v := f.Headers.Get("WWW-Authenticate"); v != "" {
			t.Errorf("%s: WWW-Authenticate %q captured", f.Path, v)
		}
		if cc := f.Headers.Get("Cache-Control"); strings.Contains(cc, "private") || strings.Contains(cc, "no-store") {
			t.Errorf("%s: Cache-Control %q captured", f.Path, cc)
		}
		for _, v := range f.Headers.Values("Vary") {
			if strings.Contains(v, "Authorization") {
				t.Errorf("%s: Vary %q captured", f.Path, v)
			}
		}
	}
	if captured < 2 {
		t.Fatalf("%d pages captured, want 2", captured)
	}
}

// A build that writes a protected page warns once, naming it: a static host
// serves it to anyone.
func TestBuildWarnsOfProtectedFiles(t *testing.T) {
	_, findings := build(t, basicauth.Options{Users: map[string]string{"team": "secret"}, Protect: []string{"/admin"}}, "/", "/admin", "/admin/users", "/administrator")
	got := exported(findings)
	if len(got) != 1 {
		t.Fatalf("basicauth-exported findings %+v, want one", findings)
	}
	f := got[0]
	if f.Level != collage.FindingWarning {
		t.Errorf("level %q, want warning", f.Level)
	}
	if !strings.Contains(f.Message, "2 ") || !strings.Contains(f.Message, "/admin/") || !strings.Contains(f.Message, "/admin/users/") {
		t.Errorf("message %q, want 2 files naming /admin/ and /admin/users/", f.Message)
	}
	if strings.Contains(f.Message, "/administrator") {
		t.Errorf("message %q names /administrator, which is not under /admin", f.Message)
	}
}

// Everything protected, the default, names at most five paths and the count.
func TestBuildWarnsNamesFive(t *testing.T) {
	_, findings := build(t, basicauth.Options{Users: map[string]string{"team": "secret"}}, "/", "/a", "/b", "/c", "/d", "/e", "/f")
	got := exported(findings)
	if len(got) != 1 {
		t.Fatalf("basicauth-exported findings %+v, want one", findings)
	}
	named := 0
	for _, word := range strings.Fields(got[0].Message) {
		if strings.HasPrefix(strings.Trim(word, "(),"), "/") {
			named++
		}
	}
	if named != 5 {
		t.Errorf("message %q names %d paths, want 5", got[0].Message, named)
	}
	if !strings.Contains(got[0].Message, "…") && !strings.Contains(got[0].Message, "more") {
		t.Errorf("message %q does not say more files were left unnamed", got[0].Message)
	}
}

// A site whose built files are none of them protected, or whose plugin is
// disabled, is not warned.
func TestBuildNoWarning(t *testing.T) {
	_, findings := build(t, basicauth.Options{Users: map[string]string{"team": "secret"}, Protect: []string{"/admin"}}, "/", "/blog")
	if got := exported(findings); len(got) != 0 {
		t.Errorf("unprotected site: %+v", got)
	}
	_, findings = build(t, basicauth.Options{Disabled: true}, "/", "/admin")
	if got := exported(findings); len(got) != 0 {
		t.Errorf("disabled plugin: %+v", got)
	}
}
