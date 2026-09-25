package cve

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

// ---- ecosystem mapping ----

func TestOSVCoordinates(t *testing.T) {
	cases := []struct {
		name string
		pkg  Package
		want []osvCoord
	}{
		{"curated crates", Package{Name: "ripgrep"}, []osvCoord{{"crates.io", "ripgrep"}}},
		{"curated pypi", Package{Name: "awscli"}, []osvCoord{{"PyPI", "awscli"}}},
		{"pypi url", Package{Name: "x", URL: "https://pypi.org/project/requests/"}, []osvCoord{{"PyPI", "requests"}}},
		{"crates url", Package{Name: "x", URL: "https://crates.io/crates/tokio"}, []osvCoord{{"crates.io", "tokio"}}},
		{"pypi source url uses name not letter", Package{Name: "x", URL: "https://files.pythonhosted.org/packages/source/r/requests/requests-2.28.0.tar.gz"}, []osvCoord{{"PyPI", "requests"}}},
		{"notpypi.org is not pypi", Package{Name: "x", URL: "https://notpypi.org/project/requests/"}, nil},
		{"github tarball is not a go module", Package{Name: "curl", URL: "https://github.com/curl/curl/archive/refs/tags/curl-8.7.1.tar.gz"}, nil},
		{"pkg.go.dev", Package{Name: "x", URL: "https://pkg.go.dev/github.com/cli/cli"}, []osvCoord{{"Go", "github.com/cli/cli"}}},
		{"curated go tool", Package{Name: "gh"}, []osvCoord{{"Go", "github.com/cli/cli"}}},
		{"versioned name strips @", Package{Name: "openssl@3"}, nil}, // no OSV coord; NVD curated CPE covers it
		{"unmapped", Package{Name: "curl"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := osvCoordinates(tc.pkg)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	cases := map[string]string{
		"1.2.3_1":    "1.2.3", // brew revision stripped
		"1.2.3":      "1.2.3",
		"3.0.11_2":   "3.0.11",
		"1.2.3_beta": "1.2.3_beta", // non-numeric suffix preserved
		"_1":         "_1",
	}
	for in, want := range cases {
		if got := normalizeVersion(in); got != want {
			t.Errorf("normalizeVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- OSV source ----

func TestOSVInjectionSafePayload(t *testing.T) {
	var gotName string
	var validJSON bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// The raw body must be valid JSON — proves no string-injection breakage.
		var generic map[string]any
		validJSON = json.Unmarshal(body, &generic) == nil
		var req osvRequest
		_ = json.Unmarshal(body, &req)
		gotName = req.Package.Name
		w.Write([]byte(`{"vulns":[]}`))
	}))
	defer srv.Close()

	// A crates URL whose name contains a double-quote and backslash.
	src := &OSVSource{Client: srv.Client(), Endpoint: srv.URL}
	_, err := src.Query(ctx(t), Package{Name: "x", Version: "1.0", URL: `https://crates.io/crates/e"vil\name`})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !validJSON {
		t.Fatal("server received malformed JSON — payload was string-injected")
	}
	if gotName != `e"vil\name` {
		t.Fatalf("name not round-tripped safely: %q", gotName)
	}
}

func TestOSVStatusErrorFailsLoud(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	src := &OSVSource{Client: srv.Client(), Endpoint: srv.URL}
	_, err := src.Query(ctx(t), Package{Name: "ripgrep", Version: "13.0.0"})
	if err == nil {
		t.Fatal("expected error on HTTP 500, got nil (silent-clean is the bug we fixed)")
	}
}

func TestOSVDecodeErrorFailsLoud(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not json`))
	}))
	defer srv.Close()
	src := &OSVSource{Client: srv.Client(), Endpoint: srv.URL}
	_, err := src.Query(ctx(t), Package{Name: "ripgrep", Version: "13.0.0"})
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
}

func TestOSVMapsVulns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulns":[{
			"id":"GHSA-xxxx","aliases":["CVE-2021-0001"],"summary":"bad thing",
			"severity":[{"type":"CVSS_V3","score":"9.8"}],
			"affected":[{"package":{"ecosystem":"crates.io","name":"ripgrep"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"13.0.1"}]}]}],
			"references":[{"type":"WEB","url":"https://x"},{"type":"ADVISORY","url":"https://adv"}]
		}]}`))
	}))
	defer srv.Close()
	src := &OSVSource{Client: srv.Client(), Endpoint: srv.URL}
	vulns, err := src.Query(ctx(t), Package{Name: "ripgrep", Version: "13.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 {
		t.Fatalf("want 1 vuln, got %d", len(vulns))
	}
	v := vulns[0]
	if v.ID != "CVE-2021-0001" || v.Severity != SeverityCritical || v.FixedIn != "13.0.1" ||
		v.Reference != "https://adv" || v.Source != "osv" || v.Package != "ripgrep" {
		t.Fatalf("bad mapping: %+v", v)
	}
	if len(v.Aliases) != 1 || v.Aliases[0] != "GHSA-xxxx" {
		t.Fatalf("aliases = %v", v.Aliases)
	}
}

// ---- NVD source ----

func TestNVDBuildsVersionedCPEAndParses(t *testing.T) {
	var gotCPE, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCPE = r.URL.Query().Get("virtualMatchString")
		gotKey = r.Header.Get("apiKey")
		w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{
			"id":"CVE-2022-1234",
			"descriptions":[{"lang":"en","value":"heap overflow"}],
			"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"baseSeverity":"HIGH"}}]},
			"references":[{"url":"https://nvd/CVE-2022-1234"}]
		}}]}`))
	}))
	defer srv.Close()
	src := &NVDSource{Client: srv.Client(), Endpoint: srv.URL, APIKey: "secret-key", MinInterval: 0}
	vulns, err := src.Query(ctx(t), Package{Name: "openssl@3", Version: "3.0.0_1"})
	if err != nil {
		t.Fatal(err)
	}
	// curated vendor/product, @-stripped name, _-stripped version.
	if gotCPE != "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*" {
		t.Fatalf("bad CPE match string: %q", gotCPE)
	}
	if gotKey != "secret-key" {
		t.Fatalf("apiKey header not sent: %q", gotKey)
	}
	if len(vulns) != 1 || vulns[0].ID != "CVE-2022-1234" || vulns[0].Severity != SeverityHigh || vulns[0].Source != "nvd" {
		t.Fatalf("bad NVD mapping: %+v", vulns)
	}
}

func TestNVDStatusErrorFailsLoud(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	defer srv.Close()
	src := &NVDSource{Client: srv.Client(), Endpoint: srv.URL, MinInterval: 0}
	_, err := src.Query(ctx(t), Package{Name: "openssl", Version: "3.0.0"})
	if err == nil {
		t.Fatal("expected error on HTTP 403, got nil")
	}
}

// ---- matcher ----

func TestMatcherSourceSelection(t *testing.T) {
	cases := []struct {
		src  string
		key  string
		want []string
	}{
		{"", "", []string{"osv"}},             // default auto, no key
		{"auto", "", []string{"osv"}},         // auto, no key
		{"auto", "k", []string{"osv", "nvd"}}, // auto, key present
		{"osv", "k", []string{"osv"}},         // forced osv
		{"nvd", "k", []string{"nvd"}},         // forced nvd
		{"both", "", []string{"osv", "nvd"}},  // both regardless of key
		{"AUTO", "k", []string{"osv", "nvd"}}, // case-insensitive
	}
	for _, tc := range cases {
		m, err := NewMatcher(Config{Source: tc.src, NVDAPIKey: tc.key})
		if err != nil {
			t.Fatalf("src=%q: %v", tc.src, err)
		}
		got := m.Sources()
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("src=%q key=%q: got %v, want %v", tc.src, tc.key, got, tc.want)
		}
	}
}

func TestMatcherRejectsUnknownSource(t *testing.T) {
	if _, err := NewMatcher(Config{Source: "ossv"}); err == nil {
		t.Fatal("unknown source was treated as a real backend")
	}
}

type stubSource struct {
	name  string
	vulns []Vuln
	err   error
}

func (s stubSource) Name() string { return s.name }
func (s stubSource) Query(context.Context, Package) ([]Vuln, error) {
	return s.vulns, s.err
}

func TestScanPackageDedupeAndErrors(t *testing.T) {
	dup := Vuln{ID: "CVE-1", Package: "curl"}
	m := &Matcher{sources: []Source{
		stubSource{name: "a", vulns: []Vuln{dup, {ID: "CVE-2", Package: "curl"}}},
		stubSource{name: "b", vulns: []Vuln{dup}},            // duplicate -> collapsed
		stubSource{name: "c", err: context.DeadlineExceeded}, // error -> surfaced, not silent
	}}
	res := m.ScanPackage(ctx(t), Package{Name: "curl"})
	if len(res.Vulns) != 2 {
		t.Fatalf("want 2 deduped vulns, got %d: %+v", len(res.Vulns), res.Vulns)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("want 1 surfaced error, got %d", len(res.Errors))
	}
	if !strings.Contains(res.Errors[0].Error(), "c:") {
		t.Fatalf("error not attributed to source: %v", res.Errors[0])
	}
}

func TestScanPackageKeepsVulnsWhenSourceErrors(t *testing.T) {
	m := &Matcher{sources: []Source{
		stubSource{name: "a", vulns: []Vuln{{ID: "CVE-1", Package: "curl"}}, err: context.DeadlineExceeded},
	}}
	res := m.ScanPackage(ctx(t), Package{Name: "curl"})
	if len(res.Vulns) != 1 || res.Vulns[0].ID != "CVE-1" {
		t.Fatalf("partial vulns dropped: %+v", res.Vulns)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("error dropped: %+v", res.Errors)
	}
}

func TestOSVKeepsEarlierCoordWhenLaterFails(t *testing.T) {
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.Write([]byte(`{"vulns":[{"id":"CVE-1","summary":"from crates"}]}`))
			return
		}
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	src := &OSVSource{Client: srv.Client(), Endpoint: srv.URL}
	vulns, err := src.Query(ctx(t), Package{
		Name:    "ripgrep",
		Version: "14.0.0",
		URL:     "https://pypi.org/project/requests/",
	})
	if err == nil {
		t.Fatal("expected the second coordinate to fail")
	}
	if len(vulns) != 1 || vulns[0].ID != "CVE-1" {
		t.Fatalf("first coordinate's vuln was dropped: %+v", vulns)
	}
}

func TestOSVEmptyVersionDoesNotQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("empty version must not be sent to OSV")
	}))
	defer srv.Close()
	src := &OSVSource{Client: srv.Client(), Endpoint: srv.URL}
	_, err := src.Query(ctx(t), Package{Name: "ripgrep"})
	if err == nil {
		t.Fatal("expected error for missing version")
	}
}

func TestOSVFixedInSkipsOtherBranch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulns":[{"id":"CVE-9","affected":[{"ranges":[
			{"events":[{"introduced":"0"},{"fixed":"1.2.0"}]},
			{"events":[{"introduced":"2.0.0"},{"fixed":"2.1.0"}]}
		]}]}]}`))
	}))
	defer srv.Close()
	src := &OSVSource{Client: srv.Client(), Endpoint: srv.URL}
	vulns, err := src.Query(ctx(t), Package{Name: "ripgrep", Version: "2.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 || vulns[0].FixedIn != "2.1.0" {
		t.Fatalf("fixed-in = %+v, want 2.1.0", vulns)
	}
}

func TestNVDPaginates(t *testing.T) {
	var starts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := r.URL.Query().Get("startIndex")
		starts = append(starts, start)
		if start == "" || start == "0" {
			w.Write([]byte(`{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-1","descriptions":[{"lang":"en","value":"one"}]}}]}`))
			return
		}
		w.Write([]byte(`{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2","descriptions":[{"lang":"en","value":"two"}]}}]}`))
	}))
	defer srv.Close()
	src := &NVDSource{Client: srv.Client(), Endpoint: srv.URL, MinInterval: 0}
	vulns, err := src.Query(ctx(t), Package{Name: "openssl", Version: "3.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 2 {
		t.Fatalf("got %d vulns, want 2 (pagination dropped a page): %+v starts=%v", len(vulns), vulns, starts)
	}
}

func TestNVDSkipsUnmappedFormula(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("unmapped formula must not be queried")
	}))
	defer srv.Close()
	src := &NVDSource{Client: srv.Client(), Endpoint: srv.URL, MinInterval: 0}
	vulns, err := src.Query(ctx(t), Package{Name: "not-a-real-formula", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 0 {
		t.Fatalf("unexpected vulns: %+v", vulns)
	}
}

func TestNVDRedirectDoesNotLeakAPIKey(t *testing.T) {
	hits := 0
	leak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("apiKey") != "" {
			t.Error("api key followed a redirect")
		}
	}))
	defer leak.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, leak.URL, http.StatusFound)
	}))
	defer srv.Close()
	src := NewNVDSource("secret-key")
	src.Endpoint = srv.URL
	src.MinInterval = 0
	_, err := src.Query(ctx(t), Package{Name: "openssl", Version: "3.0.0"})
	if err == nil {
		t.Fatal("redirect was treated as a successful lookup")
	}
	if hits != 0 {
		t.Fatalf("client followed redirect (%d hits)", hits)
	}
}

func TestNVDRejectsOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-1"}}]}`))
	}))
	defer srv.Close()
	src := &NVDSource{Client: srv.Client(), Endpoint: srv.URL, MinInterval: 0, MaxBytes: 16}
	if _, err := src.Query(ctx(t), Package{Name: "openssl", Version: "3.0.0"}); err == nil {
		t.Fatal("oversized body was accepted")
	}
}

func TestEscapeCPE(t *testing.T) {
	if got := escapeCPE("1.2.3+dfsg"); got != `1.2.3\+dfsg` {
		t.Fatalf("got %q", got)
	}
	if got := escapeCPE("1:2"); got != `1\:2` {
		t.Fatalf("got %q", got)
	}
	if got := escapeCPE("1.2.3"); got != "1.2.3" {
		t.Fatalf("got %q", got)
	}
}

func TestVersionLess(t *testing.T) {
	less, ok := versionLess("1.2.3", "1.10.0")
	if !ok || !less {
		t.Fatalf("1.2.3 < 1.10.0: less=%v ok=%v", less, ok)
	}
	less, ok = versionLess("1.2.3", "1.2.3-rc1")
	if !ok || less {
		t.Fatalf("release should sort after rc: less=%v ok=%v", less, ok)
	}
	if _, ok := versionLess("HEAD", "1.0"); ok {
		t.Fatal("HEAD should not compare as a version")
	}
}
