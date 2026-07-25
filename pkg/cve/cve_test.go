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
		{"github->go", Package{Name: "x", URL: "https://github.com/cli/cli.git"}, []osvCoord{{"Go", "github.com/cli/cli"}}},
		{"versioned name strips @", Package{Name: "openssl@3"}, nil}, // no confident coord -> NVD handles it
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
			"id":"CVE-2021-0001","summary":"bad thing",
			"severity":[{"type":"CVSS_V3","score":"9.8"}],
			"affected":[{"ranges":[{"events":[{"fixed":"13.0.1"}]}]}],
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
}

// ---- NVD source ----

func TestNVDBuildsVersionedCPEAndParses(t *testing.T) {
	var gotCPE, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCPE = r.URL.Query().Get("virtualMatchString")
		gotKey = r.Header.Get("apiKey")
		w.Write([]byte(`{"vulnerabilities":[{"cve":{
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
	// product from @-stripped name, version from _-stripped version.
	if gotCPE != "cpe:2.3:a:*:openssl:3.0.0:*:*:*:*:*:*:*" {
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
		{"", "", []string{"osv"}},               // default auto, no key
		{"auto", "", []string{"osv"}},            // auto, no key
		{"auto", "k", []string{"osv", "nvd"}},    // auto, key present
		{"osv", "k", []string{"osv"}},            // forced osv
		{"nvd", "k", []string{"nvd"}},            // forced nvd
		{"both", "", []string{"osv", "nvd"}},     // both regardless of key
		{"AUTO", "k", []string{"osv", "nvd"}},    // case-insensitive
	}
	for _, tc := range cases {
		got := NewMatcher(Config{Source: tc.src, NVDAPIKey: tc.key}).Sources()
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("src=%q key=%q: got %v, want %v", tc.src, tc.key, got, tc.want)
		}
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
		stubSource{name: "b", vulns: []Vuln{dup}},                     // duplicate -> collapsed
		stubSource{name: "c", err: context.DeadlineExceeded},          // error -> surfaced, not silent
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
