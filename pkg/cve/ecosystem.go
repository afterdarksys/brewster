package cve

import (
	"net/url"
	"strings"
)

// osvCoord is an (ecosystem, name) pair to query OSV with.
type osvCoord struct {
	Ecosystem string
	Name      string
}

// curatedOSV is the formula-to-ecosystem map. A wrong guess is a bad query,
// so anything not listed here is derived only from a package-host URL.
var curatedOSV = map[string]osvCoord{
	"awscli":     {"PyPI", "awscli"},
	"ansible":    {"PyPI", "ansible"},
	"httpie":     {"PyPI", "httpie"},
	"yt-dlp":     {"PyPI", "yt-dlp"},
	"pipenv":     {"PyPI", "pipenv"},
	"poetry":     {"PyPI", "poetry"},
	"ripgrep":    {"crates.io", "ripgrep"},
	"fd":         {"crates.io", "fd-find"},
	"bat":        {"crates.io", "bat"},
	"eza":        {"crates.io", "eza"},
	"exa":        {"crates.io", "exa"},
	"starship":   {"crates.io", "starship"},
	"deno":       {"crates.io", "deno"},
	"yarn":       {"npm", "yarn"},
	"pnpm":       {"npm", "pnpm"},
	"typescript": {"npm", "typescript"},

	"buf":           {"Go", "github.com/bufbuild/buf"},
	"caddy":         {"Go", "github.com/caddyserver/caddy/v2"},
	"consul":        {"Go", "github.com/hashicorp/consul"},
	"cosign":        {"Go", "github.com/sigstore/cosign/v2"},
	"delve":         {"Go", "github.com/go-delve/delve"},
	"gh":            {"Go", "github.com/cli/cli"},
	"golangci-lint": {"Go", "github.com/golangci/golangci-lint"},
	"helm":          {"Go", "helm.sh/helm/v3"},
	"hugo":          {"Go", "github.com/gohugoio/hugo"},
	"nats-server":   {"Go", "github.com/nats-io/nats-server/v2"},
	"nomad":         {"Go", "github.com/hashicorp/nomad"},
	"prometheus":    {"Go", "github.com/prometheus/prometheus"},
	"rclone":        {"Go", "github.com/rclone/rclone"},
	"syncthing":     {"Go", "github.com/syncthing/syncthing"},
	"terraform":     {"Go", "github.com/hashicorp/terraform"},
	"trivy":         {"Go", "github.com/aquasecurity/trivy"},
	"vault":         {"Go", "github.com/hashicorp/vault"},
}

// normalizeName strips a Homebrew versioned suffix: "openssl@3" -> "openssl".
func normalizeName(name string) string {
	if i := strings.Index(name, "@"); i > 0 {
		return name[:i]
	}
	return name
}

// normalizeVersion strips a Homebrew revision suffix: "1.2.3_1" -> "1.2.3".
// The upstream databases key on the upstream version, not the brew revision.
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.LastIndex(v, "_"); i > 0 && i < len(v)-1 {
		if isAllDigits(v[i+1:]) {
			return v[:i]
		}
	}
	return v
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func osvCoordinates(p Package) []osvCoord {
	base := normalizeName(p.Name)
	var out []osvCoord
	seen := make(map[osvCoord]bool)
	add := func(c osvCoord) {
		c.Name = strings.TrimSpace(c.Name)
		if c.Name == "" || c.Ecosystem == "" || seen[c] {
			return
		}
		seen[c] = true
		out = append(out, c)
	}

	if c, ok := curatedOSV[base]; ok {
		add(c)
	}
	for _, raw := range []string{p.URL, p.Homepage} {
		if c, ok := coordFromURL(raw); ok {
			add(c)
		}
	}
	return out
}

// hostIs matches a domain or its subdomains. "notpypi.org" does not match "pypi.org".
func hostIs(host, domain string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	domain = strings.ToLower(domain)
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func coordFromURL(raw string) (osvCoord, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return osvCoord{}, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return osvCoord{}, false
	}
	host := strings.ToLower(u.Host)
	segs := splitPath(u.Path)

	switch {
	case hostIs(host, "pypi.org") || hostIs(host, "pythonhosted.org"):
		// https://pypi.org/project/<name>/
		if n := afterSegment(segs, "project"); n != "" {
			return osvCoord{"PyPI", n}, true
		}
		// https://files.pythonhosted.org/packages/source/<letter>/<name>/...
		for i, s := range segs {
			if s == "source" && i+2 < len(segs) {
				return osvCoord{"PyPI", segs[i+2]}, true
			}
		}
	case hostIs(host, "npmjs.org") || hostIs(host, "npmjs.com"):
		if len(segs) >= 1 {
			if segs[0] == "package" && len(segs) >= 2 {
				return osvCoord{"npm", segs[1]}, true
			}
			if strings.HasPrefix(segs[0], "@") && len(segs) >= 2 {
				return osvCoord{"npm", segs[0] + "/" + segs[1]}, true
			}
			return osvCoord{"npm", segs[0]}, true
		}
	case hostIs(host, "crates.io"):
		// https://crates.io/crates/<name> or /api/v1/crates/<name>/<ver>/download
		if n := afterSegment(segs, "crates"); n != "" {
			return osvCoord{"crates.io", n}, true
		}
	case hostIs(host, "pkg.go.dev"):
		if len(segs) >= 1 {
			return osvCoord{"Go", strings.Join(segs, "/")}, true
		}
	case hostIs(host, "proxy.golang.org"):
		joined := strings.Join(segs, "/")
		if i := strings.Index(joined, "/@v/"); i > 0 {
			return osvCoord{"Go", joined[:i]}, true
		}
	}
	return osvCoord{}, false
}

func splitPath(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// afterSegment returns the path segment immediately following `key`, if any.
func afterSegment(segs []string, key string) string {
	for i, s := range segs {
		if s == key && i+1 < len(segs) {
			return segs[i+1]
		}
	}
	return ""
}
