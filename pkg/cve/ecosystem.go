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

// curatedOSV maps well-known Homebrew formulae to their real OSV coordinates.
// These are formulae that ARE first-class packages in an OSV ecosystem, where
// the formula name alone is not enough to derive the coordinate. Kept small and
// authoritative on purpose: a wrong guess produces a bad query, and unmapped
// formulae are covered by the NVD/CPE source instead.
var curatedOSV = map[string]osvCoord{
	"awscli":    {"PyPI", "awscli"},
	"ansible":   {"PyPI", "ansible"},
	"httpie":    {"PyPI", "httpie"},
	"yt-dlp":    {"PyPI", "yt-dlp"},
	"pipenv":    {"PyPI", "pipenv"},
	"poetry":    {"PyPI", "poetry"},
	"ripgrep":   {"crates.io", "ripgrep"},
	"fd":        {"crates.io", "fd-find"},
	"bat":       {"crates.io", "bat"},
	"eza":       {"crates.io", "eza"},
	"exa":       {"crates.io", "exa"},
	"starship":  {"crates.io", "starship"},
	"deno":      {"crates.io", "deno"},
	"yarn":      {"npm", "yarn"},
	"pnpm":      {"npm", "pnpm"},
	"typescript": {"npm", "typescript"},
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

// osvCoordinates returns the OSV coordinates to try for a formula. It combines
// the curated map with a conservative host-based derivation from the download
// URL / homepage. It deliberately does NOT fan out across every ecosystem the
// way the old monitor code did — an unfounded ecosystem guess just produces
// noise; formulae with no confident OSV coordinate are left to the NVD source.
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

// coordFromURL derives an OSV coordinate from a well-known package-host URL.
// Only high-confidence hosts are handled; anything else returns ok=false.
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
	case strings.Contains(host, "pypi.org") || strings.Contains(host, "pythonhosted.org"):
		// https://pypi.org/project/<name>/ or .../packages/source/x/<name>/...
		if n := afterSegment(segs, "project"); n != "" {
			return osvCoord{"PyPI", n}, true
		}
		if n := afterSegment(segs, "source"); n != "" {
			// /packages/source/<a>/<name>/... -> take the segment after the letter
			return osvCoord{"PyPI", n}, true
		}
	case strings.Contains(host, "registry.npmjs.org") || strings.Contains(host, "npmjs.com"):
		if len(segs) >= 1 {
			name := segs[0]
			if name == "package" && len(segs) >= 2 {
				name = segs[1]
			}
			return osvCoord{"npm", name}, true
		}
	case strings.Contains(host, "crates.io") || strings.Contains(host, "static.crates.io"):
		// https://crates.io/crates/<name> or /api/v1/crates/<name>/<ver>/download
		if n := afterSegment(segs, "crates"); n != "" {
			return osvCoord{"crates.io", n}, true
		}
	case host == "github.com" || strings.HasSuffix(host, ".github.com"):
		// OSV Go advisories key on the module path github.com/<owner>/<repo>.
		if len(segs) >= 2 {
			repo := strings.TrimSuffix(segs[1], ".git")
			return osvCoord{"Go", "github.com/" + segs[0] + "/" + repo}, true
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
