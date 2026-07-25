// Package cve resolves known vulnerabilities for installed Homebrew packages.
//
// Homebrew is not a first-class OSV.dev ecosystem, so a single
// {"ecosystem":"Homebrew"} query (as the original audit code did) always
// returns nothing — turning the scanner into a silent no-op. This package maps
// each formula to the coordinates the upstream databases actually use: OSV
// ecosystems (PyPI/npm/Go/crates.io/...) where a formula is a real package, and
// NVD CPE product names for system libraries. Two rules the old code broke:
//
//  1. Requests are built with encoding/json, never fmt.Sprintf, so a formula
//     name or version containing a quote or backslash cannot corrupt the query.
//  2. Lookups fail loud: a transport, HTTP-status, or decode failure returns an
//     error instead of an empty slice that would masquerade as "no vulns".
package cve

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Severity is a normalized severity level.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityUnknown  Severity = "unknown"
)

// Package is an installed formula to check.
type Package struct {
	Name     string
	Version  string
	Homepage string
	URL      string
}

// Vuln is a single matched vulnerability.
type Vuln struct {
	ID        string // CVE or OSV id
	Summary   string
	Severity  Severity
	Reference string
	FixedIn   string
	Source    string // "osv" | "nvd"
	Package   string
	Version   string
}

// Source is one vulnerability database backend.
type Source interface {
	// Query returns vulns for a package. It MUST return a non-nil error on any
	// transport/HTTP/decode failure rather than an empty slice, so the caller
	// can distinguish "clean" from "the lookup broke".
	Query(ctx context.Context, p Package) ([]Vuln, error)
	Name() string
}

// Config selects which backends run.
//
// Source: "auto" (default), "osv", "nvd", or "both".
//   - auto: OSV always; NVD additionally when an NVD API key is configured
//     (keyless NVD is rate-limited to ~5 req/30s, unusable as a default).
type Config struct {
	Source    string
	NVDAPIKey string
}

// Matcher fans a package out across the configured sources.
type Matcher struct {
	sources []Source
}

// NewMatcher builds a Matcher from config, applying the "auto" default.
func NewMatcher(cfg Config) *Matcher {
	src := strings.ToLower(strings.TrimSpace(cfg.Source))
	if src == "" {
		src = "auto"
	}

	var sources []Source
	switch src {
	case "osv":
		sources = []Source{NewOSVSource()}
	case "nvd":
		sources = []Source{NewNVDSource(cfg.NVDAPIKey)}
	case "both":
		sources = []Source{NewOSVSource(), NewNVDSource(cfg.NVDAPIKey)}
	default: // auto
		sources = []Source{NewOSVSource()}
		if strings.TrimSpace(cfg.NVDAPIKey) != "" {
			sources = append(sources, NewNVDSource(cfg.NVDAPIKey))
		}
	}
	return &Matcher{sources: sources}
}

// Sources reports the active backend names (for verbose/status output).
func (m *Matcher) Sources() []string {
	names := make([]string, 0, len(m.sources))
	for _, s := range m.sources {
		names = append(names, s.Name())
	}
	return names
}

// Result holds the vulns found for a package plus any per-source errors.
// Errors are non-fatal (other sources still run) but MUST be surfaced by the
// caller — a degraded scan is not a clean scan.
type Result struct {
	Vulns  []Vuln
	Errors []error
}

// ScanPackage queries every source and de-duplicates by (package, id).
func (m *Matcher) ScanPackage(ctx context.Context, p Package) Result {
	var res Result
	seen := make(map[string]bool)
	for _, s := range m.sources {
		vulns, err := s.Query(ctx, p)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("%s: %w", s.Name(), err))
			continue
		}
		for _, v := range vulns {
			key := v.Package + "\x00" + v.ID
			if seen[key] {
				continue
			}
			seen[key] = true
			res.Vulns = append(res.Vulns, v)
		}
	}
	return res
}

// severityFromScore maps a CVSS base score to a normalized level.
func severityFromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// severityFromLabel maps an NVD baseSeverity label to a normalized level.
func severityFromLabel(label string) Severity {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// severityFromCVSS best-effort parses an OSV severity score field, which may be
// a bare number ("7.5") or a CVSS vector string. We only trust a numeric base
// score; a vector without a computed score yields Unknown (honest over guessed).
func severityFromCVSS(score string) Severity {
	score = strings.TrimSpace(score)
	if score == "" {
		return SeverityUnknown
	}
	if f, err := strconv.ParseFloat(score, 64); err == nil {
		return severityFromScore(f)
	}
	if base, ok := cvssV3BaseScore(score); ok {
		return severityFromScore(base)
	}
	return SeverityUnknown
}
