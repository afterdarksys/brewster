// Package cve resolves known vulnerabilities for installed Homebrew packages.
//
// Threats: query bodies are encoding/json and CPE fields are escaped. Transport,
// HTTP, decode, oversize, pagination, and unknown-source failures return an
// error and keep any vulns already found. Feeds are trusted only over HTTPS.
// Formulae with no curated coordinate are skipped.
package cve

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
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
	ID        string   // preferred id: CVE alias when the feed has one, else the feed id
	Aliases   []string // other ids (GHSA, GO-..., additional CVEs)
	Summary   string
	Severity  Severity
	Reference string
	FixedIn   string
	Source    string // "osv" | "nvd"
	Package   string
	Version   string
}

// Source is one vulnerability database. Query must return an error on
// transport, HTTP, or decode failure, not an empty slice.
type Source interface {
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
	sources    []Source
	keylessNVD bool
}

const (
	scanConcurrency = 4
	packageTimeout  = 2 * time.Minute
)

func NewMatcher(cfg Config) (*Matcher, error) {
	src := strings.ToLower(strings.TrimSpace(cfg.Source))
	if src == "" {
		src = "auto"
	}

	var sources []Source
	keylessNVD := false
	switch src {
	case "osv":
		sources = []Source{NewOSVSource()}
	case "nvd":
		sources = []Source{NewNVDSource(cfg.NVDAPIKey)}
		keylessNVD = strings.TrimSpace(cfg.NVDAPIKey) == ""
	case "both":
		sources = []Source{NewOSVSource(), NewNVDSource(cfg.NVDAPIKey)}
		keylessNVD = strings.TrimSpace(cfg.NVDAPIKey) == ""
	case "auto":
		sources = []Source{NewOSVSource()}
		if strings.TrimSpace(cfg.NVDAPIKey) != "" {
			sources = append(sources, NewNVDSource(cfg.NVDAPIKey))
		}
	default:
		return nil, fmt.Errorf("unknown cve source %q (want auto, osv, nvd, or both)", src)
	}
	return &Matcher{sources: sources, keylessNVD: keylessNVD}, nil
}

func (m *Matcher) Warning() string {
	if m != nil && m.keylessNVD {
		return "NVD is enabled without an API key (about 5 requests per 30s). Set NVD_API_KEY."
	}
	return ""
}

func (m *Matcher) Sources() []string {
	names := make([]string, 0, len(m.sources))
	for _, s := range m.sources {
		names = append(names, s.Name())
	}
	return names
}

type Result struct {
	Vulns  []Vuln
	Errors []error
}

// ScanAll keeps input order. Each package has its own timeout.
func (m *Matcher) ScanAll(ctx context.Context, pkgs []Package) []Result {
	out := make([]Result, len(pkgs))
	sem := make(chan struct{}, scanConcurrency)
	var wg sync.WaitGroup
	for i, p := range pkgs {
		if err := ctx.Err(); err != nil {
			out[i].Errors = []error{err}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p Package) {
			defer wg.Done()
			defer func() { <-sem }()
			pctx, cancel := context.WithTimeout(ctx, packageTimeout)
			defer cancel()
			out[i] = m.ScanPackage(pctx, p)
		}(i, p)
	}
	wg.Wait()
	return out
}

func (m *Matcher) ScanPackage(ctx context.Context, p Package) Result {
	var res Result
	seen := make(map[string]bool)
	for _, s := range m.sources {
		vulns, err := s.Query(ctx, p)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("%s: %w", s.Name(), err))
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
