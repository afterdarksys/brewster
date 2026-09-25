package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/afterdarksys/brewster/pkg/audit"
	"github.com/afterdarksys/brewster/pkg/brew"
	"github.com/afterdarksys/brewster/pkg/cve"
)

// Config holds monitor configuration
type Config struct {
	Verbose   bool
	Source    string // CVE source: "auto" | "osv" | "nvd" | "both"
	NVDAPIKey string
}

// CVEResult holds CVE monitoring results
type CVEResult struct {
	Timestamp       time.Time  `json:"timestamp"`
	PackagesChecked int        `json:"packages_checked"`
	VulnCount       int        `json:"vulnerable_count"`
	ScanErrors      int        `json:"scan_errors,omitempty"`
	Vulnerabilities []VulnInfo `json:"vulnerabilities"`
}

// VulnInfo holds vulnerability information
type VulnInfo struct {
	Package   string         `json:"package"`
	Version   string         `json:"version"`
	CVEID     string         `json:"cve_id"`
	Aliases   []string       `json:"aliases,omitempty"`
	Severity  audit.Severity `json:"severity"`
	Summary   string         `json:"summary"`
	Published time.Time      `json:"published,omitempty"`
	FixedIn   string         `json:"fixed_in,omitempty"`
	Reference string         `json:"reference,omitempty"`
}

// TapAnalysisResult holds tap analysis results
type TapAnalysisResult struct {
	Timestamp    time.Time    `json:"timestamp"`
	TapsAnalyzed int          `json:"taps_analyzed"`
	Findings     []TapFinding `json:"findings"`
}

// TapFinding holds a finding about a tap
type TapFinding struct {
	Tap         string         `json:"tap"`
	Type        string         `json:"type"`
	Severity    audit.Severity `json:"severity"`
	Description string         `json:"description"`
	Details     interface{}    `json:"details,omitempty"`
}

// CheckCVEs checks installed packages against CVE databases
func CheckCVEs(cfg Config) (*CVEResult, error) {
	result := &CVEResult{
		Timestamp:       time.Now(),
		Vulnerabilities: []VulnInfo{},
	}

	packages, err := brew.GetInstalledFormulae()
	if err != nil {
		return nil, fmt.Errorf("failed to get installed packages: %w", err)
	}

	result.PackagesChecked = len(packages)

	if cfg.Verbose {
		fmt.Printf("  Checking %d packages for known vulnerabilities...\n", len(packages))
	}

	matcher, err := cve.NewMatcher(cve.Config{Source: cfg.Source, NVDAPIKey: cfg.NVDAPIKey})
	if err != nil {
		return nil, err
	}
	if w := matcher.Warning(); w != "" {
		fmt.Fprintf(os.Stderr, "[cve] %s\n", w)
	}

	pkgs := make([]cve.Package, len(packages))
	for i, pkg := range packages {
		pkgs[i] = cve.Package{
			Name:     pkg.Name,
			Version:  pkg.Version,
			Homepage: pkg.Homepage,
			URL:      pkg.URL,
		}
	}
	scanned := matcher.ScanAll(context.Background(), pkgs)

	scanErrors := 0
	for i, res := range scanned {
		pkg := packages[i]
		scanErrors += len(res.Errors)
		if cfg.Verbose {
			for _, e := range res.Errors {
				fmt.Fprintf(os.Stderr, "[cve] %s: %v\n", pkg.Name, e)
			}
		}
		for _, v := range res.Vulns {
			result.Vulnerabilities = append(result.Vulnerabilities, VulnInfo{
				Package:   pkg.Name,
				Version:   pkg.Version,
				CVEID:     v.ID,
				Aliases:   v.Aliases,
				Severity:  toAuditSeverity(v.Severity),
				Summary:   v.Summary,
				FixedIn:   v.FixedIn,
				Reference: v.Reference,
			})
		}
	}

	result.VulnCount = len(result.Vulnerabilities)
	result.ScanErrors = scanErrors
	if scanErrors > 0 {
		return result, fmt.Errorf("cve scan incomplete: %d source error(s)", scanErrors)
	}
	return result, nil
}

// AnalyzeTaps analyzes installed third-party taps
func AnalyzeTaps(cfg Config) (*TapAnalysisResult, error) {
	result := &TapAnalysisResult{
		Timestamp: time.Now(),
		Findings:  []TapFinding{},
	}

	taps, err := brew.GetInstalledTaps()
	if err != nil {
		return nil, fmt.Errorf("failed to get installed taps: %w", err)
	}

	result.TapsAnalyzed = len(taps)

	if cfg.Verbose {
		fmt.Printf("  Analyzing %d taps...\n", len(taps))
	}

	for _, tap := range taps {
		if tap.Official {
			continue
		}

		findings := analyzeTap(tap, cfg)
		result.Findings = append(result.Findings, findings...)
	}

	return result, nil
}

func toAuditSeverity(s cve.Severity) audit.Severity {
	switch s {
	case cve.SeverityCritical:
		return audit.SeverityCritical
	case cve.SeverityHigh:
		return audit.SeverityHigh
	case cve.SeverityMedium:
		return audit.SeverityMedium
	case cve.SeverityLow:
		return audit.SeverityLow
	default:
		return audit.SeverityMedium
	}
}

func analyzeTap(tap brew.Tap, cfg Config) []TapFinding {
	var findings []TapFinding

	// Parse owner/repo from tap name
	parts := strings.Split(tap.Name, "/")
	if len(parts) != 2 {
		return findings
	}

	owner := parts[0]
	repo := "homebrew-" + parts[1]

	// Get GitHub repo info
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo), nil)
	if err != nil {
		return findings
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		findings = append(findings, TapFinding{
			Tap:         tap.Name,
			Type:        "NETWORK_ERROR",
			Severity:    audit.SeverityInfo,
			Description: "Could not verify tap repository",
		})
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		findings = append(findings, TapFinding{
			Tap:         tap.Name,
			Type:        "MISSING_REPO",
			Severity:    audit.SeverityHigh,
			Description: "Tap repository no longer exists on GitHub",
		})
		return findings
	}

	var repoInfo struct {
		Stars         int       `json:"stargazers_count"`
		Forks         int       `json:"forks_count"`
		CreatedAt     time.Time `json:"created_at"`
		PushedAt      time.Time `json:"pushed_at"`
		OpenIssues    int       `json:"open_issues_count"`
		Archived      bool      `json:"archived"`
		DefaultBranch string    `json:"default_branch"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&repoInfo); err != nil {
		return findings
	}

	// Check for concerning patterns
	if repoInfo.Archived {
		findings = append(findings, TapFinding{
			Tap:         tap.Name,
			Type:        "ARCHIVED",
			Severity:    audit.SeverityMedium,
			Description: "Tap repository is archived - no longer maintained",
		})
	}

	age := time.Since(repoInfo.CreatedAt)
	if age < 30*24*time.Hour {
		findings = append(findings, TapFinding{
			Tap:         tap.Name,
			Type:        "NEW_TAP",
			Severity:    audit.SeverityHigh,
			Description: fmt.Sprintf("Tap was created only %d days ago", int(age.Hours()/24)),
			Details: map[string]interface{}{
				"created_at": repoInfo.CreatedAt,
				"stars":      repoInfo.Stars,
			},
		})
	}

	lastUpdate := time.Since(repoInfo.PushedAt)
	if lastUpdate > 365*24*time.Hour {
		findings = append(findings, TapFinding{
			Tap:         tap.Name,
			Type:        "STALE",
			Severity:    audit.SeverityLow,
			Description: fmt.Sprintf("No updates in %d days", int(lastUpdate.Hours()/24)),
			Details: map[string]interface{}{
				"last_update": repoInfo.PushedAt,
			},
		})
	}

	if repoInfo.Stars < 10 && age > 90*24*time.Hour {
		findings = append(findings, TapFinding{
			Tap:         tap.Name,
			Type:        "LOW_VISIBILITY",
			Severity:    audit.SeverityInfo,
			Description: fmt.Sprintf("Low community engagement (%d stars)", repoInfo.Stars),
		})
	}

	return findings
}
