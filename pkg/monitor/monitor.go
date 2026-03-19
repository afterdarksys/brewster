package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/afterdarksys/brewster/pkg/audit"
	"github.com/afterdarksys/brewster/pkg/brew"
)

// Config holds monitor configuration
type Config struct {
	Verbose bool
}

// CVEResult holds CVE monitoring results
type CVEResult struct {
	Timestamp      time.Time         `json:"timestamp"`
	PackagesChecked int              `json:"packages_checked"`
	VulnCount      int               `json:"vulnerable_count"`
	Vulnerabilities []VulnInfo       `json:"vulnerabilities"`
}

// VulnInfo holds vulnerability information
type VulnInfo struct {
	Package     string         `json:"package"`
	Version     string         `json:"version"`
	CVEID       string         `json:"cve_id"`
	Severity    audit.Severity `json:"severity"`
	Summary     string         `json:"summary"`
	Published   time.Time      `json:"published,omitempty"`
	FixedIn     string         `json:"fixed_in,omitempty"`
	Reference   string         `json:"reference,omitempty"`
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

	for _, pkg := range packages {
		vulns := queryVulnerabilities(pkg.Name, pkg.Version, cfg.Verbose)
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	result.VulnCount = len(result.Vulnerabilities)
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

func queryVulnerabilities(name, version string, verbose bool) []VulnInfo {
	var vulns []VulnInfo

	// Query OSV.dev
	osvVulns := queryOSV(name, version)
	vulns = append(vulns, osvVulns...)

	// Query NVD (National Vulnerability Database) - simplified
	nvdVulns := queryNVD(name, version)
	vulns = append(vulns, nvdVulns...)

	return vulns
}

func queryOSV(name, version string) []VulnInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Try multiple ecosystems
	ecosystems := []string{"Homebrew", "PyPI", "npm", "Go", "crates.io"}
	var allVulns []VulnInfo

	for _, ecosystem := range ecosystems {
		payload := fmt.Sprintf(`{"package":{"name":"%s","ecosystem":"%s"},"version":"%s"}`, name, ecosystem, version)

		req, err := http.NewRequestWithContext(ctx, "POST",
			"https://api.osv.dev/v1/query",
			strings.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}

		var result struct {
			Vulns []struct {
				ID        string    `json:"id"`
				Summary   string    `json:"summary"`
				Published time.Time `json:"published"`
				Severity  []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				} `json:"severity"`
				Affected []struct {
					Ranges []struct {
						Events []struct {
							Fixed string `json:"fixed"`
						} `json:"events"`
					} `json:"ranges"`
				} `json:"affected"`
				References []struct {
					Type string `json:"type"`
					URL  string `json:"url"`
				} `json:"references"`
			} `json:"vulns"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		for _, v := range result.Vulns {
			vuln := VulnInfo{
				Package:   name,
				Version:   version,
				CVEID:     v.ID,
				Summary:   v.Summary,
				Published: v.Published,
				Severity:  audit.SeverityMedium,
			}

			// Get severity
			for _, s := range v.Severity {
				if s.Type == "CVSS_V3" {
					vuln.Severity = cvssToSeverity(s.Score)
					break
				}
			}

			// Get fixed version
			for _, aff := range v.Affected {
				for _, r := range aff.Ranges {
					for _, e := range r.Events {
						if e.Fixed != "" {
							vuln.FixedIn = e.Fixed
						}
					}
				}
			}

			// Get reference URL
			for _, ref := range v.References {
				if ref.Type == "ADVISORY" {
					vuln.Reference = ref.URL
					break
				}
				if vuln.Reference == "" {
					vuln.Reference = ref.URL
				}
			}

			allVulns = append(allVulns, vuln)
		}
	}

	return allVulns
}

func queryNVD(name, version string) []VulnInfo {
	// NVD API query (simplified - in production you'd want proper API key)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Search by keyword
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s", name)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// NVD has rate limiting, so we just do basic queries
	if resp.StatusCode != 200 {
		return nil
	}

	var nvdResult struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&nvdResult); err != nil {
		return nil
	}

	var vulns []VulnInfo
	for _, v := range nvdResult.Vulnerabilities {
		// Only include if the CVE ID suggests relevance to the package
		if !strings.Contains(strings.ToLower(v.CVE.ID), strings.ToLower(name)) {
			// Check description for package name
			relevant := false
			for _, desc := range v.CVE.Descriptions {
				if strings.Contains(strings.ToLower(desc.Value), strings.ToLower(name)) {
					relevant = true
					break
				}
			}
			if !relevant {
				continue
			}
		}

		summary := ""
		for _, desc := range v.CVE.Descriptions {
			if desc.Lang == "en" {
				summary = desc.Value
				break
			}
		}

		severity := audit.SeverityMedium
		if len(v.CVE.Metrics.CvssMetricV31) > 0 {
			score := v.CVE.Metrics.CvssMetricV31[0].CvssData.BaseScore
			switch {
			case score >= 9.0:
				severity = audit.SeverityCritical
			case score >= 7.0:
				severity = audit.SeverityHigh
			case score >= 4.0:
				severity = audit.SeverityMedium
			default:
				severity = audit.SeverityLow
			}
		}

		vulns = append(vulns, VulnInfo{
			Package:   name,
			Version:   version,
			CVEID:     v.CVE.ID,
			Severity:  severity,
			Summary:   summary,
			Reference: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.CVE.ID),
		})
	}

	return vulns
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

func cvssToSeverity(score string) audit.Severity {
	if strings.Contains(score, "9.") || strings.Contains(score, "10.") {
		return audit.SeverityCritical
	}
	if strings.Contains(score, "7.") || strings.Contains(score, "8.") {
		return audit.SeverityHigh
	}
	if strings.Contains(score, "4.") || strings.Contains(score, "5.") || strings.Contains(score, "6.") {
		return audit.SeverityMedium
	}
	return audit.SeverityLow
}
