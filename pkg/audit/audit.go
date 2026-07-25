package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/brewster/internal/config"
	"github.com/afterdarksys/brewster/pkg/brew"
	"github.com/afterdarksys/brewster/pkg/cve"
	"github.com/afterdarksys/brewster/pkg/darkapi"
)

// Severity levels for findings
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// FindingType categorizes the type of security issue
type FindingType string

const (
	FindingCVE            FindingType = "CVE"
	FindingAbandoned      FindingType = "ABANDONED"
	FindingHTTP           FindingType = "INSECURE_HTTP"
	FindingDeprecated     FindingType = "DEPRECATED"
	FindingNoChecksum     FindingType = "NO_CHECKSUM"
	FindingUntrustedTap   FindingType = "UNTRUSTED_TAP"
	FindingDeadURL        FindingType = "DEAD_URL"
	FindingSuspiciousCode FindingType = "SUSPICIOUS_CODE"
)

// Finding represents a security finding
type Finding struct {
	Package     string      `json:"package"`
	Type        FindingType `json:"type"`
	Severity    Severity    `json:"severity"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	URL         string      `json:"url,omitempty"`
	CVE         string      `json:"cve,omitempty"`
	Remediation string      `json:"remediation,omitempty"`
}

// AuditResult holds the results of an audit
type AuditResult struct {
	Timestamp      time.Time `json:"timestamp"`
	PackagesScanned int      `json:"packages_scanned"`
	TapsScanned     int      `json:"taps_scanned"`
	Findings        []Finding `json:"findings"`
	Summary         Summary   `json:"summary"`
}

// Summary provides counts by severity
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// RunLocalAudit performs a security audit on locally installed packages
func RunLocalAudit(cfg config.AuditConfig) (*AuditResult, error) {
	result := &AuditResult{
		Timestamp: time.Now(),
		Findings:  []Finding{},
	}

	// Get installed packages
	packages, err := brew.GetInstalledFormulae()
	if err != nil {
		return nil, fmt.Errorf("failed to get installed packages: %w", err)
	}
	result.PackagesScanned = len(packages)

	// Get installed taps
	taps, err := brew.GetInstalledTaps()
	if err != nil {
		return nil, fmt.Errorf("failed to get installed taps: %w", err)
	}
	result.TapsScanned = len(taps)

	if cfg.Verbose {
		fmt.Printf("  Scanning %d packages and %d taps...\n", len(packages), len(taps))
	}

	// Check for HTTP URLs
	if cfg.CheckHTTP {
		for _, pkg := range packages {
			if brew.IsHTTPURL(pkg.URL) {
				result.Findings = append(result.Findings, Finding{
					Package:     pkg.FullName,
					Type:        FindingHTTP,
					Severity:    SeverityMedium,
					Title:       "Package uses insecure HTTP URL",
					Description: fmt.Sprintf("Package %s downloads from an HTTP URL which could be intercepted", pkg.Name),
					URL:         pkg.URL,
					Remediation: "Consider reporting this to the tap maintainer",
				})
			}
		}
	}

	// Check for untrusted taps
	for _, tap := range taps {
		if !tap.Official {
			result.Findings = append(result.Findings, Finding{
				Package:     tap.Name,
				Type:        FindingUntrustedTap,
				Severity:    SeverityInfo,
				Title:       "Third-party tap installed",
				Description: fmt.Sprintf("Tap %s is not an official Homebrew tap", tap.Name),
				URL:         tap.Remote,
				Remediation: "Verify the tap source is trustworthy",
			})
		}
	}

	// Check for abandoned/deprecated packages
	if cfg.CheckAbandoned {
		for _, pkg := range packages {
			findings := checkAbandoned(pkg, cfg.Verbose)
			result.Findings = append(result.Findings, findings...)
		}
	}

	// Check for CVEs
	if cfg.CheckCVE {
		findings := checkCVEs(packages, cfg)
		result.Findings = append(result.Findings, findings...)

		// Submit CVE findings to DarkAPI if enabled
		if cfg.SubmitToDarkAPI {
			if err := submitCVEFindings(result.Findings, cfg.DarkAPIURL, cfg.DarkAPIKey, cfg.Verbose); err != nil {
				if cfg.Verbose {
					fmt.Printf("  Warning: Failed to submit CVE findings to DarkAPI: %v\n", err)
				}
				// Don't fail the audit if submission fails
			} else if cfg.Verbose {
				fmt.Printf("  Successfully submitted CVE findings to DarkAPI\n")
			}
		}
	}

	// Calculate summary
	result.Summary = calculateSummary(result.Findings)

	return result, nil
}

func checkAbandoned(pkg brew.InstalledPackage, verbose bool) []Finding {
	var findings []Finding

	// Check if it's a GitHub repo and if so, check activity
	owner, repo, ok := brew.ExtractGitHubRepo(pkg.Homepage)
	if !ok {
		owner, repo, ok = brew.ExtractGitHubRepo(pkg.URL)
	}

	if ok {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET",
			fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo), nil)
		if err != nil {
			return findings
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return findings
		}
		defer resp.Body.Close()

		if resp.StatusCode == 404 {
			findings = append(findings, Finding{
				Package:     pkg.FullName,
				Type:        FindingDeadURL,
				Severity:    SeverityHigh,
				Title:       "Repository not found",
				Description: fmt.Sprintf("The GitHub repository for %s no longer exists", pkg.Name),
				URL:         fmt.Sprintf("https://github.com/%s/%s", owner, repo),
				Remediation: "Consider uninstalling this package or finding an alternative",
			})
			return findings
		}

		if resp.StatusCode == 200 {
			var repoInfo struct {
				Archived  bool      `json:"archived"`
				PushedAt  time.Time `json:"pushed_at"`
				OpenIssues int      `json:"open_issues_count"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&repoInfo); err == nil {
				// Check if archived
				if repoInfo.Archived {
					findings = append(findings, Finding{
						Package:     pkg.FullName,
						Type:        FindingAbandoned,
						Severity:    SeverityMedium,
						Title:       "Repository is archived",
						Description: fmt.Sprintf("The upstream repository for %s has been archived", pkg.Name),
						URL:         fmt.Sprintf("https://github.com/%s/%s", owner, repo),
						Remediation: "Consider finding an actively maintained alternative",
					})
				}

				// Check for inactivity (no commits in 2 years)
				if time.Since(repoInfo.PushedAt) > 2*365*24*time.Hour {
					findings = append(findings, Finding{
						Package:     pkg.FullName,
						Type:        FindingAbandoned,
						Severity:    SeverityLow,
						Title:       "Repository appears abandoned",
						Description: fmt.Sprintf("No commits to %s/%s in over 2 years (last: %s)",
							owner, repo, repoInfo.PushedAt.Format("2006-01-02")),
						URL:         fmt.Sprintf("https://github.com/%s/%s", owner, repo),
						Remediation: "Monitor for security issues; consider alternatives",
					})
				}
			}
		}
	}

	return findings
}

func checkCVEs(packages []brew.InstalledPackage, cfg config.AuditConfig) []Finding {
	matcher := cve.NewMatcher(cve.Config{Source: cfg.CVESource, NVDAPIKey: cfg.NVDAPIKey})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var findings []Finding
	scanErrors := 0

	for _, pkg := range packages {
		res := matcher.ScanPackage(ctx, cve.Package{
			Name:     pkg.Name,
			Version:  pkg.Version,
			Homepage: pkg.Homepage,
			URL:      pkg.URL,
		})
		scanErrors += len(res.Errors)
		if cfg.Verbose {
			for _, e := range res.Errors {
				fmt.Fprintf(os.Stderr, "[cve] %s: %v\n", pkg.Name, e)
			}
		}
		for _, v := range res.Vulns {
			findings = append(findings, Finding{
				Package:     pkg.FullName,
				Type:        FindingCVE,
				Severity:    toAuditSeverity(v.Severity),
				Title:       fmt.Sprintf("Known vulnerability: %s", v.ID),
				Description: v.Summary,
				CVE:         v.ID,
				URL:         v.Reference,
				Remediation: cveRemediation(v),
			})
		}
	}

	// Fail loud: a lookup that errored is NOT a clean result. Surface it so an
	// empty findings list is never silently mistaken for "no vulnerabilities" —
	// the exact failure the old Homebrew-ecosystem query produced on every run.
	if scanErrors > 0 {
		findings = append(findings, Finding{
			Type:        FindingCVE,
			Severity:    SeverityInfo,
			Title:       "CVE scan degraded",
			Description: fmt.Sprintf("%d vulnerability-source error(s) occurred; CVE results may be incomplete.", scanErrors),
			Remediation: "Re-run with --verbose; check access to api.osv.dev / services.nvd.nist.gov and NVD_API_KEY.",
		})
	}

	return findings
}

func toAuditSeverity(s cve.Severity) Severity {
	switch s {
	case cve.SeverityCritical:
		return SeverityCritical
	case cve.SeverityHigh:
		return SeverityHigh
	case cve.SeverityMedium:
		return SeverityMedium
	case cve.SeverityLow:
		return SeverityLow
	default:
		// A matched CVE whose severity couldn't be determined still warrants
		// review, so surface it as MEDIUM rather than INFO ("no action"). This
		// is common for OSV Go-DB (GO-xxxx) records, whose severity lives only
		// on their GHSA/CVE alias — resolving that alias is a possible follow-up.
		return SeverityMedium
	}
}

func cveRemediation(v cve.Vuln) string {
	if v.FixedIn != "" {
		return fmt.Sprintf("Update to %s or later", v.FixedIn)
	}
	return "Update to a patched version or apply available workarounds"
}

func calculateSummary(findings []Finding) Summary {
	var s Summary
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		case SeverityInfo:
			s.Info++
		}
		s.Total++
	}
	return s
}

// submitCVEFindings submits CVE findings to DarkAPI
func submitCVEFindings(findings []Finding, apiURL, apiKey string, verbose bool) error {
	// Filter to only CVE findings
	var cveFindings []darkapi.CVEFinding
	for _, finding := range findings {
		if finding.Type != FindingCVE {
			continue
		}

		// Parse package name and version
		parts := strings.Split(finding.Package, "@")
		packageName := finding.Package
		packageVersion := "unknown"
		if len(parts) == 2 {
			packageName = parts[0]
			packageVersion = parts[1]
		}

		// Extract CVSS score from the finding if available
		cvssScore := 0.0
		if finding.CVE != "" {
			// Try to parse CVSS score from description or severity
			cvssScore = severityToCVSS(finding.Severity)
		}

		// Get system information
		hostname := darkapi.GetHostname()
		platform, arch, systemID := darkapi.GetSystemInfo()

		// Create CVE finding
		cveFinding := darkapi.CVEFinding{
			CVEID:             finding.CVE,
			Hostname:          hostname,
			SystemID:          systemID,
			Platform:          platform,
			Architecture:      arch,
			PackageName:       packageName,
			PackageVersion:    packageVersion,
			PackageManager:    "homebrew",
			Ecosystem:         "Homebrew",
			Severity:          string(finding.Severity),
			CVSSScore:         cvssScore,
			Title:             finding.Title,
			Description:       finding.Description,
			DetectedBy:        "brewster",
			SourceToolVersion: "1.0.0",
			ReferenceURL:      finding.URL,
			RemediationText:   finding.Remediation,
			RawData: map[string]interface{}{
				"audit_timestamp": time.Now().Format(time.RFC3339),
				"finding_type":    string(finding.Type),
			},
		}

		cveFindings = append(cveFindings, cveFinding)
	}

	if len(cveFindings) == 0 {
		if verbose {
			fmt.Println("  No CVE findings to submit")
		}
		return nil
	}

	if verbose {
		fmt.Printf("  Submitting %d CVE findings to DarkAPI...\n", len(cveFindings))
	}

	// Create DarkAPI client
	client := darkapi.NewClient(apiURL, apiKey)

	// Generate batch ID
	hostname := darkapi.GetHostname()
	batchID := fmt.Sprintf("brewster-%s-%d", hostname, time.Now().Unix())

	// Submit findings
	resp, err := client.SubmitFindings(cveFindings, batchID)
	if err != nil {
		return fmt.Errorf("failed to submit findings: %w", err)
	}

	if verbose {
		fmt.Printf("  DarkAPI submission: %d inserted, %d updated\n", resp.Inserted, resp.Updated)
		if resp.PartialSuccess {
			fmt.Printf("  Warning: Partial success with %d errors\n", len(resp.Errors))
		}
	}

	return nil
}

// severityToCVSS converts a severity level to an approximate CVSS score
func severityToCVSS(severity Severity) float64 {
	switch severity {
	case SeverityCritical:
		return 9.5
	case SeverityHigh:
		return 7.5
	case SeverityMedium:
		return 5.5
	case SeverityLow:
		return 3.0
	case SeverityInfo:
		return 0.0
	default:
		return 0.0
	}
}

// parseCVSSScore attempts to extract a CVSS score from a string
func parseCVSSScore(s string) float64 {
	// Try to find patterns like "CVSS: 7.5" or just "7.5"
	s = strings.TrimSpace(s)
	if score, err := strconv.ParseFloat(s, 64); err == nil {
		if score >= 0 && score <= 10 {
			return score
		}
	}
	return 0.0
}
