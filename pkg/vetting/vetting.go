package vetting

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/afterdarksys/brewster/pkg/audit"
	"github.com/afterdarksys/brewster/pkg/brew"
	"github.com/afterdarksys/brewster/pkg/intel"
)

// VetConfig holds vetting configuration
type VetConfig struct {
	Verbose bool
}

// VetResult holds the vetting analysis
type VetResult struct {
	Target      string          `json:"target"`
	TargetType  string          `json:"target_type"` // "tap" or "formula"
	Timestamp   time.Time       `json:"timestamp"`
	RiskScore   int             `json:"risk_score"` // 0-100
	RiskLevel   string          `json:"risk_level"` // LOW, MEDIUM, HIGH, CRITICAL
	Findings    []audit.Finding `json:"findings"`
	Metadata    TapMetadata     `json:"metadata,omitempty"`
	Recommendation string       `json:"recommendation"`
}

// TapMetadata holds metadata about a tap
type TapMetadata struct {
	Name          string    `json:"name"`
	Owner         string    `json:"owner"`
	Repo          string    `json:"repo"`
	Stars         int       `json:"stars"`
	Forks         int       `json:"forks"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	OpenIssues    int       `json:"open_issues"`
	FormulaCount  int       `json:"formula_count"`
	IsArchived    bool      `json:"is_archived"`
	DefaultBranch string    `json:"default_branch"`
}

// VetTarget vets a tap or formula
func VetTarget(target string, cfg VetConfig) (*VetResult, error) {
	result := &VetResult{
		Target:    target,
		Timestamp: time.Now(),
		Findings:  []audit.Finding{},
	}

	// Determine if this is a tap or formula
	parts := strings.Split(target, "/")
	if len(parts) == 2 {
		// It's a tap (user/tap)
		result.TargetType = "tap"
		return vetTap(result, target, cfg)
	} else if len(parts) == 3 {
		// It's a formula (user/tap/formula)
		result.TargetType = "formula"
		return vetFormula(result, target, cfg)
	}

	// Try as a core formula name
	result.TargetType = "formula"
	return vetFormula(result, target, cfg)
}

// VetInstalledTaps vets all installed taps
func VetInstalledTaps(cfg VetConfig) ([]*VetResult, error) {
	taps, err := brew.GetInstalledTaps()
	if err != nil {
		return nil, err
	}

	var results []*VetResult
	for _, tap := range taps {
		if tap.Official {
			continue // Skip official taps
		}

		result, err := VetTarget(tap.Name, cfg)
		if err != nil {
			if cfg.Verbose {
				fmt.Printf("  Warning: could not vet %s: %v\n", tap.Name, err)
			}
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

func vetTap(result *VetResult, tapName string, cfg VetConfig) (*VetResult, error) {
	parts := strings.Split(tapName, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid tap name: %s", tapName)
	}

	owner := parts[0]
	repo := "homebrew-" + parts[1]

	if cfg.Verbose {
		fmt.Printf("  Analyzing tap: %s/%s\n", owner, repo)
	}

	// Get GitHub metadata
	metadata, err := getGitHubMetadata(owner, repo)
	if err != nil {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     tapName,
			Type:        audit.FindingDeadURL,
			Severity:    audit.SeverityHigh,
			Title:       "Tap repository not accessible",
			Description: fmt.Sprintf("Could not access GitHub repository: %v", err),
			Remediation: "Verify the tap exists and is accessible",
		})
		result.RiskScore = 80
		result.RiskLevel = "HIGH"
		result.Recommendation = "Cannot verify tap - do not install"
		return result, nil
	}

	result.Metadata = *metadata

	// Analyze for risks
	analyzeRepository(result, metadata)

	// Check formulas in the tap if it's installed
	checkTapFormulas(result, tapName, cfg)

	// Calculate overall risk
	calculateRisk(result)

	return result, nil
}

func vetFormula(result *VetResult, formulaName string, cfg VetConfig) (*VetResult, error) {
	if cfg.Verbose {
		fmt.Printf("  Analyzing formula: %s\n", formulaName)
	}

	// Get formula info
	formula, err := brew.GetFormulaInfo(formulaName)
	if err != nil {
		return nil, fmt.Errorf("could not get formula info: %w", err)
	}

	// Check for deprecation
	if formula.Deprecated {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     formulaName,
			Type:        audit.FindingDeprecated,
			Severity:    audit.SeverityMedium,
			Title:       "Formula is deprecated",
			Description: fmt.Sprintf("Deprecated on %s: %s", formula.DeprecationDate, formula.DeprecationReason),
			Remediation: "Find an alternative package",
		})
	}

	if formula.Disabled {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     formulaName,
			Type:        audit.FindingDeprecated,
			Severity:    audit.SeverityHigh,
			Title:       "Formula is disabled",
			Description: "This formula has been disabled and should not be used",
			Remediation: "Find an alternative package",
		})
	}

	// Check URL security
	if brew.IsHTTPURL(formula.URL) {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     formulaName,
			Type:        audit.FindingHTTP,
			Severity:    audit.SeverityMedium,
			Title:       "Formula uses insecure HTTP",
			Description: "Downloads over unencrypted HTTP can be intercepted",
			URL:         formula.URL,
			Remediation: "Consider the risk of man-in-the-middle attacks",
		})
	}

	// Threat Intel Check
	intelClient := intel.NewClient(intel.ReputationConfig{})
	rep, _ := intelClient.CheckURL(context.Background(), formula.URL)
	if rep != nil && rep.RiskScore > 0 {
		sev := audit.SeverityMedium
		if rep.RiskScore > 80 {
			sev = audit.SeverityCritical
		} else if rep.RiskScore > 50 {
			sev = audit.SeverityHigh
		}
		
		result.Findings = append(result.Findings, audit.Finding{
			Package:     formulaName,
			Type:        audit.FindingDeadURL, // Using existing type for now
			Severity:    sev,
			Title:       "Threat Intel Alert: " + strings.Join(rep.Categories, ", "),
			Description: fmt.Sprintf("Domain reputation score: %d/100. %s", rep.RiskScore, rep.Recommendation),
			URL:         formula.URL,
			Remediation: rep.Recommendation,
		})
	}

	// Check if it's from a third-party tap
	if formula.Tap != "" && !strings.HasPrefix(formula.Tap, "homebrew/") {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     formulaName,
			Type:        audit.FindingUntrustedTap,
			Severity:    audit.SeverityInfo,
			Title:       "Formula from third-party tap",
			Description: fmt.Sprintf("This formula is from %s, not an official Homebrew tap", formula.Tap),
			Remediation: "Verify you trust the tap maintainer",
		})

		// Vet the tap as well
		tapResult, err := vetTap(&VetResult{Target: formula.Tap, Timestamp: time.Now()}, formula.Tap, cfg)
		if err == nil {
			result.Findings = append(result.Findings, tapResult.Findings...)
		}
	}

	// Check upstream repository
	owner, repo, ok := brew.ExtractGitHubRepo(formula.Homepage)
	if !ok {
		owner, repo, ok = brew.ExtractGitHubRepo(formula.URL)
	}

	if ok {
		checkUpstreamRepo(result, owner, repo, formulaName)
	}

	calculateRisk(result)
	return result, nil
}

func getGitHubMetadata(owner, repo string) (*TapMetadata, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo), nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("repository not found")
	}

	var ghRepo struct {
		Name          string    `json:"name"`
		Stars         int       `json:"stargazers_count"`
		Forks         int       `json:"forks_count"`
		CreatedAt     time.Time `json:"created_at"`
		UpdatedAt     time.Time `json:"updated_at"`
		PushedAt      time.Time `json:"pushed_at"`
		OpenIssues    int       `json:"open_issues_count"`
		Archived      bool      `json:"archived"`
		DefaultBranch string    `json:"default_branch"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghRepo); err != nil {
		return nil, err
	}

	return &TapMetadata{
		Name:          ghRepo.Name,
		Owner:         owner,
		Repo:          repo,
		Stars:         ghRepo.Stars,
		Forks:         ghRepo.Forks,
		CreatedAt:     ghRepo.CreatedAt,
		UpdatedAt:     ghRepo.PushedAt,
		OpenIssues:    ghRepo.OpenIssues,
		IsArchived:    ghRepo.Archived,
		DefaultBranch: ghRepo.DefaultBranch,
	}, nil
}

func analyzeRepository(result *VetResult, meta *TapMetadata) {
	// Check age - very new repos are riskier
	age := time.Since(meta.CreatedAt)
	if age < 30*24*time.Hour {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     result.Target,
			Type:        audit.FindingUntrustedTap,
			Severity:    audit.SeverityHigh,
			Title:       "Very new repository",
			Description: fmt.Sprintf("Tap was created only %d days ago", int(age.Hours()/24)),
			Remediation: "New taps have no track record - exercise caution",
		})
	} else if age < 90*24*time.Hour {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     result.Target,
			Type:        audit.FindingUntrustedTap,
			Severity:    audit.SeverityMedium,
			Title:       "Recently created repository",
			Description: fmt.Sprintf("Tap was created %d days ago", int(age.Hours()/24)),
			Remediation: "Consider waiting for the tap to establish a track record",
		})
	}

	// Check stars - low stars might indicate obscurity
	if meta.Stars < 5 {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     result.Target,
			Type:        audit.FindingUntrustedTap,
			Severity:    audit.SeverityMedium,
			Title:       "Low community engagement",
			Description: fmt.Sprintf("Repository has only %d stars", meta.Stars),
			Remediation: "Low visibility means less community oversight",
		})
	}

	// Check if archived
	if meta.IsArchived {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     result.Target,
			Type:        audit.FindingAbandoned,
			Severity:    audit.SeverityMedium,
			Title:       "Repository is archived",
			Description: "This tap is no longer maintained",
			Remediation: "Archived taps won't receive security updates",
		})
	}

	// Check last update
	lastUpdate := time.Since(meta.UpdatedAt)
	if lastUpdate > 365*24*time.Hour {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     result.Target,
			Type:        audit.FindingAbandoned,
			Severity:    audit.SeverityLow,
			Title:       "No recent updates",
			Description: fmt.Sprintf("Last update was %d days ago", int(lastUpdate.Hours()/24)),
			Remediation: "May not receive timely security updates",
		})
	}
}

func checkTapFormulas(result *VetResult, tapName string, cfg VetConfig) {
	// Try to get formula list from the tap
	out, err := exec.Command("brew", "search", "--formula", tapName+"/").Output()
	if err != nil {
		return
	}

	formulas := strings.Fields(string(out))
	result.Metadata.FormulaCount = len(formulas)

	// Check for suspicious formula names (typosquatting popular packages)
	popularPackages := []string{"node", "python", "ruby", "go", "rust", "git", "vim", "wget", "curl", "openssl"}
	for _, formula := range formulas {
		formulaBase := strings.TrimPrefix(formula, tapName+"/")
		for _, popular := range popularPackages {
			if isSimilar(formulaBase, popular) && formulaBase != popular {
				result.Findings = append(result.Findings, audit.Finding{
					Package:     formula,
					Type:        audit.FindingUntrustedTap,
					Severity:    audit.SeverityHigh,
					Title:       "Potential typosquatting",
					Description: fmt.Sprintf("Formula '%s' has similar name to popular package '%s'", formulaBase, popular),
					Remediation: "Verify this is the intended package before installing",
				})
			}
		}
	}

	// Deep scan formula files if verbose mode
	if cfg.Verbose {
		scanTapFormulaFiles(result, tapName, formulas)
	}
}

// scanTapFormulaFiles scans formula files in a tap for suspicious patterns
func scanTapFormulaFiles(result *VetResult, tapName string, formulas []string) {
	prefix, err := brew.GetBrewPrefix()
	if err != nil {
		return
	}

	parts := strings.Split(tapName, "/")
	if len(parts) != 2 {
		return
	}

	tapPath := filepath.Join(prefix, "Homebrew", "Library", "Taps", parts[0], "homebrew-"+parts[1])

	// Check for Formula directory
	formulaDir := filepath.Join(tapPath, "Formula")
	if _, err := os.Stat(formulaDir); os.IsNotExist(err) {
		// Try Formulas (plural)
		formulaDir = filepath.Join(tapPath, "Formulas")
		if _, err := os.Stat(formulaDir); os.IsNotExist(err) {
			return
		}
	}

	// Scan each formula file
	for _, formula := range formulas {
		formulaBase := strings.TrimPrefix(formula, tapName+"/")
		formulaFile := filepath.Join(formulaDir, formulaBase+".rb")

		findings := ScanFormulaFile(formulaFile, formula)
		result.Findings = append(result.Findings, findings...)
	}
}

// DeepScanInstalledFormulas performs a deep scan of all installed formula files
func DeepScanInstalledFormulas(cfg VetConfig) ([]audit.Finding, error) {
	var allFindings []audit.Finding

	prefix, err := brew.GetBrewPrefix()
	if err != nil {
		return nil, fmt.Errorf("could not get brew prefix: %w", err)
	}

	// Scan core formulas
	coreFormulasDir := filepath.Join(prefix, "Homebrew", "Library", "Taps", "homebrew", "homebrew-core", "Formula")
	if _, err := os.Stat(coreFormulasDir); err == nil {
		findings := scanFormulaDirectory(coreFormulasDir, "homebrew/core", cfg)
		allFindings = append(allFindings, findings...)
	}

	// Scan installed taps
	taps, err := brew.GetInstalledTaps()
	if err != nil {
		return allFindings, nil // Continue with what we have
	}

	for _, tap := range taps {
		if tap.Official {
			continue // Skip official taps, focus on third-party
		}

		parts := strings.Split(tap.Name, "/")
		if len(parts) != 2 {
			continue
		}

		tapPath := filepath.Join(prefix, "Homebrew", "Library", "Taps", parts[0], "homebrew-"+parts[1])
		formulaDir := filepath.Join(tapPath, "Formula")
		if _, err := os.Stat(formulaDir); os.IsNotExist(err) {
			formulaDir = filepath.Join(tapPath, "Formulas")
		}

		findings := scanFormulaDirectory(formulaDir, tap.Name, cfg)
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

func scanFormulaDirectory(dir, tapName string, cfg VetConfig) []audit.Finding {
	var findings []audit.Finding

	entries, err := os.ReadDir(dir)
	if err != nil {
		return findings
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rb") {
			continue
		}

		formulaPath := filepath.Join(dir, entry.Name())
		formulaName := tapName + "/" + strings.TrimSuffix(entry.Name(), ".rb")

		if cfg.Verbose {
			fmt.Printf("    Scanning %s...\n", formulaName)
		}

		fileFindings := ScanFormulaFile(formulaPath, formulaName)
		findings = append(findings, fileFindings...)
	}

	return findings
}

func checkUpstreamRepo(result *VetResult, owner, repo, pkgName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo), nil)
	if err != nil {
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     pkgName,
			Type:        audit.FindingDeadURL,
			Severity:    audit.SeverityHigh,
			Title:       "Upstream repository not found",
			Description: fmt.Sprintf("GitHub repository %s/%s no longer exists", owner, repo),
			Remediation: "Source code may not be auditable - consider alternatives",
		})
		return
	}

	var repoInfo struct {
		Archived bool      `json:"archived"`
		PushedAt time.Time `json:"pushed_at"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&repoInfo); err != nil {
		return
	}

	if repoInfo.Archived {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     pkgName,
			Type:        audit.FindingAbandoned,
			Severity:    audit.SeverityMedium,
			Title:       "Upstream is archived",
			Description: "The upstream project has been archived",
			Remediation: "No future updates or security fixes expected",
		})
	}

	if time.Since(repoInfo.PushedAt) > 2*365*24*time.Hour {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     pkgName,
			Type:        audit.FindingAbandoned,
			Severity:    audit.SeverityLow,
			Title:       "Upstream appears inactive",
			Description: fmt.Sprintf("No commits in over 2 years (last: %s)", repoInfo.PushedAt.Format("2006-01-02")),
			Remediation: "May not receive security updates",
		})
	}
}

// isSimilar checks for similar strings (simple Levenshtein-like check)
func isSimilar(a, b string) bool {
	if a == b {
		return false // Exact match doesn't count as "similar"
	}

	// Check for common typosquatting patterns
	a = strings.ToLower(a)
	b = strings.ToLower(b)

	// Single character difference
	if len(a) == len(b) {
		diffs := 0
		for i := range a {
			if a[i] != b[i] {
				diffs++
			}
		}
		if diffs == 1 {
			return true
		}
	}

	// One character added/removed
	if abs(len(a)-len(b)) == 1 {
		shorter, longer := a, b
		if len(a) > len(b) {
			shorter, longer = b, a
		}
		for i := 0; i <= len(shorter); i++ {
			candidate := longer[:i] + longer[i+1:]
			if candidate == shorter {
				return true
			}
		}
	}

	// Common substitutions
	substitutions := map[string]string{
		"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
	}
	normalized := a
	for from, to := range substitutions {
		normalized = strings.ReplaceAll(normalized, from, to)
	}
	if normalized == b {
		return true
	}

	return false
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func calculateRisk(result *VetResult) {
	score := 0

	for _, f := range result.Findings {
		switch f.Severity {
		case audit.SeverityCritical:
			score += 30
		case audit.SeverityHigh:
			score += 20
		case audit.SeverityMedium:
			score += 10
		case audit.SeverityLow:
			score += 5
		case audit.SeverityInfo:
			score += 1
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	result.RiskScore = score

	switch {
	case score >= 70:
		result.RiskLevel = "CRITICAL"
		result.Recommendation = "Do not install - significant security concerns"
	case score >= 50:
		result.RiskLevel = "HIGH"
		result.Recommendation = "Exercise extreme caution - review findings carefully"
	case score >= 25:
		result.RiskLevel = "MEDIUM"
		result.Recommendation = "Proceed with caution - some concerns identified"
	case score >= 10:
		result.RiskLevel = "LOW"
		result.Recommendation = "Minor concerns - generally safe to proceed"
	default:
		result.RiskLevel = "MINIMAL"
		result.Recommendation = "No significant concerns identified"
	}
}

// SuspiciousPatterns to check in formula files
var SuspiciousPatterns = []struct {
	Pattern     *regexp.Regexp
	Description string
	Severity    audit.Severity
}{
	{regexp.MustCompile(`curl.*\|.*sh`), "Piping curl to shell", audit.SeverityHigh},
	{regexp.MustCompile(`wget.*\|.*sh`), "Piping wget to shell", audit.SeverityHigh},
	{regexp.MustCompile(`eval\s*\(`), "Use of eval", audit.SeverityMedium},
	{regexp.MustCompile(`rm\s+-rf\s+/`), "Dangerous recursive delete", audit.SeverityCritical},
	{regexp.MustCompile(`chmod\s+777`), "World-writable permissions", audit.SeverityMedium},
	{regexp.MustCompile(`sudo\s+`), "Use of sudo", audit.SeverityMedium},
	{regexp.MustCompile(`base64\s+-d`), "Base64 decoding (obfuscation)", audit.SeverityMedium},
	{regexp.MustCompile(`\\x[0-9a-fA-F]{2}`), "Hex-encoded strings (obfuscation)", audit.SeverityMedium},
	{regexp.MustCompile(`nc\s+-[el]`), "Netcat listener (backdoor)", audit.SeverityCritical},
	{regexp.MustCompile(`/dev/tcp/`), "Bash TCP socket (backdoor)", audit.SeverityCritical},
	{regexp.MustCompile(`mkfifo.*nc`), "Named pipe with netcat (reverse shell)", audit.SeverityCritical},
	{regexp.MustCompile(`\$\(.*curl.*\)`), "Command substitution with curl", audit.SeverityHigh},
	{regexp.MustCompile(`ENV\[["'].*KEY.*["']\]`), "Accessing environment keys", audit.SeverityLow},
	{regexp.MustCompile(`system\s*\(`), "Direct system call", audit.SeverityMedium},
}

// ScanFormulaContent scans formula file content for suspicious patterns
func ScanFormulaContent(content, formulaName string) []audit.Finding {
	var findings []audit.Finding

	for _, sp := range SuspiciousPatterns {
		if matches := sp.Pattern.FindAllString(content, -1); len(matches) > 0 {
			findings = append(findings, audit.Finding{
				Package:     formulaName,
				Type:        "SUSPICIOUS_CODE",
				Severity:    sp.Severity,
				Title:       fmt.Sprintf("Suspicious pattern: %s", sp.Description),
				Description: fmt.Sprintf("Found %d occurrence(s) of suspicious pattern", len(matches)),
				Remediation: "Review the formula source code carefully before installing",
			})
		}
	}

	return findings
}

// ScanFormulaFile reads and scans a formula file for suspicious patterns
func ScanFormulaFile(formulaPath, formulaName string) []audit.Finding {
	content, err := os.ReadFile(formulaPath)
	if err != nil {
		return nil
	}
	return ScanFormulaContent(string(content), formulaName)
}

// CaskSuspiciousPatterns - patterns to check in cask files
// Casks have different risks since they download .app/.pkg/.dmg files
var CaskSuspiciousPatterns = []struct {
	Pattern     *regexp.Regexp
	Description string
	Severity    audit.Severity
}{
	// Download source risks
	{regexp.MustCompile(`url\s+["']http://`), "Downloads over insecure HTTP", audit.SeverityHigh},
	{regexp.MustCompile(`url\s+["'].*\.(ru|cn|tk|ml|ga|cf)/`), "Download from high-risk TLD", audit.SeverityHigh},
	{regexp.MustCompile(`url\s+["'].*dropbox\.com`), "Downloads from Dropbox (no verification)", audit.SeverityMedium},
	{regexp.MustCompile(`url\s+["'].*drive\.google\.com`), "Downloads from Google Drive (no verification)", audit.SeverityMedium},
	{regexp.MustCompile(`url\s+["'].*mega\.nz`), "Downloads from Mega (common malware host)", audit.SeverityHigh},

	// Checksum risks
	{regexp.MustCompile(`sha256\s+:no_check`), "No SHA256 checksum verification", audit.SeverityCritical},

	// Installer risks
	{regexp.MustCompile(`pkg\s+["'].*\.pkg["']`), "Installs system package (elevated privileges)", audit.SeverityMedium},
	{regexp.MustCompile(`installer\s+script:`), "Uses custom installer script", audit.SeverityHigh},
	{regexp.MustCompile(`preflight\s+do`), "Has preflight script (runs before install)", audit.SeverityMedium},
	{regexp.MustCompile(`postflight\s+do`), "Has postflight script (runs after install)", audit.SeverityMedium},
	{regexp.MustCompile(`uninstall\s+script:`), "Custom uninstall script", audit.SeverityMedium},

	// Permission risks
	{regexp.MustCompile(`accessibility`), "Requests accessibility permissions", audit.SeverityMedium},
	{regexp.MustCompile(`input_monitoring`), "Requests input monitoring (keylogger risk)", audit.SeverityHigh},
	{regexp.MustCompile(`screen_recording`), "Requests screen recording", audit.SeverityMedium},
	{regexp.MustCompile(`full_disk_access`), "Requests full disk access", audit.SeverityHigh},

	// Suspicious behaviors
	{regexp.MustCompile(`launchctl\s+load`), "Loads launch daemon/agent (persistence)", audit.SeverityMedium},
	{regexp.MustCompile(`kextload`), "Loads kernel extension", audit.SeverityHigh},
	{regexp.MustCompile(`/System/`), "Modifies system directories", audit.SeverityHigh},
	{regexp.MustCompile(`/Library/LaunchDaemons`), "Installs system-wide daemon", audit.SeverityMedium},
}

// ScanCaskContent scans cask file content for suspicious patterns
func ScanCaskContent(content, caskName string) []audit.Finding {
	var findings []audit.Finding

	for _, sp := range CaskSuspiciousPatterns {
		if matches := sp.Pattern.FindAllString(content, -1); len(matches) > 0 {
			findings = append(findings, audit.Finding{
				Package:     caskName,
				Type:        audit.FindingSuspiciousCode,
				Severity:    sp.Severity,
				Title:       fmt.Sprintf("Cask risk: %s", sp.Description),
				Description: fmt.Sprintf("Found %d occurrence(s)", len(matches)),
				Remediation: "Review the cask source and verify the download URL is legitimate",
			})
		}
	}

	return findings
}

// ScanCaskFile reads and scans a cask file for suspicious patterns
func ScanCaskFile(caskPath, caskName string) []audit.Finding {
	content, err := os.ReadFile(caskPath)
	if err != nil {
		return nil
	}
	return ScanCaskContent(string(content), caskName)
}

// DeepScanInstalledCasks performs a deep scan of all installed cask files
func DeepScanInstalledCasks(cfg VetConfig) ([]audit.Finding, error) {
	var allFindings []audit.Finding

	prefix, err := brew.GetBrewPrefix()
	if err != nil {
		return nil, fmt.Errorf("could not get brew prefix: %w", err)
	}

	// Scan homebrew/cask (official casks)
	caskDir := filepath.Join(prefix, "Homebrew", "Library", "Taps", "homebrew", "homebrew-cask", "Casks")
	if _, err := os.Stat(caskDir); err == nil {
		findings := scanCaskDirectory(caskDir, "homebrew/cask", cfg)
		allFindings = append(allFindings, findings...)
	}

	// Scan third-party taps for casks
	taps, err := brew.GetInstalledTaps()
	if err != nil {
		return allFindings, nil
	}

	for _, tap := range taps {
		if tap.Official && tap.Name != "homebrew/cask" {
			continue
		}

		parts := strings.Split(tap.Name, "/")
		if len(parts) != 2 {
			continue
		}

		tapPath := filepath.Join(prefix, "Homebrew", "Library", "Taps", parts[0], "homebrew-"+parts[1])
		caskDir := filepath.Join(tapPath, "Casks")
		if _, err := os.Stat(caskDir); os.IsNotExist(err) {
			continue
		}

		findings := scanCaskDirectory(caskDir, tap.Name, cfg)
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

func scanCaskDirectory(dir, tapName string, cfg VetConfig) []audit.Finding {
	var findings []audit.Finding

	entries, err := os.ReadDir(dir)
	if err != nil {
		return findings
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rb") {
			continue
		}

		caskPath := filepath.Join(dir, entry.Name())
		caskName := tapName + "/" + strings.TrimSuffix(entry.Name(), ".rb")

		if cfg.Verbose {
			fmt.Printf("    Scanning cask %s...\n", caskName)
		}

		fileFindings := ScanCaskFile(caskPath, caskName)
		findings = append(findings, fileFindings...)
	}

	return findings
}

// VetCask vets an individual cask
func VetCask(caskToken string, cfg VetConfig) (*VetResult, error) {
	result := &VetResult{
		Target:     caskToken,
		TargetType: "cask",
		Timestamp:  time.Now(),
		Findings:   []audit.Finding{},
	}

	if cfg.Verbose {
		fmt.Printf("  Analyzing cask: %s\n", caskToken)
	}

	// Get cask info
	cask, err := brew.GetCaskInfo(caskToken)
	if err != nil {
		return nil, fmt.Errorf("could not get cask info: %w", err)
	}

	// Check for deprecation
	if cask.Deprecated {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     caskToken,
			Type:        audit.FindingDeprecated,
			Severity:    audit.SeverityMedium,
			Title:       "Cask is deprecated",
			Description: "This cask has been deprecated",
			Remediation: "Find an alternative application",
		})
	}

	if cask.Disabled {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     caskToken,
			Type:        audit.FindingDeprecated,
			Severity:    audit.SeverityHigh,
			Title:       "Cask is disabled",
			Description: "This cask has been disabled and should not be used",
			Remediation: "Find an alternative application",
		})
	}

	// Check URL security
	if brew.IsHTTPURL(cask.URL) {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     caskToken,
			Type:        audit.FindingHTTP,
			Severity:    audit.SeverityHigh,
			Title:       "Cask uses insecure HTTP download",
			Description: "Application downloads over unencrypted HTTP can be tampered with",
			URL:         cask.URL,
			Remediation: "High risk - downloads can be man-in-the-middled",
		})
	}

	// Check for missing checksum
	if cask.Sha256 == "" || cask.Sha256 == "no_check" {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     caskToken,
			Type:        audit.FindingNoChecksum,
			Severity:    audit.SeverityCritical,
			Title:       "No checksum verification",
			Description: "Downloaded application is not verified with SHA256",
			Remediation: "Cannot verify download integrity - high malware risk",
		})
	}

	// Check if it's from a third-party tap
	if cask.Tap != "" && !strings.HasPrefix(cask.Tap, "homebrew/") {
		result.Findings = append(result.Findings, audit.Finding{
			Package:     caskToken,
			Type:        audit.FindingUntrustedTap,
			Severity:    audit.SeverityMedium,
			Title:       "Cask from third-party tap",
			Description: fmt.Sprintf("This cask is from %s, not an official Homebrew tap", cask.Tap),
			Remediation: "Verify you trust the tap maintainer",
		})
	}

	// Check homepage for GitHub and analyze if present
	owner, repo, ok := brew.ExtractGitHubRepo(cask.Homepage)
	if ok {
		checkUpstreamRepo(result, owner, repo, caskToken)
	}

	calculateRisk(result)
	return result, nil
}
