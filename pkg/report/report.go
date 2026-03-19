package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/afterdarksys/brewster/pkg/audit"
	"github.com/afterdarksys/brewster/pkg/monitor"
	"github.com/afterdarksys/brewster/pkg/vetting"
	"gopkg.in/yaml.v3"
)

// CombinedReport holds results from multiple scans
type CombinedReport struct {
	Audit   *audit.AuditResult       `json:"audit,omitempty"`
	Vetting []*vetting.VetResult     `json:"vetting,omitempty"`
	Monitor *monitor.CVEResult       `json:"monitor,omitempty"`
}

// Output renders results in the specified format
func Output(data interface{}, format string) error {
	switch strings.ToLower(format) {
	case "json":
		return outputJSON(data)
	case "yaml", "yml":
		return outputYAML(data)
	case "table", "text", "":
		return outputTable(data)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func outputJSON(data interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func outputYAML(data interface{}) error {
	return yaml.NewEncoder(os.Stdout).Encode(data)
}

func outputTable(data interface{}) error {
	switch v := data.(type) {
	case *audit.AuditResult:
		return printAuditResult(v)
	case *vetting.VetResult:
		return printVetResult(v)
	case []*vetting.VetResult:
		for _, r := range v {
			if err := printVetResult(r); err != nil {
				return err
			}
			fmt.Println()
		}
		return nil
	case *monitor.CVEResult:
		return printCVEResult(v)
	case *monitor.TapAnalysisResult:
		return printTapAnalysisResult(v)
	case CombinedReport:
		return printCombinedReport(v)
	default:
		// Fallback to JSON
		return outputJSON(data)
	}
}

func printAuditResult(r *audit.AuditResult) error {
	fmt.Printf("\n📋 Audit Results\n")
	fmt.Printf("================\n")
	fmt.Printf("Scanned: %d packages, %d taps\n", r.PackagesScanned, r.TapsScanned)
	fmt.Printf("Time: %s\n\n", r.Timestamp.Format("2006-01-02 15:04:05"))

	if len(r.Findings) == 0 {
		fmt.Println("✅ No security issues found!")
		return nil
	}

	// Group by severity
	fmt.Printf("Summary: %d critical, %d high, %d medium, %d low, %d info\n\n",
		r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info)

	printFindings(r.Findings)
	return nil
}

func printVetResult(r *vetting.VetResult) error {
	fmt.Printf("\n🔍 Vetting Report: %s\n", r.Target)
	fmt.Printf("================================\n")
	fmt.Printf("Type: %s\n", r.TargetType)
	fmt.Printf("Risk Score: %d/100\n", r.RiskScore)
	fmt.Printf("Risk Level: %s\n", colorRisk(r.RiskLevel))
	fmt.Printf("Recommendation: %s\n\n", r.Recommendation)

	if r.TargetType == "tap" && r.Metadata.Name != "" {
		fmt.Printf("Repository Info:\n")
		fmt.Printf("  ⭐ Stars: %d\n", r.Metadata.Stars)
		fmt.Printf("  🍴 Forks: %d\n", r.Metadata.Forks)
		fmt.Printf("  📅 Created: %s\n", r.Metadata.CreatedAt.Format("2006-01-02"))
		fmt.Printf("  📝 Last Update: %s\n", r.Metadata.UpdatedAt.Format("2006-01-02"))
		fmt.Printf("  📦 Formulas: %d\n\n", r.Metadata.FormulaCount)
	}

	if len(r.Findings) == 0 {
		fmt.Println("✅ No concerns identified!")
		return nil
	}

	printFindings(r.Findings)
	return nil
}

func printCVEResult(r *monitor.CVEResult) error {
	fmt.Printf("\n🛡️  CVE Check Results\n")
	fmt.Printf("====================\n")
	fmt.Printf("Packages Checked: %d\n", r.PackagesChecked)
	fmt.Printf("Vulnerabilities Found: %d\n\n", r.VulnCount)

	if r.VulnCount == 0 {
		fmt.Println("✅ No known vulnerabilities found!")
		return nil
	}

	for _, v := range r.Vulnerabilities {
		icon := severityIcon(v.Severity)
		fmt.Printf("%s [%s] %s @ %s\n", icon, v.Severity, v.Package, v.Version)
		fmt.Printf("   CVE: %s\n", v.CVEID)
		if v.Summary != "" {
			// Truncate long summaries
			summary := v.Summary
			if len(summary) > 100 {
				summary = summary[:97] + "..."
			}
			fmt.Printf("   %s\n", summary)
		}
		if v.FixedIn != "" {
			fmt.Printf("   Fixed in: %s\n", v.FixedIn)
		}
		if v.Reference != "" {
			fmt.Printf("   Ref: %s\n", v.Reference)
		}
		fmt.Println()
	}

	return nil
}

func printTapAnalysisResult(r *monitor.TapAnalysisResult) error {
	fmt.Printf("\n🔎 Tap Analysis Results\n")
	fmt.Printf("========================\n")
	fmt.Printf("Taps Analyzed: %d\n\n", r.TapsAnalyzed)

	if len(r.Findings) == 0 {
		fmt.Println("✅ No concerns with installed taps!")
		return nil
	}

	for _, f := range r.Findings {
		icon := severityIcon(f.Severity)
		fmt.Printf("%s [%s] %s\n", icon, f.Type, f.Tap)
		fmt.Printf("   %s\n\n", f.Description)
	}

	return nil
}

func printCombinedReport(r CombinedReport) error {
	fmt.Println("\n🍺 Brewster Comprehensive Report")
	fmt.Println("=================================")

	if r.Audit != nil {
		printAuditResult(r.Audit)
	}

	if len(r.Vetting) > 0 {
		fmt.Println("\n--- Tap Vetting ---")
		for _, v := range r.Vetting {
			printVetResult(v)
		}
	}

	if r.Monitor != nil {
		printCVEResult(r.Monitor)
	}

	// Overall summary
	fmt.Println("\n=================================")
	fmt.Println("📊 Overall Summary")

	totalFindings := 0
	criticalCount := 0
	highCount := 0

	if r.Audit != nil {
		totalFindings += r.Audit.Summary.Total
		criticalCount += r.Audit.Summary.Critical
		highCount += r.Audit.Summary.High
	}

	for _, v := range r.Vetting {
		totalFindings += len(v.Findings)
		for _, f := range v.Findings {
			if f.Severity == audit.SeverityCritical {
				criticalCount++
			} else if f.Severity == audit.SeverityHigh {
				highCount++
			}
		}
	}

	if r.Monitor != nil {
		totalFindings += r.Monitor.VulnCount
		for _, v := range r.Monitor.Vulnerabilities {
			if v.Severity == audit.SeverityCritical {
				criticalCount++
			} else if v.Severity == audit.SeverityHigh {
				highCount++
			}
		}
	}

	fmt.Printf("Total Findings: %d\n", totalFindings)
	fmt.Printf("Critical: %d | High: %d\n", criticalCount, highCount)

	if criticalCount > 0 {
		fmt.Println("\n🚨 CRITICAL issues require immediate attention!")
	} else if highCount > 0 {
		fmt.Println("\n⚠️  HIGH severity issues should be reviewed.")
	} else if totalFindings > 0 {
		fmt.Println("\n📝 Review findings and address as appropriate.")
	} else {
		fmt.Println("\n✅ Your Homebrew installation looks secure!")
	}

	return nil
}

func printFindings(findings []audit.Finding) {
	// Sort by severity
	bySeverity := map[audit.Severity][]audit.Finding{}
	for _, f := range findings {
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
	}

	severityOrder := []audit.Severity{
		audit.SeverityCritical,
		audit.SeverityHigh,
		audit.SeverityMedium,
		audit.SeverityLow,
		audit.SeverityInfo,
	}

	for _, sev := range severityOrder {
		fs, ok := bySeverity[sev]
		if !ok || len(fs) == 0 {
			continue
		}

		for _, f := range fs {
			icon := severityIcon(f.Severity)
			fmt.Printf("%s [%s] %s\n", icon, f.Severity, f.Title)
			fmt.Printf("   Package: %s\n", f.Package)
			if f.Description != "" {
				fmt.Printf("   %s\n", f.Description)
			}
			if f.CVE != "" {
				fmt.Printf("   CVE: %s\n", f.CVE)
			}
			if f.URL != "" {
				fmt.Printf("   URL: %s\n", f.URL)
			}
			if f.Remediation != "" {
				fmt.Printf("   💡 %s\n", f.Remediation)
			}
			fmt.Println()
		}
	}
}

func severityIcon(s audit.Severity) string {
	switch s {
	case audit.SeverityCritical:
		return "🔴"
	case audit.SeverityHigh:
		return "🟠"
	case audit.SeverityMedium:
		return "🟡"
	case audit.SeverityLow:
		return "🔵"
	case audit.SeverityInfo:
		return "⚪"
	default:
		return "❓"
	}
}

func colorRisk(level string) string {
	switch level {
	case "CRITICAL":
		return "🔴 CRITICAL"
	case "HIGH":
		return "🟠 HIGH"
	case "MEDIUM":
		return "🟡 MEDIUM"
	case "LOW":
		return "🔵 LOW"
	case "MINIMAL":
		return "🟢 MINIMAL"
	default:
		return level
	}
}
