package main

import (
	"fmt"
	"os"

	"github.com/afterdarktech/brewster/internal/config"
	"github.com/afterdarktech/brewster/pkg/audit"
	"github.com/afterdarktech/brewster/pkg/brew"
	"github.com/afterdarktech/brewster/pkg/monitor"
	"github.com/afterdarktech/brewster/pkg/report"
	"github.com/afterdarktech/brewster/pkg/sbom"
	"github.com/afterdarktech/brewster/pkg/vetting"
	"github.com/spf13/cobra"
)

var (
	version   = "0.1.0"
	outputFmt string
	verbose   bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "brewster",
		Short: "Security scanner for the Homebrew ecosystem",
		Long: `Brewster - Find and flag security incidents in the Homebrew ecosystem.

Detect bad distributors, abandoned projects, supply chain risks, and more.`,
		Version: version,
	}

	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "table", "Output format: table, json, yaml")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Subcommands
	rootCmd.AddCommand(auditCmd())
	rootCmd.AddCommand(vetCmd())
	rootCmd.AddCommand(monitorCmd())
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(deepScanCmd())
	rootCmd.AddCommand(caskScanCmd())
	rootCmd.AddCommand(vetCaskCmd())
	rootCmd.AddCommand(sbomCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// auditCmd - scan local brew installation
func auditCmd() *cobra.Command {
	var checkCVE bool
	var checkAbandoned bool
	var checkHTTP bool
	var submitToDarkAPI bool
	var darkAPIURL string
	var darkAPIKey string

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit your local Homebrew installation",
		Long:  `Scan installed packages and taps for security issues.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get API key from env if not provided via flag
			if darkAPIKey == "" {
				darkAPIKey = os.Getenv("DARKAPI_KEY")
			}
			if darkAPIURL == "" {
				darkAPIURL = os.Getenv("DARKAPI_URL")
			}

			cfg := config.AuditConfig{
				CheckCVE:        checkCVE,
				CheckAbandoned:  checkAbandoned,
				CheckHTTP:       checkHTTP,
				Verbose:         verbose,
				SubmitToDarkAPI: submitToDarkAPI,
				DarkAPIURL:      darkAPIURL,
				DarkAPIKey:      darkAPIKey,
			}

			results, err := audit.RunLocalAudit(cfg)
			if err != nil {
				return fmt.Errorf("audit failed: %w", err)
			}

			return report.Output(results, outputFmt)
		},
	}

	cmd.Flags().BoolVar(&checkCVE, "cve", true, "Check for known CVEs")
	cmd.Flags().BoolVar(&checkAbandoned, "abandoned", true, "Check for abandoned upstream projects")
	cmd.Flags().BoolVar(&checkHTTP, "http", true, "Flag packages using HTTP instead of HTTPS")
	cmd.Flags().BoolVar(&submitToDarkAPI, "submit", false, "Submit CVE findings to DarkAPI")
	cmd.Flags().StringVar(&darkAPIURL, "darkapi-url", "", "DarkAPI URL (default from DARKAPI_URL env)")
	cmd.Flags().StringVar(&darkAPIKey, "darkapi-key", "", "DarkAPI API key (default from DARKAPI_KEY env)")

	return cmd
}

// vetCmd - vet a tap or formula before installing
func vetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vet [tap/formula]",
		Short: "Vet a tap or formula before installing",
		Long: `Analyze a tap or formula for security risks before installation.

Examples:
  brewster vet homebrew/cask
  brewster vet user/tap/formula`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			results, err := vetting.VetTarget(args[0], vetting.VetConfig{
				Verbose: verbose,
			})
			if err != nil {
				return fmt.Errorf("vetting failed: %w", err)
			}

			return report.Output(results, outputFmt)
		},
	}

	return cmd
}

// monitorCmd - ecosystem monitoring
func monitorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Monitor the Homebrew ecosystem for threats",
		Long:  `Gather intelligence on Homebrew packages, CVEs, and suspicious activity.`,
	}

	cmd.AddCommand(monitorCVECmd())
	cmd.AddCommand(monitorTapsCmd())

	return cmd
}

func monitorCVECmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cve",
		Short: "Check ecosystem for CVE-affected packages",
		RunE: func(cmd *cobra.Command, args []string) error {
			results, err := monitor.CheckCVEs(monitor.Config{Verbose: verbose})
			if err != nil {
				return fmt.Errorf("CVE check failed: %w", err)
			}
			return report.Output(results, outputFmt)
		},
	}
}

func monitorTapsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "taps",
		Short: "Analyze third-party taps for suspicious activity",
		RunE: func(cmd *cobra.Command, args []string) error {
			results, err := monitor.AnalyzeTaps(monitor.Config{Verbose: verbose})
			if err != nil {
				return fmt.Errorf("tap analysis failed: %w", err)
			}
			return report.Output(results, outputFmt)
		},
	}
}

// scanCmd - full comprehensive scan
func scanCmd() *cobra.Command {
	var submitToDarkAPI bool
	var darkAPIURL string
	var darkAPIKey string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a comprehensive security scan",
		Long:  `Performs full audit, vetting of installed taps, and ecosystem checks.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get API key from env if not provided via flag
			if darkAPIKey == "" {
				darkAPIKey = os.Getenv("DARKAPI_KEY")
			}
			if darkAPIURL == "" {
				darkAPIURL = os.Getenv("DARKAPI_URL")
			}

			fmt.Println("🍺 Brewster Comprehensive Security Scan")
			fmt.Println("========================================")

			// Run local audit
			fmt.Println("\n[1/3] Auditing local installation...")
			auditResults, err := audit.RunLocalAudit(config.AuditConfig{
				CheckCVE:        true,
				CheckAbandoned:  true,
				CheckHTTP:       true,
				Verbose:         verbose,
				SubmitToDarkAPI: submitToDarkAPI,
				DarkAPIURL:      darkAPIURL,
				DarkAPIKey:      darkAPIKey,
			})
			if err != nil {
				fmt.Printf("  ⚠️  Audit error: %v\n", err)
			}

			// Vet installed taps
			fmt.Println("\n[2/3] Vetting installed taps...")
			vetResults, err := vetting.VetInstalledTaps(vetting.VetConfig{Verbose: verbose})
			if err != nil {
				fmt.Printf("  ⚠️  Vetting error: %v\n", err)
			}

			// Ecosystem check
			fmt.Println("\n[3/3] Checking ecosystem intelligence...")
			monitorResults, err := monitor.CheckCVEs(monitor.Config{Verbose: verbose})
			if err != nil {
				fmt.Printf("  ⚠️  Monitor error: %v\n", err)
			}

			// Combine results
			combined := report.CombinedReport{
				Audit:   auditResults,
				Vetting: vetResults,
				Monitor: monitorResults,
			}

			fmt.Println("\n========================================")
			return report.Output(combined, outputFmt)
		},
	}

	cmd.Flags().BoolVar(&submitToDarkAPI, "submit", false, "Submit CVE findings to DarkAPI")
	cmd.Flags().StringVar(&darkAPIURL, "darkapi-url", "", "DarkAPI URL (default from DARKAPI_URL env)")
	cmd.Flags().StringVar(&darkAPIKey, "darkapi-key", "", "DarkAPI API key (default from DARKAPI_KEY env)")

	return cmd
}

// deepScanCmd - deep scan formula files for suspicious patterns
func deepScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "deep-scan",
		Short: "Deep scan formula files for suspicious code patterns",
		Long: `Scan Homebrew formula source files for potentially malicious patterns.

This scans the actual Ruby formula files for:
- Piped curl/wget to shell (curl | sh)
- Eval usage and obfuscation techniques
- Base64/hex-encoded payloads
- Backdoor patterns (netcat listeners, /dev/tcp)
- Dangerous file operations (rm -rf /)
- Direct system calls`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("🔬 Brewster Deep Scan - Formula Code Analysis")
			fmt.Println("=============================================")

			findings, err := vetting.DeepScanInstalledFormulas(vetting.VetConfig{Verbose: verbose})
			if err != nil {
				return fmt.Errorf("deep scan failed: %w", err)
			}

			if len(findings) == 0 {
				fmt.Println("\n✅ No suspicious patterns detected in formula files")
				return nil
			}

			fmt.Printf("\n⚠️  Found %d suspicious patterns\n\n", len(findings))
			return report.Output(findings, outputFmt)
		},
	}
}

// caskScanCmd - deep scan cask files for suspicious patterns
func caskScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cask-scan",
		Short: "Deep scan cask files for suspicious patterns",
		Long: `Scan Homebrew cask files for potentially risky behaviors.

This scans cask definition files for:
- Insecure HTTP downloads
- Downloads from high-risk sources (Dropbox, Google Drive, Mega)
- Missing SHA256 checksums
- Custom installer/uninstaller scripts
- Pre/post-flight scripts
- Dangerous permission requests (input monitoring, full disk access)
- Launch daemon installation
- Kernel extension loading`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("🍺 Brewster Cask Scan - Application Risk Analysis")
			fmt.Println("================================================")

			findings, err := vetting.DeepScanInstalledCasks(vetting.VetConfig{Verbose: verbose})
			if err != nil {
				return fmt.Errorf("cask scan failed: %w", err)
			}

			if len(findings) == 0 {
				fmt.Println("\n✅ No suspicious patterns detected in cask files")
				return nil
			}

			fmt.Printf("\n⚠️  Found %d risk indicators\n\n", len(findings))
			return report.Output(findings, outputFmt)
		},
	}
}

// vetCaskCmd - vet a specific cask before installing
func vetCaskCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "vet-cask [cask]",
		Short: "Vet a cask before installing",
		Long: `Analyze a cask for security risks before installation.

Examples:
  brewster vet-cask google-chrome
  brewster vet-cask --cask vlc`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("🔍 Vetting cask: %s\n", args[0])
			fmt.Println("========================")

			result, err := vetting.VetCask(args[0], vetting.VetConfig{
				Verbose: verbose,
			})
			if err != nil {
				return fmt.Errorf("cask vetting failed: %w", err)
			}

			return report.Output(result, outputFmt)
		},
	}
}

// sbomCmd - generate a Software Bill of Materials
func sbomCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sbom",
		Short: "Generate a CycloneDX SBOM for the local installation",
		Long:  `Maps out all installed packages and generates a dependency graph/blast-radius analysis in CycloneDX format.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			packages, err := brew.GetInstalledFormulae()
			if err != nil {
				return fmt.Errorf("failed to get installed packages: %w", err)
			}

			builder := sbom.NewBuilder("brewster")
			out, err := builder.Generate(packages, sbom.FormatJSON)
			if err != nil {
				return fmt.Errorf("failed to generate sbom: %w", err)
			}
			
			fmt.Println(string(out))
			return nil
		},
	}
}
