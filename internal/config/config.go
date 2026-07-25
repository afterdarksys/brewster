package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// AuditConfig holds configuration for local audits
type AuditConfig struct {
	CheckCVE       bool
	CheckAbandoned bool
	CheckHTTP      bool
	Verbose        bool

	// CVE matching
	CVESource string // "auto" (default) | "osv" | "nvd" | "both"
	NVDAPIKey string

	// DarkAPI integration
	SubmitToDarkAPI bool
	DarkAPIURL      string
	DarkAPIKey      string
}

// fileConfig is the on-disk config schema (optional).
type fileConfig struct {
	CVE struct {
		Source    string `yaml:"source"`
		NVDAPIKey string `yaml:"nvd_api_key"`
	} `yaml:"cve"`
}

// configPath returns the config file location: $BREWSTER_CONFIG if set,
// else ~/.config/brewster/config.yaml.
func configPath() string {
	if p := strings.TrimSpace(os.Getenv("BREWSTER_CONFIG")); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "brewster", "config.yaml")
}

// loadFile reads the optional config file. A missing file is not an error.
func loadFile() fileConfig {
	var fc fileConfig
	path := configPath()
	if path == "" {
		return fc
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fc // absent/unreadable -> defaults
	}
	_ = yaml.Unmarshal(data, &fc)
	return fc
}

// ResolveCVE determines the CVE source and NVD API key.
// Precedence (highest first): explicit flag value, environment variable,
// config file, built-in default ("auto"). Empty flag values are ignored so
// they don't clobber env/file settings.
func ResolveCVE(flagSource, flagKey string) (source, nvdKey string) {
	fc := loadFile()

	source = firstNonEmpty(
		flagSource,
		os.Getenv("BREWSTER_CVE_SOURCE"),
		fc.CVE.Source,
		"auto",
	)
	nvdKey = firstNonEmpty(
		flagKey,
		os.Getenv("NVD_API_KEY"),
		fc.CVE.NVDAPIKey,
	)
	return strings.ToLower(strings.TrimSpace(source)), strings.TrimSpace(nvdKey)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
