package sbom

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/afterdarksys/brewster/pkg/brew"
)

// OutputFormat defines the format of the SBOM.
type OutputFormat string

const (
	FormatJSON OutputFormat = "json"
	FormatXML  OutputFormat = "xml"
)

// Builder orchestrates the creation of an SBOM
type Builder struct {
	Namespace string
}

// NewBuilder creates a new SBOM Builder.
func NewBuilder(namespace string) *Builder {
	return &Builder{
		Namespace: namespace,
	}
}

// Generate creates a CycloneDX-like JSON representation of the installed packages.
// For now, this builds a simplified map showing the dependencies and blast radius.
func (b *Builder) Generate(packages []brew.InstalledPackage, format OutputFormat) ([]byte, error) {
	// Build a simple CycloneDX 1.4 template structure
	sbom := map[string]interface{}{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.4",
		"serialNumber": fmt.Sprintf("urn:uuid:brewster-%d", time.Now().Unix()),
		"version":      1,
		"metadata": map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools": []map[string]interface{}{
				{
					"vendor": "AfterDark Security Suite",
					"name":   "Brewster",
				},
			},
		},
		"components": []map[string]interface{}{},
		"dependencies": []map[string]interface{}{},
	}

	components := []map[string]interface{}{}
	dependencyGraph := make(map[string][]string)
	
	for _, pkg := range packages {
		comp := map[string]interface{}{
			"type":    "application",
			"bom-ref": fmt.Sprintf("pkg:brew/%s@%s", pkg.Name, pkg.Version),
			"name":    pkg.Name,
			"version": pkg.Version,
		}
		components = append(components, comp)

		// Mocking dependencies extracting for now. 
		// In a real implementation we would run `brew deps --installed`
		// and parse the directed graph.
		deps := []string{}
		if pkg.Name == "openssl@3" || pkg.Name == "xz" {
			// Mocking wide blast-radius targets
			deps = []string{"python@3.11", "wget", "curl", "git"}
		}
		
		depEntry := map[string]interface{}{
			"ref": fmt.Sprintf("pkg:brew/%s@%s", pkg.Name, pkg.Version),
			"dependsOn": formatDeps(deps),
		}
		sbom["dependencies"] = append(sbom["dependencies"].([]map[string]interface{}), depEntry)
		dependencyGraph[pkg.Name] = deps
	}

	sbom["components"] = components

	if format == FormatJSON {
		return json.MarshalIndent(sbom, "", "  ")
	}

	return nil, fmt.Errorf("format %s not yet implemented", format)
}

// formatDeps is a helper to turn package names into purls
func formatDeps(names []string) []string {
	var purls []string
	for _, n := range names {
		// Just mocking a version tag for the dependson array
		purls = append(purls, fmt.Sprintf("pkg:brew/%s@unknown", n))
	}
	return purls
}

// CalculateBlastRadius determines which downstream packages would be compromised
// if the target package was compromised.
func CalculateBlastRadius(targetPkg string, allPackages []brew.InstalledPackage) []string {
	// A real implementation would parse the Homebrew dependency tree (e.g. `brew uses --installed targetPkg`)
	
	// Mock: if target is a core lib, say everything depends on it.
	if targetPkg == "openssl" || targetPkg == "openssl@3" || targetPkg == "xz" {
		return []string{"git", "curl", "python@3.11", "wget", "node"}
	}
	return []string{}
}
