package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveCVERejectsBrokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("cve: ["), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BREWSTER_CONFIG", path)
	if _, _, err := ResolveCVE("", ""); err == nil {
		t.Fatal("broken config was ignored")
	}
}

func TestResolveCVERejectsUnknownSource(t *testing.T) {
	t.Setenv("BREWSTER_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	if _, _, err := ResolveCVE("ossv", ""); err == nil {
		t.Fatal("unknown source accepted")
	}
}

func TestResolveCVEMissingFileUsesDefault(t *testing.T) {
	t.Setenv("BREWSTER_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("BREWSTER_CVE_SOURCE", "")
	t.Setenv("NVD_API_KEY", "")
	source, key, err := ResolveCVE("", "")
	if err != nil {
		t.Fatal(err)
	}
	if source != "auto" || key != "" {
		t.Fatalf("source=%q key=%q", source, key)
	}
}
