package brew

import "testing"

func TestExpandInstalledKeepsEveryKeg(t *testing.T) {
	base := InstalledPackage{Name: "openssl@3", FullName: "openssl@3"}
	got := expandInstalled(base, []string{"3.0.0", "3.2.1"})
	if len(got) != 2 || got[0].Version != "3.0.0" || got[1].Version != "3.2.1" {
		t.Fatalf("got %+v", got)
	}
	if got[0].Name != "openssl@3" || got[1].FullName != "openssl@3" {
		t.Fatalf("identity not copied: %+v", got)
	}
}

func TestExpandInstalledEmptyVersionStillReported(t *testing.T) {
	got := expandInstalled(InstalledPackage{Name: "wget"}, nil)
	if len(got) != 1 || got[0].Version != "" || got[0].Name != "wget" {
		t.Fatalf("got %+v", got)
	}
}
