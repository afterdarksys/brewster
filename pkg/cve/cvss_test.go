package cve

import (
	"math"
	"testing"
)

func TestCVSSV3BaseScore(t *testing.T) {
	// Canonical 9.8 CRITICAL vector (network, no auth, full impact).
	if got, ok := cvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"); !ok || math.Abs(got-9.8) > 0.05 {
		t.Errorf("critical vector = %.2f ok=%v, want 9.8", got, ok)
	}
	// A 3.0 vector should parse too.
	if _, ok := cvssV3BaseScore("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"); !ok {
		t.Error("v3.0 vector should parse")
	}
	// Non-vectors return ok=false so callers can fall back to a label.
	for _, bad := range []string{"", "7.5", "not a vector", "CVSS:2.0/AV:N"} {
		if _, ok := cvssV3BaseScore(bad); ok {
			t.Errorf("%q should not parse as a v3 vector", bad)
		}
	}
}

func TestSeverityFromCVSSVector(t *testing.T) {
	// Vector strings (not numeric) must now grade correctly instead of Unknown.
	cases := map[string]Severity{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": SeverityCritical, // 9.8
		"CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H": SeverityHigh,     // gh advisory, ~8.0
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N": SeverityLow,      // 3.3
	}
	for vec, want := range cases {
		if got := severityFromCVSS(vec); got != want {
			t.Errorf("severityFromCVSS(%q) = %q, want %q", vec, got, want)
		}
	}
	// A numeric score still works; an empty/garbage value is Unknown.
	if severityFromCVSS("9.1") != SeverityCritical {
		t.Error("numeric 9.1 should be critical")
	}
	if severityFromCVSS("garbage") != SeverityUnknown {
		t.Error("garbage should be unknown")
	}
}
