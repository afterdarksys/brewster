package cve

import (
	"math"
	"strings"
)

// cvssV3BaseScore computes the CVSS v3.0/v3.1 base score from a vector string
// (e.g. "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H"). It implements the FIRST
// CVSS v3.1 specification, including the spec's Roundup. Returns ok=false if the
// string is not a parseable v3 vector, so callers can fall back to a label.
func cvssV3BaseScore(vector string) (float64, bool) {
	vector = strings.TrimSpace(vector)
	if !strings.HasPrefix(vector, "CVSS:3") {
		return 0, false
	}

	m := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}

	av, ok1 := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac, ok2 := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui, ok3 := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	scope := m["S"]

	// Privileges Required weights depend on Scope.
	var pr float64
	var ok4 bool
	if scope == "C" {
		pr, ok4 = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	} else {
		pr, ok4 = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	}

	conf, ok5 := impactMetric(m["C"])
	integ, ok6 := impactMetric(m["I"])
	avail, ok7 := impactMetric(m["A"])

	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) || (scope != "U" && scope != "C") {
		return 0, false
	}

	iss := 1 - ((1 - conf) * (1 - integ) * (1 - avail))
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui
	var base float64
	if scope == "U" {
		base = roundUp1(math.Min(impact+exploitability, 10))
	} else {
		base = roundUp1(math.Min(1.08*(impact+exploitability), 10))
	}
	return base, true
}

func impactMetric(v string) (float64, bool) {
	f, ok := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[v]
	return f, ok
}

// roundUp1 is the CVSS v3.1 Roundup function (round up to one decimal place),
// implemented with integer math to avoid floating-point edge cases.
func roundUp1(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
