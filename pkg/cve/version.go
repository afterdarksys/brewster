package cve

import (
	"strconv"
	"strings"
)

type verPart struct {
	n    int
	rest string
}

// versionLess reports whether a < b. ok is false when either side is not a
// dotted version, so callers skip a fix recommendation they cannot order.
func versionLess(a, b string) (less, ok bool) {
	ap, aok := parseVer(a)
	bp, bok := parseVer(b)
	if !aok || !bok {
		return false, false
	}
	n := max(len(ap), len(bp))
	for i := 0; i < n; i++ {
		var x, y verPart
		if i < len(ap) {
			x = ap[i]
		}
		if i < len(bp) {
			y = bp[i]
		}
		if x.n != y.n {
			return x.n < y.n, true
		}
		if x.rest == y.rest {
			continue
		}
		if x.rest == "" {
			return false, true
		}
		if y.rest == "" {
			return true, true
		}
		return x.rest < y.rest, true
	}
	return false, true
}

func parseVer(v string) ([]verPart, bool) {
	if v == "" {
		return nil, false
	}
	var out []verPart
	for _, seg := range strings.Split(v, ".") {
		i := 0
		for i < len(seg) && seg[i] >= '0' && seg[i] <= '9' {
			i++
		}
		if i == 0 {
			return nil, false
		}
		n, err := strconv.Atoi(seg[:i])
		if err != nil {
			return nil, false
		}
		out = append(out, verPart{n: n, rest: seg[i:]})
	}
	return out, true
}
