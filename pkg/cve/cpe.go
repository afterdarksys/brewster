package cve

import "strings"

// cpeCoord is an NVD application CPE (part "a"). Formulae missing from
// curatedCPE are not queried. nginx is listed three times because NVD renamed it.
type cpeCoord struct {
	Vendor  string
	Product string
}

var curatedCPE = map[string][]cpeCoord{
	"bash":       {{"gnu", "bash"}},
	"binutils":   {{"gnu", "binutils"}},
	"containerd": {{"linuxfoundation", "containerd"}},
	"curl":       {{"haxx", "curl"}},
	"docker":     {{"docker", "docker"}},
	"expat":      {{"libexpat", "expat"}},
	"ffmpeg":     {{"ffmpeg", "ffmpeg"}},
	"freetype":   {{"freetype", "freetype"}},
	"gcc":        {{"gnu", "gcc"}},
	"gettext":    {{"gnu", "gettext"}},
	"git":        {{"git-scm", "git"}},
	"gnupg":      {{"gnupg", "gnupg"}},
	"go":         {{"golang", "go"}},
	"gzip":       {{"gnu", "gzip"}},
	"httpd":      {{"apache", "http_server"}},
	"libpng":     {{"libpng", "libpng"}},
	"libressl":   {{"openbsd", "libressl"}},
	"libxml2":    {{"xmlsoft", "libxml2"}},
	"nginx":      {{"f5", "nginx_open_source"}, {"f5", "nginx"}, {"nginx", "nginx"}},
	"node":       {{"nodejs", "node.js"}},
	"openssh":    {{"openbsd", "openssh"}},
	"openssl":    {{"openssl", "openssl"}},
	"pcre2":      {{"pcre", "pcre2"}},
	"perl":       {{"perl", "perl"}},
	"php":        {{"php", "php"}},
	"postgresql": {{"postgresql", "postgresql"}},
	"python":     {{"python", "python"}},
	"redis":      {{"redis", "redis"}},
	"ruby":       {{"ruby-lang", "ruby"}},
	"runc":       {{"linuxfoundation", "runc"}},
	"sqlite":     {{"sqlite", "sqlite"}},
	"tar":        {{"gnu", "tar"}},
	"vim":        {{"vim", "vim"}},
	"wget":       {{"gnu", "wget"}},
	"xz":         {{"tukaani", "xz"}},
	"zlib":       {{"zlib", "zlib"}},
}

// escapeCPE quotes a CPE 2.3 attribute. ":" would shift fields; "*" would become a wildcard.
func escapeCPE(s string) string {
	const specials = `!"#$%&'()+,/:;<=>?@[\]^` + "`" + `{|}~*`
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\\' || r == ' ' || strings.ContainsRune(specials, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
