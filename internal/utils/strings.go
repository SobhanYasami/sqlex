package utils

import (
	"net/url"
	"regexp"
	"strings"
)

// URLDecode decodes a URL-encoded string.
func URLDecode(s string) string {
	decoded, err := url.QueryUnescape(strings.ReplaceAll(s, "+", "%2B"))
	if err != nil {
		return s
	}
	return decoded
}

// URLEncode URL-encodes a string, with special-character safe set depending on context.
// valueType "payload" uses stricter encoding.
func URLEncode(s, injectionType string, isMultipart bool, isPayload bool) string {
	if s == "" {
		return s
	}
	// Decode first to avoid double-encoding
	decoded, err := url.QueryUnescape(s)
	if err == nil {
		s = decoded
	}
	safe := "/=*?&:;,+"
	if isPayload {
		safe = ""
	}
	var sb strings.Builder
	for _, r := range s {
		c := string(r)
		if strings.ContainsRune(safe, r) || isAlphanumSafe(r) {
			sb.WriteString(c)
		} else {
			sb.WriteString(url.QueryEscape(c))
		}
	}
	return sb.String()
}

func isAlphanumSafe(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
		r == '-' || r == '_' || r == '.' || r == '~'
}

// ToList splits a comma-separated column list.
func ToList(columns string) []string {
	re := regexp.MustCompile(` +`)
	s := re.ReplaceAllString(columns, "")
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

var dbmsDict = map[string]string{
	"mysql":    "MySQL",
	"mssql":   "Microsoft SQL Server",
	"mssqlserver": "Microsoft SQL Server",
	"microsoftsqlserver": "Microsoft SQL Server",
	"pgsql":   "PostgreSQL",
	"postgres": "PostgreSQL",
	"postgresql": "PostgreSQL",
	"oracle":  "Oracle",
	"access":  "Microsoft Access",
	"db2":     "IBM DB2",
	"sqlite":  "SQLite",
	"sybase":  "Sybase",
	"maxdb":   "SAP MaxDB",
	"hsqldb":  "HSQLDB",
	"informix": "Informix",
}

// DBMSFullName converts a short DBMS name to the canonical full name.
func DBMSFullName(dbms string) string {
	if dbms == "" {
		return ""
	}
	if v, ok := dbmsDict[strings.ToLower(dbms)]; ok {
		return v
	}
	return dbms
}

// CleanupOffsetPayload removes LIMIT/OFFSET from a query and adds the given offset.
func CleanupOffsetPayload(query string, offset int) string {
	re := regexp.MustCompile(`(?i)\s+LIMIT\s+\d+\s*,\s*\d+|\s+OFFSET\s+\d+`)
	q := re.ReplaceAllString(query, "")
	return q
}

// DBMSEncoding wraps a query value in DBMS-specific encoding/cast functions.
func DBMSEncoding(value, backend string, isString bool) string {
	switch backend {
	case "MySQL":
		if isString {
			return "CAST(" + value + " AS NCHAR)"
		}
		return value
	case "Microsoft SQL Server":
		if isString {
			return "CAST(" + value + " AS NVARCHAR(4000))"
		}
		return value
	case "PostgreSQL":
		if isString {
			return "CAST(" + value + " AS VARCHAR(10000))"
		}
		return value
	case "Oracle":
		if isString {
			return "CAST(" + value + " AS NVARCHAR2(4000))"
		}
		return value
	}
	return value
}
