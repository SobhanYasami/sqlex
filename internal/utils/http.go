package utils

import (
	"regexp"
	"strings"

	"github.com/SobhanYasami/sqlex/internal/payloads"
	"github.com/SobhanYasami/sqlex/internal/request"
)

var (
	reScript  = regexp.MustCompile(`(?si)<script[^>]*>.*?</script>`)
	reStyle   = regexp.MustCompile(`(?si)<style[^>]*>.*?</style>`)
	reComment = regexp.MustCompile(`(?si)<!--.*?-->`)
	reTag     = regexp.MustCompile(`<[^>]+>`)
	reWS      = regexp.MustCompile(`\s{2,}`)
	reTabs    = regexp.MustCompile(`[\t\n\r]`)
)

// FilterHTML strips script/style/comment/tag content from an HTML page.
// If textOnly, also strips all remaining HTML tags.
func FilterHTML(page string, textOnly bool) string {
	s := reScript.ReplaceAllString(page, " ")
	s = reStyle.ReplaceAllString(s, " ")
	s = reComment.ReplaceAllString(s, " ")
	if textOnly {
		s = reTag.ReplaceAllString(s, " ")
	}
	s = reTabs.ReplaceAllString(s, " ")
	s = reWS.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// SequenceRatio computes a similarity ratio between two strings using
// set-intersection of tokens, approximating Python's SequenceMatcher.quick_ratio.
func SequenceRatio(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if a == "" && b == "" {
		return 1.0
	}
	if a == "" || b == "" {
		return 0.0
	}
	// Character-level bigrams for better sensitivity than word tokens.
	bigrams := func(s string) map[string]int {
		m := make(map[string]int, len(s))
		for i := 0; i < len(s)-1; i++ {
			k := s[i : i+2]
			m[k]++
		}
		return m
	}
	ba := bigrams(a)
	bb := bigrams(b)
	matches := 0
	for k, ca := range ba {
		if cb, ok := bb[k]; ok {
			if ca < cb {
				matches += ca
			} else {
				matches += cb
			}
		}
	}
	total := len(a) + len(b) - 2
	if total == 0 {
		return 1.0
	}
	ratio := float64(2*matches) / float64(total)
	// round to 3 decimal places
	return float64(int(ratio*1000+0.5)) / 1000
}

// BooleanCheckResult is the output of CheckBooleanResponses.
type BooleanCheckResult struct {
	Vulnerable    bool
	Case          string
	Difference    string
	String        string
	NotString     string
	StatusCode    int
	ContentLength int64
}

// CheckBooleanResponses implements the 6-case boolean injection detection.
// Callers pass RunState fields explicitly to avoid import cycles.
func CheckBooleanResponses(
	base, attackTrue, attackFalse *request.HTTPResponse,
	code int,
	matchString, notMatchString string,
	textOnly bool,
	matchRatio *float64,
	boolCheckOnCT bool,
	boolCTT, boolCTF *int64,
	matchRatioCheck *bool,
	cases []string,
) BooleanCheckResult {
	res := BooleanCheckResult{}

	var w0, w1, w2 string
	if textOnly {
		w0 = FilterHTML(base.FilteredText, true)
		w1 = FilterHTML(attackTrue.FilteredText, true)
		w2 = FilterHTML(attackFalse.FilteredText, true)
	} else {
		w0 = base.Text
		w1 = attackTrue.Text
		w2 = attackFalse.Text
	}

	ratioTrue := SequenceRatio(w0, w1)
	ratioFalse := SequenceRatio(w0, w2)

	if *matchRatio == 0 {
		if ratioFalse >= 0.02 && ratioFalse <= 0.98 {
			*matchRatio = ratioFalse
		}
	}

	scb := base.StatusCode
	sct := attackTrue.StatusCode
	scf := attackFalse.StatusCode
	ctb := base.ContentLength
	ctt := attackTrue.ContentLength
	ctf := attackFalse.ContentLength

	var detectedCases []string

	if code != 0 {
		if code == sct || code == scf {
			res.Vulnerable = true
			res.StatusCode = code
			detectedCases = append(detectedCases, "Status code")
		}
	} else if matchString != "" {
		re := regexp.MustCompile(`(?is)` + regexp.QuoteMeta(matchString))
		if re.MatchString(w1) {
			res.Vulnerable = true
			res.Difference = matchString
			res.String = matchString
			res.NotString = notMatchString
			detectedCases = append(detectedCases, "Page Content")
		} else {
			diff := pageDiff(w1, w2)
			if diff != "" {
				res.Vulnerable = true
				res.Difference = diff
				res.String = diff
				detectedCases = append(detectedCases, "Page Content")
			}
		}
	} else if notMatchString != "" {
		re := regexp.MustCompile(`(?is)` + regexp.QuoteMeta(notMatchString))
		if re.MatchString(w2) {
			res.Vulnerable = true
			res.Difference = notMatchString
			res.NotString = notMatchString
			res.String = matchString
			detectedCases = append(detectedCases, "Page Content")
		}
	} else {
		if boolCheckOnCT {
			if ctt != ctf && ctb == ctt {
				res.Vulnerable = true
				res.ContentLength = ctt
				detectedCases = append(detectedCases, "Content Length")
			} else if ctt != ctf && ctb == ctf {
				res.Vulnerable = true
				res.ContentLength = ctf
				detectedCases = append(detectedCases, "Content Length")
			}
		}
		if ratioTrue != ratioFalse {
			detectedCases = append(detectedCases, "Page Ratio")
			res.Vulnerable = true
		}
		if scb == sct && scb != scf {
			detectedCases = append(detectedCases, "Status Code")
			res.Vulnerable = true
		} else if scb == scf && scb != sct {
			res.Vulnerable = true
			detectedCases = append(detectedCases, "Status Code")
		}
	}

	if len(detectedCases) > 0 {
		res.Case = strings.Join(detectedCases, ", ")
		if scb == 403 || sct == 403 || scf == 403 {
			res.Case = ""
			res.Vulnerable = false
		}
	}

	if res.Case == "Content Length" && *boolCTT == 0 && *boolCTF == 0 {
		*boolCTT = ctt
		*boolCTF = ctf
	}

	if res.Vulnerable && len(cases) > 0 {
		caseParts := splitCases(res.Case)
		res.Vulnerable = slicesEqual(cases, caseParts)
	}

	if res.Vulnerable {
		if res.StatusCode == 0 {
			res.StatusCode = attackTrue.StatusCode
		}
		if res.ContentLength == 0 {
			res.ContentLength = attackTrue.ContentLength
		}
	}

	return res
}

func pageDiff(a, b string) string {
	aWords := strings.Fields(a)
	bSet := make(map[string]struct{}, len(b))
	for _, w := range strings.Fields(b) {
		bSet[w] = struct{}{}
	}
	for _, w := range aWords {
		if _, ok := bSet[w]; !ok && len(w) > 4 {
			return w
		}
	}
	return ""
}

func splitCases(s string) []string {
	parts := strings.Split(s, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SearchPossibleDBMSErrors scans an HTTP response body for known SQL error patterns.
// Returns the first matching DBMS name, or empty string.
func SearchPossibleDBMSErrors(html string) string {
	for dbms, patterns := range payloads.SQLErrors {
		for _, pat := range patterns {
			re, err := regexp.Compile(`(?is)` + pat)
			if err != nil {
				continue
			}
			if re.MatchString(html) {
				return dbms
			}
		}
	}
	return ""
}

// SearchRegex runs a list of patterns against content and returns the first
// named capture group "error_based_response", or empty string.
func SearchRegex(patterns []string, content string) string {
	text := FilterHTML(content, true)
	for _, pat := range patterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			continue
		}
		m := re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		names := re.SubexpNames()
		for i, name := range names {
			if name == "error_based_response" && i < len(m) && m[i] != "" {
				v := m[i]
				// cleanup
				v = regexp.MustCompile(`[\(\~]+`).ReplaceAllString(v, "")
				v = regexp.MustCompile(`\s+`).ReplaceAllString(v, " ")
				v = strings.TrimSpace(v)
				if v == "" {
					v = "<blank_value>"
				}
				return v
			}
		}
	}
	return ""
}
