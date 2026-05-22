package utils

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/SobhanYasami/sqlex/internal/payloads"
	"github.com/SobhanYasami/sqlex/internal/request"
)

// InjectionPoints holds parsed injection parameters by type.
type InjectionPoints struct {
	CustomInjectionIn []string
	IsMultipart       bool
	IsJSON            bool
	IsXML             bool
	// Keyed by "GET","POST","COOKIE","HEADER"
	Points map[string][]request.Parameter
}

var reMultipart = regexp.MustCompile(`(?i)Content-Disposition:[^;]+;\s*name=`)
var reXML = regexp.MustCompile(`(?s)^\s*<[^>]+>(.+>)?\s*$`)
var reProblematic = regexp.MustCompile(`(;q=[^;']+)|(\*/\*)`)

// ExtractInjectionPoints parses URL, POST data, headers, and cookies into
// a map of injection parameters, following the Python implementation.
func ExtractInjectionPoints(rawURL, data, headers, cookies string) InjectionPoints {
	pts := make(map[string][]request.Parameter)
	var customIn []string
	isMultipart, isJSON, isXML := false, false, false

	avoid := make(map[string]struct{}, len(payloads.AvoidParams))
	for _, p := range payloads.AvoidParams {
		avoid[p] = struct{}{}
	}
	injectHdrs := make(map[string]struct{}, len(payloads.InjectHeaders))
	for _, h := range payloads.InjectHeaders {
		injectHdrs[h] = struct{}{}
	}

	// Headers
	if headers != "" {
		var hdrParams []request.Parameter
		for _, line := range strings.Split(headers, "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, ":") {
				continue
			}
			idx := strings.Index(line, ":")
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+1:])
			cleaned := reProblematic.ReplaceAllString(v, "")
			if strings.Contains(cleaned, "*") {
				hdrParams = append(hdrParams, request.Parameter{Key: k, Value: v, Type: ""})
			} else if _, ok := injectHdrs[k]; ok {
				hdrParams = append(hdrParams, request.Parameter{Key: k, Value: v, Type: ""})
			}
		}
		if len(hdrParams) > 0 {
			pts["HEADER"] = hdrParams
		}
	}

	// Cookies
	if cookies != "" {
		if strings.Contains(cookies, ":") {
			parts := strings.SplitN(cookies, ":", 2)
			cookies = strings.TrimSpace(parts[1])
		}
		var cookieParams []request.Parameter
		for _, pair := range strings.Split(cookies, ";") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			idx := strings.Index(pair, "=")
			if idx < 0 {
				continue
			}
			k := strings.TrimSpace(pair[:idx])
			v := strings.TrimSpace(pair[idx+1:])
			cookieParams = append(cookieParams, request.Parameter{Key: k, Value: v, Type: ""})
		}
		if len(cookieParams) > 0 {
			pts["COOKIE"] = cookieParams
		}
	}

	// POST data
	if data != "" {
		var postParams []request.Parameter
		// Try JSON
		var jdata interface{}
		if json.Unmarshal([]byte(data), &jdata) == nil {
			isJSON = true
			postParams = flattenJSON(jdata)
		}
		if !isJSON {
			if reMultipart.MatchString(data) {
				isMultipart = true
				postParams = extractMultipart(data)
			} else if reXML.MatchString(data) {
				isXML = true
				postParams = extractXML(data)
			} else {
				vals, _ := url.ParseQuery(data)
				for k, vs := range vals {
					v := ""
					if len(vs) > 0 {
						v = vs[len(vs)-1]
					}
					postParams = append(postParams, request.Parameter{Key: k, Value: v, Type: ""})
				}
			}
		}
		if len(postParams) > 0 {
			pts["POST"] = postParams
		}
	}

	// GET params
	if rawURL != "" {
		parsed, err := url.Parse(rawURL)
		if err == nil {
			vals, _ := url.ParseQuery(parsed.RawQuery)
			var getParams []request.Parameter
			for k, vs := range vals {
				v := ""
				if len(vs) > 0 {
					v = strings.Join(vs, "")
				}
				getParams = append(getParams, request.Parameter{Key: k, Value: v, Type: ""})
			}
			if len(getParams) == 0 && parsed.Path != "" && parsed.Path != "/" && strings.Contains(parsed.Path, "*") {
				getParams = []request.Parameter{{Key: "#1*", Value: "*", Type: ""}}
			}
			pts["GET"] = getParams
		}
	}

	// Detect custom injection markers and build final ordered map
	for _, params := range pts {
		for _, p := range params {
			if strings.Contains(p.Value, "*") {
				for typ, tparams := range pts {
					for _, tp := range tparams {
						if tp.Key == p.Key {
							customIn = append(customIn, typ)
						}
					}
				}
			}
			if strings.Contains(p.Key, "*") && p.Key != "#1*" {
				for typ, tparams := range pts {
					for _, tp := range tparams {
						if tp.Key == p.Key {
							customIn = append(customIn, typ)
						}
					}
				}
			}
		}
	}

	// Filter avoid params and ensure ordered map
	ordered := map[string][]request.Parameter{
		"GET": {}, "POST": {}, "COOKIE": {}, "HEADER": {},
	}
	for typ, params := range pts {
		var filtered []request.Parameter
		for _, p := range params {
			if _, skip := avoid[p.Key]; !skip {
				filtered = append(filtered, p)
			}
		}
		ordered[typ] = filtered
	}

	customIn = dedup(customIn)
	return InjectionPoints{
		CustomInjectionIn: customIn,
		IsMultipart:       isMultipart,
		IsJSON:            isJSON,
		IsXML:             isXML,
		Points:            ordered,
	}
}

func dedup(s []string) []string {
	seen := make(map[string]struct{})
	out := s[:0]
	for _, v := range s {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

var reMultipartEntry = regexp.MustCompile(
	`(?is)(Content-Disposition[^\n]+?name\s*=\s*["']?(?P<name>.*?)["']?\s*)(?P<value>[\w\.\@_\-\*\+\[\]\=\>\;\:\'\"\?\/\<\.\,\!\@\#\$\%\^\&\*\(\)\_\+\` + "`" + `\~\{\}\|\\ ]*)?(\s)+--`)

func extractMultipart(data string) []request.Parameter {
	var out []request.Parameter
	re := reMultipartEntry
	for _, m := range re.FindAllStringSubmatch(data, -1) {
		names := re.SubexpNames()
		name, value := "", ""
		for i, n := range names {
			if n == "name" {
				name = m[i]
			}
			if n == "value" {
				value = strings.TrimSpace(m[i])
			}
		}
		if name != "" {
			out = append(out, request.Parameter{Key: name, Value: value, Type: "MULTIPART "})
		}
	}
	return out
}

var reXMLTag = regexp.MustCompile(`(<(?P<key>[^>/ ][^>]*)(?:\s[^>]*)?>)(?P<value>[^<]*)(</[^>]+>)`)

func extractXML(data string) []request.Parameter {
	var out []request.Parameter
	for _, m := range reXMLTag.FindAllStringSubmatch(data, -1) {
		names := reXMLTag.SubexpNames()
		k, v := "", ""
		for i, n := range names {
			if n == "key" {
				k = m[i]
			}
			if n == "value" {
				v = m[i]
			}
		}
		if k != "" {
			out = append(out, request.Parameter{Key: k, Value: v, Type: "SOUP "})
		}
	}
	return out
}

func flattenJSON(data interface{}) []request.Parameter {
	var out []request.Parameter
	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			switch vv := val.(type) {
			case map[string]interface{}:
				out = append(out, flattenJSON(vv)...)
			case []interface{}:
				for _, item := range vv {
					switch si := item.(type) {
					case string:
						out = append(out, request.Parameter{Key: key, Value: si, Type: "JSON "})
					default:
						out = append(out, flattenJSON(item)...)
					}
				}
			default:
				out = append(out, request.Parameter{Key: key, Value: jsonStr(val), Type: "JSON "})
			}
		}
	case []interface{}:
		for _, item := range v {
			out = append(out, flattenJSON(item)...)
		}
	}
	return out
}

func jsonStr(v interface{}) string {
	switch vv := v.(type) {
	case string:
		return vv
	case float64:
		s := fmt.Sprintf("%g", vv)
		return s
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// PrepareAttackRequest injects a payload into the raw text (URL, data, or headers)
// for the given parameter and injection type.
func PrepareAttackRequest(
	text, payload string,
	param request.Parameter,
	injectionType string,
	isJSON, isMultipart, isXML bool,
	skipURLEnc bool,
	backend string,
) string {
	key := param.Key
	value := param.Value

	replaceValue := strings.HasPrefix(payload, "if(") ||
		strings.HasPrefix(payload, "OR(") ||
		strings.HasPrefix(payload, "XOR") ||
		strings.HasPrefix(payload, "(SELEC") ||
		strings.HasPrefix(payload, "AND(")

	if !isJSON && key != "#1*" && !skipURLEnc {
		text = URLEncode(text, injectionType, isMultipart, false)
		key = URLEncode(key, injectionType, isMultipart, false)
		value = URLEncode(value, injectionType, isMultipart, false)
		if !skipURLEnc {
			payload = URLEncode(payload, injectionType, isMultipart, true)
		}
	}
	if isJSON {
		payload = URLDecode(payload)
	}

	// Custom injection marker in key
	keyDecoded := URLDecode(key)
	if (injectionType == "GET" || injectionType == "POST" || injectionType == "COOKIE" || injectionType == "HEADER") &&
		strings.Contains(keyDecoded, "*") && keyDecoded != "#1*" {
		init, _, last := partitionRight(text, keyDecoded)
		keyNew := strings.ReplaceAll(keyDecoded, "*", "")
		return init + keyNew + payload + last
	}

	// URI injection
	if key == "#1*" && injectionType == "GET" {
		if value == "*" {
			parts := strings.SplitN(text, value, 2)
			if len(parts) == 2 {
				return parts[0] + payload + parts[1]
			}
		}
		return regexp.MustCompile(`(?is)(/`+regexp.QuoteMeta(value)+`)`).
			ReplaceAllString(text, "${1}"+payload)
	}

	// Value with custom injection marker
	valueDecoded := URLDecode(value)
	if key != "#1*" && strings.Contains(valueDecoded, "*") &&
		(injectionType == "GET" || injectionType == "POST" || injectionType == "COOKIE") {
		paramStr := key + "=" + value
		replaced := strings.ReplaceAll(paramStr, "*", payload)
		return strings.Replace(text, paramStr, replaced, 1)
	}

	// Standard parameter injection
	keyEsc := regexp.QuoteMeta(key)
	valueEsc := regexp.QuoteMeta(value)

	switch injectionType {
	case "GET", "POST", "COOKIE":
		if injectionType == "POST" && isJSON {
			// JSON injection
			reJSON := regexp.MustCompile(`(?is)(['"]` + keyEsc + `['"])(:)(\s*['"\[[]*)` + valueEsc + `(['"\],]*)`)
			if replaceValue {
				return reJSON.ReplaceAllString(text, `${1}${2}${3}`+escapeJSONVal(payload)+`${5}`)
			}
			return reJSON.ReplaceAllString(text, `${1}${2}${3}`+escapeJSONVal(value)+escapeJSONVal(payload)+`${5}`)
		}
		prefix := ""
		if injectionType != "GET" {
			prefix = "?"
		}
		reGPC := regexp.MustCompile(`(?is)(((?:\?| |&)?` + prefix + keyEsc + `)(=)(` + valueEsc + `))`)
		m := reGPC.FindString(text)
		if m != "" && strings.Contains(m, "*") {
			return reGPC.ReplaceAllString(text, `${1}${2}`+payload)
		}
		if replaceValue {
			return reGPC.ReplaceAllString(text, `${1}${2}`+payload)
		}
		return reGPC.ReplaceAllString(text, `${1}${2}${3}`+payload)
	case "HEADER":
		reHdr := regexp.MustCompile(`(?is)(` + keyEsc + `)(:)(\s*` + valueEsc + `)`)
		m := reHdr.FindString(text)
		if m != "" && strings.Contains(m, "*") {
			result := reHdr.ReplaceAllString(text, `${1}${2}${3}`+payload)
			return strings.Replace(result, "*", "", 1)
		}
		return reHdr.ReplaceAllString(text, `${1}${2}${3}`+payload)
	}
	return text
}

func escapeJSONVal(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

func partitionRight(s, sep string) (string, string, string) {
	idx := strings.LastIndex(s, sep)
	if idx < 0 {
		return s, "", ""
	}
	return s[:idx], sep, s[idx+len(sep):]
}
