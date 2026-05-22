package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/SobhanYasami/sqlex/internal/config"
	"github.com/SobhanYasami/sqlex/internal/inject"
	"github.com/SobhanYasami/sqlex/internal/payloads"
	"github.com/SobhanYasami/sqlex/internal/request"
	"github.com/SobhanYasami/sqlex/internal/session"
	"github.com/SobhanYasami/sqlex/internal/utils"
)

// InjectionResult is returned when a vulnerability is confirmed.
type InjectionResult struct {
	Vulnerable        bool
	URL               string
	Data              string
	Parameter         request.Parameter
	Backend           string
	InjectionType     string
	PayloadType       string
	Title             string
	Vector            string
	PreparedVector    string
	Payload           string
	MatchString       string
	NotString         string
	IsString          bool
	BooleanFalseAttack *request.HTTPResponse
	Base              *request.HTTPResponse
	Vectors           map[string]string
	Cases             []string
}

// expandedPayload is an internal struct for a ready-to-fire payload with prefix/suffix.
type expandedPayload struct {
	prefix string
	suffix string
	raw    string
	str    string // prefix + raw + suffix
}

// CheckInjections dispatches boolean, time, and error-based checks based on cfg.Technique.
// Returns the first confirmed InjectionResult, or nil if none found.
func CheckInjections(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	sess *session.Session,
	base *request.HTTPResponse,
	param request.Parameter,
	headers http.Header,
	injectionType string,
	possibleDBMS string,
	sessionPath string,
) (*InjectionResult, error) {
	// Session check first
	if sess != nil && sessionPath != "" {
		if res := checkSession(ctx, cfg, rs, client, sess, base, param, headers, injectionType, sessionPath); res != nil {
			return res, nil
		}
	}

	techniques := cfg.Technique

	// Error-based
	if techniques&config.TechniqueError != 0 {
		res, err := checkErrorBased(ctx, cfg, rs, client, base, param, headers, injectionType, possibleDBMS)
		if err == nil && res != nil {
			if sess != nil && sessionPath != "" {
				storePayload(sess, sessionPath, res, base, param, headers, injectionType)
			}
			return res, nil
		}
	}

	// Boolean-based
	if techniques&config.TechniqueBoolean != 0 {
		res, err := checkBooleanBased(ctx, cfg, rs, client, base, param, headers, injectionType, possibleDBMS)
		if err == nil && res != nil {
			if sess != nil && sessionPath != "" {
				storePayload(sess, sessionPath, res, base, param, headers, injectionType)
			}
			return res, nil
		}
	}

	// Time-based
	if techniques&config.TechniqueTime != 0 {
		res, err := checkTimeBased(ctx, cfg, rs, client, base, param, headers, injectionType, possibleDBMS)
		if err == nil && res != nil {
			if sess != nil && sessionPath != "" {
				storePayload(sess, sessionPath, res, base, param, headers, injectionType)
			}
			return res, nil
		}
	}

	return nil, nil
}

// checkSession attempts to resume from saved tbl_payload.
func checkSession(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	sess *session.Session,
	base *request.HTTPResponse,
	param request.Parameter,
	headers http.Header,
	injectionType, sessionPath string,
) *InjectionResult {
	rec, err := sess.FetchPayload(sessionPath)
	if err != nil || rec == nil {
		return nil
	}
	// Validate that the saved vector still works
	ictx := inject.InjectCtx{
		URL:           cfg.URL,
		Data:          cfg.Data,
		Headers:       headers,
		Parameter:     param,
		InjectionType: injectionType,
		IsMultipart:   rs.IsMultipart,
		IsJSON:        rs.IsJSON,
		IsXML:         rs.IsXML,
		Backend:       rec.Backend,
	}
	vectors := make(map[string]string)
	if rec.Vector != "" {
		switch rec.PayloadType {
		case "boolean-based blind":
			vectors["boolean_vector"] = rec.Vector
		case "time-based blind", "stacked queries":
			vectors["time_vector"] = rec.Vector
		case "error-based":
			vectors["error_vector"] = rec.Vector
		}
	}
	// Quick sanity check with saved payload
	_, checkErr := inject.Expression(ctx, cfg, rs, client, ictx, rec.Payload, false)
	if checkErr != nil {
		return nil
	}
	attack01 := base // fallback; ideally stored
	if rec.Attack01 != "" {
		var a request.HTTPResponse
		if json.Unmarshal([]byte(rec.Attack01), &a) == nil {
			attack01 = &a
		}
	}
	cases := []string{}
	if rec.Cases != "" {
		cases = strings.Split(rec.Cases, ",")
	}
	return &InjectionResult{
		Vulnerable:         true,
		URL:                cfg.URL,
		Parameter:          param,
		Backend:            rec.Backend,
		InjectionType:      injectionType,
		PayloadType:        rec.PayloadType,
		Title:              rec.Title,
		Vector:             rec.Vector,
		PreparedVector:     rec.Vector,
		Payload:            rec.Payload,
		MatchString:        rec.String,
		NotString:          rec.NotString,
		BooleanFalseAttack: attack01,
		Base:               base,
		Vectors:            vectors,
		Cases:              cases,
	}
}

// checkBooleanBased iterates boolean payloads and confirms any hit.
func checkBooleanBased(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	base *request.HTTPResponse,
	param request.Parameter,
	headers http.Header,
	injectionType, possibleDBMS string,
) (*InjectionResult, error) {
	allPayloads := collectBooleanPayloads(possibleDBMS, cfg.DBMS)

	ictx := inject.InjectCtx{
		URL:           cfg.URL,
		Data:          cfg.Data,
		Headers:       headers,
		Parameter:     param,
		InjectionType: injectionType,
		IsMultipart:   rs.IsMultipart,
		IsJSON:        rs.IsJSON,
		IsXML:         rs.IsXML,
	}

	for _, entry := range allPayloads {
		if possibleDBMS != "" && entry.DBMS != "" && entry.DBMS != possibleDBMS {
			continue
		}
		if cfg.DBMS != "" && entry.DBMS != "" && entry.DBMS != cfg.DBMS {
			continue
		}
		expPayloads := expandPayload(entry, cfg.Prefix, cfg.Suffix)
		for _, ep := range expPayloads {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			rnum := rand.Intn(8765) + 1234
			exprTrue := strings.ReplaceAll(ep.str, "[RANDNUM]=[RANDNUM]",
				fmt.Sprintf("%05d=%04d", rnum, rnum))
			exprTrue = strings.ReplaceAll(exprTrue, "[ORIGVALUE]",
				strings.ReplaceAll(param.Value, "*", ""))
			exprFalse := strings.ReplaceAll(ep.str, "[RANDNUM]=[RANDNUM]",
				fmt.Sprintf("%05d=%04d", rnum, rnum-68))
			exprFalse = strings.ReplaceAll(exprFalse, "[ORIGVALUE]",
				strings.ReplaceAll(param.Value, "*", ""))

			attackTrue, err := inject.Expression(ctx, cfg, rs, client, ictx, exprTrue, false)
			if err != nil {
				continue
			}
			if cfg.Delay > 0 {
				time.Sleep(cfg.Delay)
			}
			attackFalse, err := inject.Expression(ctx, cfg, rs, client, ictx, exprFalse, false)
			if err != nil {
				continue
			}

			var boolCTT, boolCTF int64
			br := utils.CheckBooleanResponses(
				base, attackTrue, attackFalse,
				cfg.Code, cfg.MatchString, cfg.NotString, rs.TextOnly,
				&rs.MatchRatio, rs.BoolCheckOnCT,
				&boolCTT, &boolCTF, &rs.MatchRatioCheck, rs.Cases,
			)
			if !br.Vulnerable {
				continue
			}

			// Confirm
			if !confirmBoolean(ctx, cfg, rs, client, ictx, base, ep, attackTrue, entry, br) {
				continue
			}

			// Fingerprint DBMS if not yet known
			backend := possibleDBMS
			if backend == "" {
				backend = cfg.DBMS
			}
			if backend == "" {
				backend = fingerprint(ctx, cfg, rs, client, ictx, base, attackTrue, attackFalse, entry.Vector, ep)
			}
			if backend == "" {
				continue // false positive
			}

			vector := ep.prefix + entry.Vector + ep.suffix
			vectors := map[string]string{"boolean_vector": vector}
			return &InjectionResult{
				Vulnerable:         true,
				URL:                cfg.URL,
				Data:               cfg.Data,
				Parameter:          param,
				Backend:            backend,
				InjectionType:      injectionType,
				PayloadType:        "boolean-based blind",
				Title:              entry.Title,
				Vector:             entry.Vector,
				PreparedVector:     vector,
				Payload:            exprTrue,
				MatchString:        br.String,
				NotString:          br.NotString,
				IsString:           br.String != "",
				BooleanFalseAttack: attackFalse,
				Base:               base,
				Vectors:            vectors,
				Cases:              utils.ToList(br.Case),
			}, nil
		}
	}
	return nil, nil
}

// checkTimeBased iterates time-based payloads and confirms with varied sleep times.
func checkTimeBased(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	base *request.HTTPResponse,
	param request.Parameter,
	headers http.Header,
	injectionType, possibleDBMS string,
) (*InjectionResult, error) {
	timeBased := collectTimePayloads(possibleDBMS, cfg.DBMS)
	sleepSec := int(cfg.TimeSec.Seconds())
	if sleepSec == 0 {
		sleepSec = 5
	}

	ictx := inject.InjectCtx{
		URL:           cfg.URL,
		Data:          cfg.Data,
		Headers:       headers,
		Parameter:     param,
		InjectionType: injectionType,
		IsMultipart:   rs.IsMultipart,
		IsJSON:        rs.IsJSON,
		IsXML:         rs.IsXML,
	}

	for _, entry := range timeBased {
		if possibleDBMS != "" && entry.DBMS != "" && entry.DBMS != possibleDBMS {
			continue
		}
		expPayloads := expandPayload(entry, cfg.Prefix, cfg.Suffix)
		for _, ep := range expPayloads {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			expr := strings.ReplaceAll(ep.str, "[SLEEPTIME]", fmt.Sprintf("%d", sleepSec))
			expr = strings.ReplaceAll(expr, "[ORIGVALUE]", strings.ReplaceAll(param.Value, "*", ""))

			attack, err := inject.Expression(ctx, cfg, rs, client, ictx, expr, false)
			if err != nil {
				continue
			}
			if attack.ResponseTime < float64(sleepSec) {
				continue
			}

			// Confirm: fire 5 probes with different sleep times and verify correlation
			if !confirmTimeBased(ctx, cfg, rs, client, ictx, base, ep, entry, sleepSec, attack.ResponseTime) {
				continue
			}

			backend := possibleDBMS
			if backend == "" {
				backend = cfg.DBMS
			}
			if backend == "" {
				backend = entry.DBMS
			}
			vector := ep.prefix + entry.Vector + ep.suffix
			vectors := map[string]string{"time_vector": vector}
			return &InjectionResult{
				Vulnerable:     true,
				URL:            cfg.URL,
				Data:           cfg.Data,
				Parameter:      param,
				Backend:        backend,
				InjectionType:  injectionType,
				PayloadType:    "time-based blind",
				Title:          entry.Title,
				Vector:         entry.Vector,
				PreparedVector: vector,
				Payload:        expr,
				Base:           base,
				Vectors:        vectors,
			}, nil
		}
	}
	return nil, nil
}

// checkErrorBased fires error-based payloads and checks for the r0oth3x49 marker.
func checkErrorBased(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	base *request.HTTPResponse,
	param request.Parameter,
	headers http.Header,
	injectionType, possibleDBMS string,
) (*InjectionResult, error) {
	errorPL := collectErrorPayloads(possibleDBMS, cfg.DBMS)

	ictx := inject.InjectCtx{
		URL:           cfg.URL,
		Data:          cfg.Data,
		Headers:       headers,
		Parameter:     param,
		InjectionType: injectionType,
		IsMultipart:   rs.IsMultipart,
		IsJSON:        rs.IsJSON,
		IsXML:         rs.IsXML,
	}

	for _, entry := range errorPL {
		if possibleDBMS != "" && entry.DBMS != "" && entry.DBMS != possibleDBMS {
			continue
		}
		expPayloads := expandPayload(entry, cfg.Prefix, cfg.Suffix)
		for _, ep := range expPayloads {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			attack, err := inject.Expression(ctx, cfg, rs, client, ictx, ep.str, false)
			if err != nil {
				continue
			}
			// Look for the r0oth3x49 marker or other error-based response patterns
			errorPatterns := []string{
				payloads.Regex["xpath"],
				payloads.Regex["error_based"],
				payloads.Regex["bigint"],
				payloads.Regex["double"],
				payloads.Regex["generic"],
				payloads.Regex["generic_errors"],
				payloads.Regex["mssql_string"],
			}
			value := utils.SearchRegex(errorPatterns, attack.Text)
			if value == "" || value == "<blank_value>" {
				// Also check for the generic r0oth3x49~...~END pattern
				if !strings.Contains(attack.Text, "r0oth3x49") && !strings.Contains(attack.Text, "Injected~") {
					continue
				}
			}

			backend := possibleDBMS
			if backend == "" {
				backend = cfg.DBMS
			}
			if backend == "" {
				backend = entry.DBMS
			}
			vector := ep.prefix + entry.Vector + ep.suffix
			vectors := map[string]string{"error_vector": vector}
			return &InjectionResult{
				Vulnerable:     true,
				URL:            cfg.URL,
				Data:           cfg.Data,
				Parameter:      param,
				Backend:        backend,
				InjectionType:  injectionType,
				PayloadType:    "error-based",
				Title:          entry.Title,
				Vector:         entry.Vector,
				PreparedVector: vector,
				Payload:        ep.str,
				Base:           base,
				Vectors:        vectors,
			}, nil
		}
	}
	return nil, nil
}

// confirmBoolean runs 5 boolean sanity checks against known-true/false conditions.
func confirmBoolean(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ictx inject.InjectCtx,
	base *request.HTTPResponse,
	ep expandedPayload,
	attackTrue *request.HTTPResponse,
	entry payloads.PayloadEntry,
	br utils.BooleanCheckResult,
) bool {
	testCases := [][2]string{
		{"2*3*8=6*8", "2*3*8=6*9"},
		{"3*2>(1*5)", "3*3<(2*4)"},
		{"3*2*0>=0", "3*3*9<(2*4)"},
		{"5*4=20", "5*4=21"},
		{"3*2*1=6", "3*2*0=6"},
	}
	if attackTrue.ResponseTime > 8 {
		testCases = testCases[:3]
	}
	passed := 0
	for _, tc := range testCases {
		exprT := strings.ReplaceAll(ep.str, "[RANDNUM]=[RANDNUM]", tc[0])
		exprF := strings.ReplaceAll(ep.str, "[RANDNUM]=[RANDNUM]", tc[1])
		at, err := inject.Expression(ctx, cfg, rs, client, ictx, exprT, false)
		if err != nil {
			continue
		}
		af, err := inject.Expression(ctx, cfg, rs, client, ictx, exprF, false)
		if err != nil {
			continue
		}
		var boolCTT, boolCTF int64
		cbr := utils.CheckBooleanResponses(
			base, at, af,
			cfg.Code, br.String, br.NotString, rs.TextOnly,
			&rs.MatchRatio, rs.BoolCheckOnCT,
			&boolCTT, &boolCTF, &rs.MatchRatioCheck, rs.Cases,
		)
		if cbr.Vulnerable {
			passed++
		}
	}
	threshold := len(testCases) * 80 / 100
	return passed >= threshold
}

// confirmTimeBased varies sleep times to confirm timing-based injection.
func confirmTimeBased(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ictx inject.InjectCtx,
	base *request.HTTPResponse,
	ep expandedPayload,
	entry payloads.PayloadEntry,
	baseSleep int,
	detectedTime float64,
) bool {
	sleepTimes := []int{0, 2, 0, baseSleep, 2}
	confirmed := 0
	for _, st := range sleepTimes {
		expr := strings.ReplaceAll(ep.str, "[SLEEPTIME]", fmt.Sprintf("%d", st))
		attack, err := inject.Expression(ctx, cfg, rs, client, ictx, expr, false)
		if err != nil {
			continue
		}
		expected := attack.ResponseTime >= float64(st) && attack.ResponseTime != detectedTime
		if st == 0 {
			expected = attack.ResponseTime < float64(baseSleep)
		}
		if expected {
			confirmed++
		}
	}
	return confirmed >= 4
}

// fingerprint calls DBMS-specific boolean expressions to identify the backend.
func fingerprint(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ictx inject.InjectCtx,
	base, attackTrue, attackFalse *request.HTTPResponse,
	vector string, ep expandedPayload,
) string {
	// Import avoidance: inline boolean expression checks
	dbmsExpressions := map[string]string{
		"MySQL":                "QUARTER(NULL) IS NULL",
		"Microsoft SQL Server": "UNICODE(SQUARE(NULL)) IS NULL",
		"PostgreSQL":           "QUOTE_IDENT(NULL) IS NULL",
		"Oracle":               "LENGTH(SYSDATE)=LENGTH(SYSDATE)",
	}
	fullVector := ep.prefix + vector + ep.suffix
	for dbms, expr := range dbmsExpressions {
		probe := strings.ReplaceAll(fullVector, "[INFERENCE]", expr)
		probe = strings.ReplaceAll(probe, "[SLEEPTIME]", fmt.Sprintf("%d", int(cfg.TimeSec.Seconds())))
		attack, err := inject.Expression(ctx, cfg, rs, client, ictx, probe, false)
		if err != nil {
			continue
		}
		var boolCTT, boolCTF int64
		br := utils.CheckBooleanResponses(
			base, attack, attackFalse,
			cfg.Code, cfg.MatchString, cfg.NotString, rs.TextOnly,
			&rs.MatchRatio, rs.BoolCheckOnCT,
			&boolCTT, &boolCTF, &rs.MatchRatioCheck, rs.Cases,
		)
		if br.Vulnerable {
			return dbms
		}
	}
	return ""
}

// expandPayload generates prefix+payload+suffix combinations.
func expandPayload(entry payloads.PayloadEntry, prefix, suffix string) []expandedPayload {
	var out []expandedPayload
	if prefix != "" || suffix != "" {
		// User-supplied prefix/suffix: use single combination with last comment's payload
		lastPL := entry.Payload
		if len(entry.Comments) > 0 {
			// use empty comment if exists
			for _, c := range entry.Comments {
				if c.Suf == "" {
					lastPL = entry.Payload
					break
				}
			}
		}
		p := prefix
		s := suffix
		if p != "" && !strings.HasSuffix(p, " ") {
			p += " "
		}
		out = append(out, expandedPayload{
			prefix: p, suffix: s, raw: lastPL,
			str: p + lastPL + s,
		})
		return out
	}
	for _, c := range entry.Comments {
		out = append(out, expandedPayload{
			prefix: c.Pref, suffix: c.Suf, raw: entry.Payload,
			str: c.Pref + entry.Payload + c.Suf,
		})
	}
	if len(out) == 0 {
		out = append(out, expandedPayload{raw: entry.Payload, str: entry.Payload})
	}
	return out
}

// collectBooleanPayloads returns all boolean-based payload entries.
func collectBooleanPayloads(possibleDBMS, dbms string) []payloads.PayloadEntry {
	var out []payloads.PayloadEntry
	// Generic boolean tests first
	out = append(out, payloads.GetPayloads("BooleanTests", "boolean-based")...)
	// DBMS-specific
	for _, db := range []string{"MySQL", "Microsoft SQL Server", "PostgreSQL", "Oracle"} {
		out = append(out, payloads.GetPayloads(db, "boolean-based")...)
	}
	return out
}

// collectTimePayloads returns time-based + stacked-queries payload entries.
func collectTimePayloads(possibleDBMS, dbms string) []payloads.PayloadEntry {
	var out []payloads.PayloadEntry
	for _, db := range []string{"MySQL", "Microsoft SQL Server", "PostgreSQL", "Oracle"} {
		out = append(out, payloads.GetPayloads(db, "time-based")...)
		out = append(out, payloads.GetPayloads(db, "stacked-queries")...)
	}
	return out
}

// collectErrorPayloads returns error-based payload entries.
func collectErrorPayloads(possibleDBMS, dbms string) []payloads.PayloadEntry {
	var out []payloads.PayloadEntry
	for _, db := range []string{"MySQL", "Microsoft SQL Server", "PostgreSQL", "Oracle"} {
		out = append(out, payloads.GetPayloads(db, "error-based")...)
	}
	return out
}

// storePayload saves injection result to session DB.
func storePayload(
	sess *session.Session,
	sessionPath string,
	res *InjectionResult,
	base *request.HTTPResponse,
	param request.Parameter,
	headers http.Header,
	injectionType string,
) {
	paramJSON, _ := json.Marshal(param)
	attack01JSON := ""
	if res.BooleanFalseAttack != nil {
		b, _ := json.Marshal(res.BooleanFalseAttack)
		attack01JSON = string(b)
	}
	endpoint := base.Path
	casesStr := strings.Join(res.Cases, ",")
	_, _ = sess.SavePayload(sessionPath, session.PayloadRecord{
		Title:         res.Title,
		Attempts:      1,
		Payload:       res.Payload,
		Vector:        res.PreparedVector,
		Backend:       res.Backend,
		Parameter:     string(paramJSON),
		InjectionType: injectionType,
		PayloadType:   res.PayloadType,
		Endpoint:      endpoint,
		String:        res.MatchString,
		NotString:     res.NotString,
		Attack01:      attack01JSON,
		Cases:         casesStr,
	})
}
