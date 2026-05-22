package engine

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/fatih/color"
	"github.com/SobhanYasami/sqlex/internal/config"
	"github.com/SobhanYasami/sqlex/internal/detection"
	"github.com/SobhanYasami/sqlex/internal/enumeration"
	"github.com/SobhanYasami/sqlex/internal/payloads"
	"github.com/SobhanYasami/sqlex/internal/request"
	"github.com/SobhanYasami/sqlex/internal/session"
	"github.com/SobhanYasami/sqlex/internal/utils"
)

var (
	bold   = color.New(color.Bold)
	green  = color.New(color.FgGreen, color.Bold)
	yellow = color.New(color.FgYellow, color.Bold)
	red    = color.New(color.FgRed, color.Bold)
	cyan   = color.New(color.FgCyan, color.Bold)
)

// Engine orchestrates the full injection + enumeration flow.
type Engine struct {
	cfg    *config.Config
	rs     *config.RunState
	sess   *session.Session
	client *request.Client
	enum   *enumeration.Enumerator
}

func New(cfg *config.Config) (*Engine, error) {
	rs := config.NewRunState()
	rs.IsJSON = cfg.IsJSON
	rs.IsXML = cfg.IsXML
	rs.IsMultipart = cfg.IsMultipart
	rs.TextOnly = cfg.TextOnly

	client, err := request.NewClient(cfg.Proxy, true, cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}

	sess := session.New()

	return &Engine{
		cfg:    cfg,
		rs:     rs,
		sess:   sess,
		client: client,
		enum:   enumeration.New(sess),
	}, nil
}

// Run is the main entrypoint: detect injection, then enumerate.
func (e *Engine) Run(ctx context.Context) error {
	cfg := e.cfg

	// Normalise DBMS name
	cfg.DBMS = utils.DBMSFullName(cfg.DBMS)

	// Build merged headers
	headers := buildHeaders(cfg)

	// Random user-agent
	if cfg.RandomAgent || cfg.MobileAgent {
		ua := payloads.RandomUA()
		if ua != "" {
			if headers == nil {
				headers = make(http.Header)
			}
			headers.Set("User-Agent", ua)
		}
		e.rs.RandomAgentHdr = headers
	}

	// Session file paths
	method := "GET"
	if cfg.Data != "" {
		method = "POST"
	}
	fps, err := e.sess.GenerateFilepath(cfg.URL, method, cfg.Data, cfg.FlushSession)
	if err != nil {
		return fmt.Errorf("session init: %w", err)
	}
	if err := e.sess.Init(fps.Session); err != nil {
		return fmt.Errorf("session schema: %w", err)
	}
	sessionPath := fps.Session
	cfg.SessionDir = sessionPath

	// Extract injection points
	pts := utils.ExtractInjectionPoints(cfg.URL, cfg.Data, headersToStr(headers), cfg.Cookie)
	e.rs.IsJSON = pts.IsJSON
	e.rs.IsXML = pts.IsXML
	e.rs.IsMultipart = pts.IsMultipart

	// Existing payload count for resume detection
	payloadCount, _ := e.sess.PayloadCount(sessionPath)

	// Ordered injection types: custom markers first, then GET, POST, COOKIE, HEADER
	injectionOrder := orderedInjectionTypes(pts)

	injFound := false
	var injResult *detection.InjectionResult

	for _, injType := range injectionOrder {
		params := pts.Points[injType]
		if len(params) == 0 {
			continue
		}

		for _, param := range params {
			// Filter to --test-parameter if set
			if cfg.Param != "" && !strings.EqualFold(param.Key, cfg.Param) &&
				!strings.Contains(param.Key, "*") {
				continue
			}

			paramAlreadyTested := payloadCount > 0

			basicRes, err := detection.BasicCheck(
				ctx, cfg, e.rs, e.client, param, injType, headers,
				payloadCount, paramAlreadyTested,
			)
			if err != nil {
				red.Fprintf(color.Error, "[ERROR] %s\n", err)
				continue
			}

			base := basicRes.Base
			if base == nil {
				continue
			}

			if basicRes.IsResumed && basicRes.IsParameterTested {
				// Already tested this parameter in a prior session; skip basic check
			}

			printParamInfo(param, injType, basicRes)

			res, err := detection.CheckInjections(
				ctx, cfg, e.rs, e.client, e.sess,
				base, param, headers, injType,
				basicRes.PossibleDBMS, sessionPath,
			)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			if res == nil || !res.Vulnerable {
				yellow.Fprintf(color.Output, "[WARNING] parameter '%s' does not appear to be injectable\n", param.Key)
				continue
			}

			injResult = res
			injFound = true

			// Apply RunState from injection result
			e.rs.SetBackend(res.Backend)
			for k, v := range res.Vectors {
				e.rs.SetVector(k, v)
			}
			e.rs.MatchRatio = 0
			if res.MatchString != "" {
				e.rs.IsString = true
			}
			if len(res.Cases) > 0 {
				e.rs.Cases = res.Cases
			}

			printInjectionFound(res)
			break
		}
		if injFound {
			break
		}
	}

	if !injFound || injResult == nil {
		red.Fprintln(color.Output, "\n[CRITICAL] no injectable parameters found")
		return nil
	}

	// Resolve vector and vectorType for enumeration
	vector, vectorType := resolveVector(e.rs)
	base := injResult.Base
	attack01 := injResult.BooleanFalseAttack
	if attack01 == nil {
		attack01 = base
	}
	param := injResult.Parameter
	injType := injResult.InjectionType

	// -- Enumerate --

	if cfg.GetBanner {
		res, err := e.enum.FetchBanner(ctx, cfg, e.rs, e.client, base, attack01, headers, param, injType, vector, vectorType, sessionPath)
		if err == nil && res.OK {
			green.Fprintf(color.Output, "[INFO] banner: '%s'\n", res.Result)
		}
	}

	if cfg.CurrentUser {
		res, err := e.enum.FetchCurrentUser(ctx, cfg, e.rs, e.client, base, attack01, headers, param, injType, vector, vectorType, sessionPath)
		if err == nil && res.OK {
			green.Fprintf(color.Output, "[INFO] current user: '%s'\n", res.Result)
		}
	}

	if cfg.CurrentDB {
		res, err := e.enum.FetchCurrentDB(ctx, cfg, e.rs, e.client, base, attack01, headers, param, injType, vector, vectorType, sessionPath)
		if err == nil && res.OK {
			green.Fprintf(color.Output, "[INFO] current database: '%s'\n", res.Result)
		}
	}

	if cfg.Hostname {
		res, err := e.enum.FetchHostname(ctx, cfg, e.rs, e.client, base, attack01, headers, param, injType, vector, vectorType, sessionPath)
		if err == nil && res.OK {
			green.Fprintf(color.Output, "[INFO] hostname: '%s'\n", res.Result)
		}
	}

	if cfg.GetDBs {
		res, err := e.enum.FetchDBs(ctx, cfg, e.rs, e.client, base, attack01, headers, param, injType, vector, vectorType, sessionPath, cfg.StartLimit, cfg.StopLimit)
		if err != nil {
			red.Fprintf(color.Error, "[ERROR] --dbs: %s\n", err)
		} else if res.OK {
			cyan.Fprintln(color.Output, "[INFO] available databases:")
			for i, db := range res.Result {
				fmt.Fprintf(color.Output, "  [%d] %s\n", i+1, db)
			}
		}
	}

	if cfg.GetTables && cfg.DB != "" {
		res, err := e.enum.FetchTables(ctx, cfg, e.rs, e.client, base, attack01, headers, param, injType, vector, vectorType, sessionPath, cfg.DB, cfg.StartLimit, cfg.StopLimit)
		if err != nil {
			red.Fprintf(color.Error, "[ERROR] --tables: %s\n", err)
		} else if res.OK {
			cyan.Fprintf(color.Output, "[INFO] database '%s' tables:\n", cfg.DB)
			for i, tbl := range res.Result {
				fmt.Fprintf(color.Output, "  [%d] %s\n", i+1, tbl)
			}
		}
	}

	if cfg.GetColumns && cfg.DB != "" && cfg.Table != "" {
		res, err := e.enum.FetchColumns(ctx, cfg, e.rs, e.client, base, attack01, headers, param, injType, vector, vectorType, sessionPath, cfg.DB, cfg.Table, cfg.StartLimit, cfg.StopLimit)
		if err != nil {
			red.Fprintf(color.Error, "[ERROR] --columns: %s\n", err)
		} else if res.OK {
			cyan.Fprintf(color.Output, "[INFO] table '%s.%s' columns:\n", cfg.DB, cfg.Table)
			for i, col := range res.Result {
				fmt.Fprintf(color.Output, "  [%d] %s\n", i+1, col)
			}
		}
	}

	if cfg.Dump && cfg.DB != "" && cfg.Table != "" {
		cols := utils.ToList(cfg.Columns)
		if len(cols) == 0 {
			// Fetch all columns first
			colRes, err := e.enum.FetchColumns(ctx, cfg, e.rs, e.client, base, attack01, headers, param, injType, vector, vectorType, sessionPath, cfg.DB, cfg.Table, 0, 0)
			if err == nil && colRes.OK {
				cols = colRes.Result
			}
		}
		if len(cols) == 0 {
			red.Fprintln(color.Error, "[ERROR] --dump: no columns found")
		} else {
			rows, err := e.enum.DumpTable(ctx, cfg, e.rs, e.client, base, attack01, headers, param, injType, vector, vectorType, sessionPath, cfg.DB, cfg.Table, cols, cfg.StartLimit, cfg.StopLimit)
			if err != nil {
				red.Fprintf(color.Error, "[ERROR] --dump: %s\n", err)
			} else if len(rows) > 0 {
				printTable(cfg.DB, cfg.Table, cols, rows)
				// Write CSV
				var csvRows [][]string
				for _, row := range rows {
					var r []string
					for _, c := range cols {
						r = append(r, row[c])
					}
					csvRows = append(csvRows, r)
				}
				if csvErr := e.sess.DumpToCSV(sessionPath, cfg.DB, cfg.Table, cols, csvRows); csvErr == nil {
					cyan.Fprintf(color.Output, "[INFO] data saved to CSV under session directory\n")
				}
			}
		}
	}

	return nil
}

// buildHeaders merges cfg.Headers and cfg.Cookie into a single http.Header.
func buildHeaders(cfg *config.Config) http.Header {
	h := make(http.Header)
	for k, vs := range cfg.Headers {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	if cfg.Cookie != "" {
		cookie := cfg.Cookie
		if idx := strings.Index(cookie, ":"); idx >= 0 {
			cookie = strings.TrimSpace(cookie[idx+1:])
		}
		h.Set("Cookie", cookie)
	}
	return h
}

// headersToStr converts http.Header to the newline-separated "Key: Value" format
// expected by ExtractInjectionPoints.
func headersToStr(h http.Header) string {
	var sb strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// orderedInjectionTypes returns injection types with custom-marker types first.
func orderedInjectionTypes(pts utils.InjectionPoints) []string {
	seen := make(map[string]bool)
	var order []string
	for _, t := range pts.CustomInjectionIn {
		if !seen[t] {
			seen[t] = true
			order = append(order, t)
		}
	}
	for _, t := range []string{"GET", "POST", "COOKIE", "HEADER"} {
		if !seen[t] {
			seen[t] = true
			order = append(order, t)
		}
	}
	return order
}

// resolveVector picks the best available vector and its type string.
func resolveVector(rs *config.RunState) (vector, vectorType string) {
	if v := rs.GetVector("boolean_vector"); v != "" {
		return v, "boolean_vector"
	}
	if v := rs.GetVector("error_vector"); v != "" {
		return v, "error_vector"
	}
	if v := rs.GetVector("time_vector"); v != "" {
		return v, "time_vector"
	}
	return "", ""
}

func printParamInfo(param request.Parameter, injType string, br detection.BasicCheckResult) {
	prefix := strings.TrimSpace(param.Type)
	if prefix == "" {
		prefix = injType
	}
	bold.Fprintf(color.Output, "[INFO] testing '%s' parameter '%s'\n", prefix, param.Key)
	if br.IsDynamic {
		yellow.Fprintln(color.Output, "[WARNING] heuristic detected dynamic page")
	}
	if br.PossibleDBMS != "" {
		cyan.Fprintf(color.Output, "[INFO] heuristic detected possible DBMS: %s\n", br.PossibleDBMS)
	}
}

func printInjectionFound(res *detection.InjectionResult) {
	green.Fprintf(color.Output, "[SUCCESS] '%s' is vulnerable\n", res.Parameter.Key)
	fmt.Fprintf(color.Output, "  Backend  : %s\n", res.Backend)
	fmt.Fprintf(color.Output, "  Technique: %s\n", res.PayloadType)
	fmt.Fprintf(color.Output, "  Title    : %s\n", res.Title)
	fmt.Fprintf(color.Output, "  Payload  : %s\n", res.Payload)
}

func printTable(database, table string, cols []string, rows []map[string]string) {
	cyan.Fprintf(color.Output, "\n[INFO] dumping table '%s.%s' (%d rows)\n\n", database, table, len(rows))

	// Compute column widths
	widths := make(map[string]int, len(cols))
	for _, c := range cols {
		widths[c] = len(c)
	}
	for _, row := range rows {
		for _, c := range cols {
			if l := len(row[c]); l > widths[c] {
				widths[c] = l
			}
		}
	}

	sep := "+"
	for _, c := range cols {
		sep += strings.Repeat("-", widths[c]+2) + "+"
	}
	fmt.Fprintln(color.Output, sep)

	hdr := "|"
	for _, c := range cols {
		hdr += fmt.Sprintf(" %-*s |", widths[c], c)
	}
	bold.Fprintln(color.Output, hdr)
	fmt.Fprintln(color.Output, sep)

	for _, row := range rows {
		line := "|"
		for _, c := range cols {
			line += fmt.Sprintf(" %-*s |", widths[c], row[c])
		}
		fmt.Fprintln(color.Output, line)
	}
	fmt.Fprintln(color.Output, sep)
}
