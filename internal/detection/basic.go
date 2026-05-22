package detection

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SobhanYasami/sqlex/internal/config"
	"github.com/SobhanYasami/sqlex/internal/inject"
	"github.com/SobhanYasami/sqlex/internal/request"
	"github.com/SobhanYasami/sqlex/internal/utils"
)

// BasicCheckResult is returned by BasicCheck.
type BasicCheckResult struct {
	Base               *request.HTTPResponse
	PossibleDBMS       string
	IsConnectionTested bool
	IsDynamic          bool
	IsResumed          bool
	IsParameterTested  bool
	Prioritize         bool
}

// BasicCheck performs:
//  1. Connection test to the target
//  2. Page stability check (dynamic detection)
//  3. SQL error heuristic via simple injection markers
func BasicCheck(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	param request.Parameter,
	injectionType string,
	headers http.Header,
	sessionPayloadCount int, // from tbl_payload for this endpoint
	paramAlreadyTested bool,
) (BasicCheckResult, error) {
	result := BasicCheckResult{IsConnectionTested: true}

	ictx := inject.InjectCtx{
		URL:           cfg.URL,
		Data:          cfg.Data,
		Headers:       headers,
		Parameter:     param,
		InjectionType: injectionType,
		IsMultipart:   rs.IsMultipart,
		IsJSON:        rs.IsJSON,
		IsXML:         rs.IsXML,
		Backend:       rs.GetBackend(),
	}

	base, err := inject.Expression(ctx, cfg, rs, client, ictx, "", true)
	if err != nil {
		return result, fmt.Errorf("connection test failed: %w", err)
	}
	result.Base = base

	if sessionPayloadCount > 0 {
		result.IsResumed = true
		result.IsParameterTested = paramAlreadyTested
		return result, nil
	}

	// Stability check
	time.Sleep(300 * time.Millisecond)
	resp2, err := inject.Expression(ctx, cfg, rs, client, ictx, "", true)
	if err == nil {
		if base.ContentLength != resp2.ContentLength {
			rs.BoolCheckOnCT = false
		}
		baseLines := strings.Split(utils.FilterHTML(base.FilteredText, true), "\n")
		resp2Lines := strings.Split(utils.FilterHTML(resp2.FilteredText, true), "\n")
		baseSet := make(map[string]struct{}, len(baseLines))
		for _, l := range baseLines {
			baseSet[l] = struct{}{}
		}
		stable := true
		for _, l := range resp2Lines {
			if _, ok := baseSet[l]; !ok {
				stable = false
				break
			}
		}
		if !stable {
			result.IsDynamic = true
		}
	}

	// Heuristic SQL error probes
	heuristicPayloads := []string{"'\",..))", "',..))", "\",..)))", "'\"", "%27%22"}
	for _, expr := range heuristicPayloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		attack, err := inject.Expression(ctx, cfg, rs, client, ictx, expr, false)
		if err != nil {
			continue
		}
		dbms := utils.SearchPossibleDBMSErrors(attack.Text)
		if dbms != "" {
			result.PossibleDBMS = dbms
			if cfg.Technique&config.TechniqueError == 0 {
				result.Prioritize = true
			}
			break
		}
		if attack.StatusCode != 400 {
			break
		}
	}

	return result, nil
}

