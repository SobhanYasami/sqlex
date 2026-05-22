package inject

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SobhanYasami/sqlex/internal/config"
	"github.com/SobhanYasami/sqlex/internal/request"
	"github.com/SobhanYasami/sqlex/internal/utils"
)

// InjectCtx holds all context needed to fire an injected request.
type InjectCtx struct {
	URL           string
	Data          string
	Headers       http.Header
	Parameter     request.Parameter
	InjectionType string
	IsMultipart   bool
	IsJSON        bool
	IsXML         bool
	Backend       string
}

// Expression performs a single injected request, returning the HTTP response.
// expression: the fully-rendered SQL payload string (may be empty for connection test).
// Retries up to cfg.Retry times on network errors.
func Expression(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ictx InjectCtx,
	expression string,
	connectionTest bool,
) (*request.HTTPResponse, error) {
	return expressionRetry(ctx, cfg, rs, client, ictx, expression, connectionTest, 0)
}

func expressionRetry(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	ictx InjectCtx,
	expression string,
	connectionTest bool,
	attempt int,
) (*request.HTTPResponse, error) {
	attackURL := ictx.URL
	attackData := ictx.Data
	attackHeaders := headersToStr(ictx.Headers)

	if !connectionTest && expression != "" {
		// Replace [ORIGVALUE] with actual param value
		paramValue := strings.ReplaceAll(ictx.Parameter.Value, "*", "")
		expr := strings.ReplaceAll(expression, "[ORIGVALUE]", paramValue)

		switch ictx.InjectionType {
		case "HEADER":
			attackHeaders = utils.PrepareAttackRequest(
				attackHeaders, expr, ictx.Parameter, ictx.InjectionType,
				ictx.IsJSON, ictx.IsMultipart, ictx.IsXML, cfg.SkipURLEnc, ictx.Backend,
			)
		case "COOKIE":
			encode := !cfg.SkipURLEnc
			_ = encode
			attackHeaders = utils.PrepareAttackRequest(
				attackHeaders, expr, ictx.Parameter, ictx.InjectionType,
				ictx.IsJSON, ictx.IsMultipart, ictx.IsXML, cfg.SkipURLEnc, ictx.Backend,
			)
		case "GET":
			attackURL = utils.PrepareAttackRequest(
				ictx.URL, expr, ictx.Parameter, ictx.InjectionType,
				ictx.IsJSON, ictx.IsMultipart, ictx.IsXML, cfg.SkipURLEnc, ictx.Backend,
			)
		case "POST":
			attackData = utils.PrepareAttackRequest(
				ictx.Data, expr, ictx.Parameter, ictx.InjectionType,
				ictx.IsJSON, ictx.IsMultipart, ictx.IsXML, cfg.SkipURLEnc, ictx.Backend,
			)
		}
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Build headers map
	hdrs := strToHeaders(attackHeaders)
	// Merge RunState random agent headers
	if rs.RandomAgentHdr != nil {
		for k, vs := range rs.RandomAgentHdr {
			hdrs[k] = vs
		}
	}

	method := "GET"
	if attackData != "" {
		method = "POST"
	}

	resp, err := client.Perform(ctx, method, attackURL, attackData, hdrs)
	if err != nil {
		if attempt >= cfg.Retry {
			return nil, fmt.Errorf("max retries exceeded: %w", err)
		}
		// brief backoff before retry
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		return expressionRetry(ctx, cfg, rs, client, ictx, expression, connectionTest, attempt+1)
	}

	// 401 handling
	if resp.StatusCode == 401 && len(cfg.IgnoreCode) == 0 {
		return nil, fmt.Errorf("HTTP 401 Unauthorized — provide credentials or use --ignore-code")
	}

	rs.ReqCounter.Add(1)
	if cfg.Delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(cfg.Delay):
		}
	}

	return resp, nil
}

func headersToStr(h http.Header) string {
	var sb strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			sb.WriteString(k + ": " + v + "\n")
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}

func strToHeaders(s string) http.Header {
	h := make(http.Header)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ":") {
			continue
		}
		idx := strings.Index(line, ":")
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		h.Add(k, v)
	}
	return h
}
