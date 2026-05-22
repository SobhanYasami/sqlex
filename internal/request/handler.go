package request

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html/charset"
)

// Requester is the interface used by all callers.
type Requester interface {
	Perform(ctx context.Context, method, urlStr, data string, headers http.Header) (*HTTPResponse, error)
}

// Perform sends an HTTP request and returns a parsed HTTPResponse.
// method: "GET" | "POST". data: POST body (empty → GET).
func (c *Client) Perform(ctx context.Context, method, urlStr, data string, headers http.Header) (*HTTPResponse, error) {
	if method == "" {
		if data != "" {
			method = "POST"
		} else {
			method = "GET"
		}
	}

	var body io.Reader
	if data != "" {
		body = strings.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if method == "POST" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	start := time.Now()
	resp, err := c.HTTP.Do(req)
	elapsed := time.Since(start).Seconds()
	if err != nil {
		return &HTTPResponse{
			OK:           false,
			URL:          urlStr,
			Data:         data,
			Method:       method,
			ErrorMsg:     err.Error(),
			ResponseTime: elapsed,
		}, nil
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)

	// Handle gzip
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gr, gerr := gzip.NewReader(bytes.NewReader(rawBody))
		if gerr == nil {
			defer gr.Close()
			rawBody, _ = io.ReadAll(gr)
		}
	}

	// Charset detection + decode to UTF-8
	contentType := resp.Header.Get("Content-Type")
	enc, _, _ := charset.DetermineEncoding(rawBody, contentType)
	decoded, _ := enc.NewDecoder().Bytes(rawBody)
	text := string(decoded)

	redirected := resp.StatusCode == 301 || resp.StatusCode == 302 ||
		resp.StatusCode == 303 || resp.StatusCode == 307

	return &HTTPResponse{
		OK:            resp.StatusCode < 500,
		URL:           resp.Request.URL.String(),
		Data:          data,
		Text:          text,
		Path:          resp.Request.URL.Path,
		Method:        method,
		Reason:        resp.Status,
		Headers:       resp.Header,
		Redirected:    redirected,
		RequestURL:    urlStr,
		StatusCode:    resp.StatusCode,
		ResponseTime:  elapsed,
		ContentLength: resp.ContentLength,
	}, nil
}
