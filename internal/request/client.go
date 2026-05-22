package request

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"
)

// Client wraps *http.Client with proxy + TLS config.
type Client struct {
	HTTP *http.Client
}

// NewClient builds an http.Client with optional proxy, TLS skip, and timeout.
func NewClient(proxyURL string, insecure bool, timeout time.Duration) (*Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		Proxy:           http.ProxyFromEnvironment,
	}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(u)
	}
	return &Client{
		HTTP: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}
