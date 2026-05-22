package request

import "net/http"

// HTTPResponse mirrors the Python namedtuple with same fields.
type HTTPResponse struct {
	OK            bool
	URL           string
	Data          string
	Text          string
	Path          string
	Method        string
	Reason        string
	Headers       http.Header
	ErrorMsg      string
	Redirected    bool
	RequestURL    string
	StatusCode    int
	ResponseTime  float64
	ContentLength int64
	FilteredText  string
}

// Parameter represents a single injectable parameter.
type Parameter struct {
	Key   string
	Value string
	Type  string // GET | POST | HEADER | COOKIE | URI
}
