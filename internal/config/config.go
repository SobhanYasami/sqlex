package config

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type Technique uint8

const (
	TechniqueBoolean Technique = 1 << iota
	TechniqueError
	TechniqueTime
)

func ParseTechniques(s string) Technique {
	var t Technique
	for _, c := range s {
		switch c {
		case 'B', 'b':
			t |= TechniqueBoolean
		case 'E', 'e':
			t |= TechniqueError
		case 'T', 't':
			t |= TechniqueTime
		}
	}
	return t
}

// Config is read-only after CLI parse. Passed by pointer everywhere.
type Config struct {
	URL          string
	Data         string
	Cookie       string
	Proxy        string
	Headers      http.Header
	Level        int
	MatchString  string
	NotString    string
	Code         int
	TextOnly     bool
	Param        string // --test-parameter
	DBMS         string
	Prefix       string
	Suffix       string
	Technique    Technique
	Delay        time.Duration
	Timeout      time.Duration
	TimeSec      time.Duration
	Retry        int
	Threads      int
	FetchUsing   string
	SessionDir   string
	FlushSession bool
	FreshQueries bool
	Batch        bool
	SkipURLEnc   bool
	SafeChars    string
	ConfirmPL    bool  // --confirm-payloads
	TestFilter   string
	IgnoreCode   []int
	IsJSON       bool
	IsXML        bool
	IsMultipart  bool
	RequestFile  string
	BulkFile     string
	ForceSSL     bool
	FollowRedir  *bool // nil = smart, true = always, false = never
	RandomAgent  bool
	MobileAgent  bool
	Verbose      int
	SQLShell     bool
	// Extraction requests
	GetBanner   bool
	CurrentUser bool
	CurrentDB   bool
	Hostname    bool
	GetDBs      bool
	GetTables   bool
	GetColumns  bool
	Dump        bool
	CountOnly   bool
	DB          string
	Table       string
	Columns     string
	StartLimit  int
	StopLimit   int
}

func DefaultConfig() *Config {
	t := time.Duration(30) * time.Second
	ts := time.Duration(5) * time.Second
	return &Config{
		Level:     1,
		Technique: TechniqueBoolean | TechniqueTime,
		Timeout:   t,
		TimeSec:   ts,
		Retry:     3,
		Code:      200,
		Verbose:   1,
	}
}

// RunState holds mutable runtime state. Never copied by value.
type RunState struct {
	mu             sync.RWMutex
	Backend        string
	Vectors        map[string]string // "boolean_vector","error_vector","time_vector"
	Base           interface{}       // *request.HTTPResponse — interface to avoid import cycle
	Attack01       interface{}       // *request.HTTPResponse
	ReqCounter     atomic.Int64
	InjCounter     atomic.Int64
	ReadTOCounter  atomic.Int64
	IsString       bool
	IsJSON         bool
	IsXML          bool
	IsMultipart    bool
	TextOnly       bool
	MatchRatio     float64
	BoolCheckOnCT  bool
	MatchRatioCheck bool
	Cases          []string
	Prioritize     bool
	RandomAgentHdr http.Header
}

func NewRunState() *RunState {
	rs := &RunState{
		Vectors:       make(map[string]string),
		BoolCheckOnCT: true,
		Cases:         []string{},
	}
	rs.ReqCounter.Store(1)
	return rs
}

func (rs *RunState) SetBackend(b string) {
	rs.mu.Lock()
	rs.Backend = b
	rs.mu.Unlock()
}

func (rs *RunState) GetBackend() string {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.Backend
}

func (rs *RunState) SetVector(key, val string) {
	rs.mu.Lock()
	rs.Vectors[key] = val
	rs.mu.Unlock()
}

func (rs *RunState) GetVector(key string) string {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.Vectors[key]
}

func (rs *RunState) SetBase(v interface{}) {
	rs.mu.Lock()
	rs.Base = v
	rs.mu.Unlock()
}

func (rs *RunState) GetBase() interface{} {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.Base
}
