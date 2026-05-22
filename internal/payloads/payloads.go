package payloads

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

//go:embed payloads.json
var payloadsRaw []byte

//go:embed extra.json
var extraRaw []byte

//go:embed uas.json
var uasRaw []byte

// Comment represents prefix/suffix pair used to wrap a payload.
type Comment struct {
	Pref string `json:"pref"`
	Suf  string `json:"suf"`
}

// PayloadEntry is a single injection test payload with metadata.
type PayloadEntry struct {
	Payload  string    `json:"payload"`
	Comments []Comment `json:"comments"`
	Title    string    `json:"title"`
	Vector   string    `json:"vector"`
	DBMS     string    `json:"dbms"`
}

// All payload data loaded at init time.
var (
	once sync.Once

	NOCPayloads  map[string]string            // NUMBER_OF_CHARACTERS_PAYLOADS
	LengthPL     map[string][]string          // LENGTH_PAYLOADS
	DataExtrPL   map[string]map[string]string // DATA_EXTRACTION_PAYLOADS
	Regex        map[string]string            // named regex patterns
	BannerPL     map[string][]string
	CurrentUserPL map[string][]string
	CurrentDBPL  map[string][]string
	HostnamePL   map[string][]string
	// PAYLOADS: map[dbms]map[technique][]PayloadEntry
	Payloads     map[string]map[string][]PayloadEntry

	SQLErrors      map[string][]string
	AvoidParams    []string
	InjectHeaders  []string
	DBsCountPL     map[string][]string
	DBsNamesPL     map[string][]string
	TblsCountPL    map[string][]string
	TblsNamesPL    map[string][]string
	ColsCountPL    map[string][]string
	ColsNamesPL    map[string][]string
	RecsCountPL    map[string][]string
	RecsDumpPL     map[string][]string

	UserAgents []string
)

type rawPayloads struct {
	NOC     map[string]string              `json:"NUMBER_OF_CHARACTERS_PAYLOADS"`
	Length  map[string][]string            `json:"LENGTH_PAYLOADS"`
	DataExtr map[string]map[string]string  `json:"DATA_EXTRACTION_PAYLOADS"`
	Regex   map[string]string              `json:"REGEX"`
	Banner  map[string][]string            `json:"PAYLOADS_BANNER"`
	CurUser map[string][]string            `json:"PAYLOADS_CURRENT_USER"`
	CurDB   map[string][]string            `json:"PAYLOADS_CURRENT_DATABASE"`
	Hostname map[string][]string           `json:"PAYLOADS_HOSTNAME"`
	Payloads map[string]map[string][]PayloadEntry `json:"PAYLOADS"`
}

type rawExtra struct {
	SQLErrors    map[string][]string `json:"SQL_ERRORS"`
	AvoidParams  []string            `json:"AVOID_PARAMS"`
	InjectHdrs   []string            `json:"INJECTABLE_HEADERS"`
	DBsCount     map[string][]string `json:"PAYLOADS_DBS_COUNT"`
	DBsNames     map[string][]string `json:"PAYLOADS_DBS_NAMES"`
	TblsCount    map[string][]string `json:"PAYLOADS_TBLS_COUNT"`
	TblsNames    map[string][]string `json:"PAYLOADS_TBLS_NAMES"`
	ColsCount    map[string][]string `json:"PAYLOADS_COLS_COUNT"`
	ColsNames    map[string][]string `json:"PAYLOADS_COLS_NAMES"`
	RecsCount    map[string][]string `json:"PAYLOADS_RECS_COUNT"`
	RecsDump     map[string][]string `json:"PAYLOADS_RECS_DUMP"`
}

func init() {
	once.Do(func() {
		var p rawPayloads
		if err := json.Unmarshal(payloadsRaw, &p); err != nil {
			panic(fmt.Sprintf("payloads.json parse error: %v", err))
		}
		NOCPayloads   = p.NOC
		LengthPL      = p.Length
		DataExtrPL    = p.DataExtr
		Regex         = p.Regex
		BannerPL      = p.Banner
		CurrentUserPL = p.CurUser
		CurrentDBPL   = p.CurDB
		HostnamePL    = p.Hostname
		Payloads      = p.Payloads

		var e rawExtra
		if err := json.Unmarshal(extraRaw, &e); err != nil {
			panic(fmt.Sprintf("extra.json parse error: %v", err))
		}
		SQLErrors     = e.SQLErrors
		AvoidParams   = e.AvoidParams
		InjectHeaders = e.InjectHdrs
		DBsCountPL    = e.DBsCount
		DBsNamesPL    = e.DBsNames
		TblsCountPL   = e.TblsCount
		TblsNamesPL   = e.TblsNames
		ColsCountPL   = e.ColsCount
		ColsNamesPL   = e.ColsNames
		RecsCountPL   = e.RecsCount
		RecsDumpPL    = e.RecsDump

		var uas []string
		if err := json.Unmarshal(uasRaw, &uas); err != nil {
			panic(fmt.Sprintf("uas.json parse error: %v", err))
		}
		UserAgents = uas
	})
}

// GetPayloads returns all entries for a given dbms+technique.
// dbms may be "BooleanTests", "MySQL", "Oracle", etc.
func GetPayloads(dbms, technique string) []PayloadEntry {
	if Payloads == nil {
		return nil
	}
	return Payloads[dbms][technique]
}
