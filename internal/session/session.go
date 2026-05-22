package session

import (
	"crypto/md5"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

// Filepaths holds session-related file paths for a target.
type Filepaths struct {
	Session  string
	Logs     string
	Filepath string
}

// PayloadRecord maps to a tbl_payload row.
type PayloadRecord struct {
	ID            int64
	Title         string
	Attempts      int
	Payload       string
	Vector        string
	Backend       string
	Parameter     string
	InjectionType string
	PayloadType   string
	Endpoint      string
	ParameterType string
	String        string
	NotString     string
	Attack01      string
	Cases         string
}

// StorageRecord maps to a storage row.
type StorageRecord struct {
	ID     int64
	Value  string
	Length int
}

// Session manages the SQLite session file for a target.
type Session struct {
	mu  sync.Mutex
	dbs map[string]*sql.DB // path → *sql.DB
}

func New() *Session {
	return &Session{dbs: make(map[string]*sql.DB)}
}

func (s *Session) db(path string) (*sql.DB, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if db, ok := s.dbs[path]; ok {
		return db, nil
	}
	db, err := sql.Open("sqlite", path+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s.dbs[path] = db
	return db, nil
}

// GenerateFilepath builds the session directory + file paths for a target URL.
// If flushSession, the existing session file is deleted.
func (s *Session) GenerateFilepath(rawURL, method, data string, flushSession bool) (Filepaths, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return Filepaths{}, err
	}
	host := parsed.Hostname()

	// hash of url+method+data for uniqueness
	h := fmt.Sprintf("%x", md5.Sum([]byte(rawURL+method+data)))[:8]
	dir := filepath.Join(os.Getenv("HOME"), ".sqlex", host, h)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return Filepaths{}, err
	}
	sessionFile := filepath.Join(dir, "session.sqlite")
	logFile := filepath.Join(dir, "log")

	if flushSession {
		_ = os.Remove(sessionFile)
		// close existing db if open
		s.mu.Lock()
		if db, ok := s.dbs[sessionFile]; ok {
			db.Close()
			delete(s.dbs, sessionFile)
		}
		s.mu.Unlock()
	}

	return Filepaths{
		Session:  sessionFile,
		Logs:     logFile,
		Filepath: dir,
	}, nil
}

// Init creates or validates the schema in the session file.
func (s *Session) Init(path string) error {
	db, err := s.db(path)
	if err != nil {
		return err
	}
	_, err = db.Exec(schemaDDL)
	return err
}

// SavePayload inserts an injection fingerprint into tbl_payload.
func (s *Session) SavePayload(path string, r PayloadRecord) (int64, error) {
	db, err := s.db(path)
	if err != nil {
		return 0, err
	}
	res, err := db.Exec(sqlInsertPayload,
		r.Title, r.Attempts, r.Payload, r.Vector, r.Backend,
		r.Parameter, r.InjectionType, r.PayloadType, r.Endpoint,
		r.ParameterType, r.String, r.NotString, r.Attack01, r.Cases,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FetchPayload returns the first tbl_payload row, or nil if empty.
func (s *Session) FetchPayload(path string) (*PayloadRecord, error) {
	db, err := s.db(path)
	if err != nil {
		return nil, err
	}
	row := db.QueryRow(sqlSelectPayload)
	var r PayloadRecord
	err = row.Scan(&r.ID, &r.Title, &r.Attempts, &r.Payload, &r.Vector,
		&r.Backend, &r.Parameter, &r.InjectionType, &r.PayloadType,
		&r.Endpoint, &r.ParameterType, &r.String, &r.NotString,
		&r.Attack01, &r.Cases)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// PayloadCount returns number of rows in tbl_payload.
func (s *Session) PayloadCount(path string) (int, error) {
	db, err := s.db(path)
	if err != nil {
		return 0, err
	}
	var n int
	return n, db.QueryRow(sqlCountPayload).Scan(&n)
}

// UpsertResult inserts or updates a storage row for the given dump type.
func (s *Session) UpsertResult(path, dumpType, value string, length int) error {
	db, err := s.db(path)
	if err != nil {
		return err
	}
	// Check if exists
	var id int64
	var existing string
	err = db.QueryRow(`SELECT id, value FROM storage WHERE type=?`, dumpType).Scan(&id, &existing)
	if err == sql.ErrNoRows {
		_, err = db.Exec(sqlInsertStorage, value, length, dumpType)
		return err
	}
	if err != nil {
		return err
	}
	_, err = db.Exec(sqlUpdateStorage, value, id, dumpType)
	return err
}

// FetchStoredResult retrieves a partial result for the given dump type.
// Returns (value, length, rowID, ok).
func (s *Session) FetchStoredResult(path, dumpType string) (string, int, int64, bool) {
	db, err := s.db(path)
	if err != nil {
		return "", 0, 0, false
	}
	var id int64
	var value string
	var length int
	err = db.QueryRow(sqlSelectStorage, dumpType).Scan(&id, &value, &length)
	if err != nil {
		return "", 0, 0, false
	}
	return value, length, id, true
}

// DumpToCSV writes results to a CSV file under the session directory.
func (s *Session) DumpToCSV(path, database, table string, fieldNames []string, rows [][]string) error {
	dir := filepath.Join(filepath.Dir(path), "dump", database)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	csvPath := filepath.Join(dir, table+".csv")
	f, err := os.Create(csvPath)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if len(fieldNames) > 0 {
		_ = w.Write(fieldNames)
	}
	for _, row := range rows {
		_ = w.Write(row)
	}
	w.Flush()
	return w.Error()
}

// MarshalAttack01 serialises an HTTPResponse to JSON for storage.
func MarshalAttack01(v interface{}) string {
	if v == nil {
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// CasesStr serialises the cases slice for storage.
func CasesStr(cases []string) string {
	return strings.Join(cases, ",")
}
