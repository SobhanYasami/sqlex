package session

const schemaDDL = `
DROP TABLE IF EXISTS tbl_payload;
DROP TABLE IF EXISTS storage;
CREATE TABLE tbl_payload (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  title           TEXT NOT NULL,
  attempts        INTEGER NOT NULL,
  payload         TEXT NOT NULL,
  vector          TEXT NOT NULL,
  backend         TEXT NOT NULL,
  parameter       TEXT NOT NULL,
  injection_type  TEXT NOT NULL,
  payload_type    TEXT NOT NULL,
  endpoint        TEXT NOT NULL,
  parameter_type  TEXT,
  string          TEXT,
  not_string      TEXT,
  attack01        TEXT,
  cases           TEXT NOT NULL DEFAULT ""
);
CREATE TABLE storage (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  value  TEXT,
  length INTEGER,
  type   TEXT
);
CREATE INDEX IF NOT EXISTS idx_type ON storage (type);
`

const sqlInsertPayload = `
INSERT INTO tbl_payload
  (title,attempts,payload,vector,backend,parameter,injection_type,payload_type,endpoint,parameter_type,string,not_string,attack01,cases)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);
`

const sqlInsertStorage = `INSERT INTO storage (value, length, type) VALUES (?,?,?);`
const sqlUpdateStorage = `UPDATE storage SET value=? WHERE id=? AND type=?;`
const sqlSelectPayload = `SELECT * FROM tbl_payload LIMIT 1;`
const sqlSelectStorage = `SELECT id, value, length FROM storage WHERE type=?;`
const sqlCountPayload  = `SELECT COUNT(*) FROM tbl_payload;`
