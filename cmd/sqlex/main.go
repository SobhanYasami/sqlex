package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/SobhanYasami/sqlex/internal/config"
	"github.com/SobhanYasami/sqlex/internal/engine"
	"github.com/spf13/cobra"
)

var version = "1.0.0"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cfg := config.DefaultConfig()

	var (
		rawHeaders  string
		technique   string
		delay       float64
		timeout     float64
		timeSec     float64
		followRedir string
	)

	cmd := &cobra.Command{
		Use:   "sqlex",
		Short: "Advanced SQL injection detection and exploitation tool",
		Long: color.New(color.FgCyan, color.Bold).Sprint(`
 ██████╗  ██████╗ ██╗     ███████╗██╗  ██╗
██╔════╝ ██╔═══██╗██║     ██╔════╝╚██╗██╔╝
╚█████╗  ██║   ██║██║     █████╗   ╚███╔╝
 ╚═══██╗ ██║▄▄ ██║██║     ██╔══╝   ██╔██╗
██████╔╝ ╚██████╔╝███████╗███████╗██╔╝ ██╗
╚═════╝   ╚══▀▀═╝ ╚══════╝╚══════╝╚═╝  ╚═╝`) +
			fmt.Sprintf("\n                                  v%s\n", version),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.URL == "" && cfg.RequestFile == "" && cfg.BulkFile == "" {
				return fmt.Errorf("you must provide -u/--url, -r/--request-file, or -m/--bulk-file")
			}

			// Parse technique
			if technique != "" {
				cfg.Technique = config.ParseTechniques(technique)
			}

			// Parse durations
			cfg.Delay = time.Duration(delay * float64(time.Second))
			cfg.Timeout = time.Duration(timeout * float64(time.Second))
			cfg.TimeSec = time.Duration(timeSec * float64(time.Second))

			// Parse headers
			if rawHeaders != "" {
				cfg.Headers = parseHeaders(rawHeaders)
			}

			// Parse follow-redirect
			if followRedir != "" {
				switch strings.ToLower(followRedir) {
				case "true", "yes", "1":
					t := true
					cfg.FollowRedir = &t
				case "false", "no", "0":
					f := false
					cfg.FollowRedir = &f
				}
			}

			// Signal context for graceful Ctrl-C
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			eng, err := engine.New(cfg)
			if err != nil {
				return fmt.Errorf("init: %w", err)
			}
			return eng.Run(ctx)
		},
	}

	// Target
	f := cmd.Flags()
	f.StringVarP(&cfg.URL, "url", "u", "", "Target URL (e.g. 'http://target/page?id=1')")
	f.StringVarP(&cfg.Data, "data", "d", "", "Data string to be sent through POST")
	f.StringVar(&cfg.Cookie, "cookie", "", "HTTP Cookie header value")
	f.StringVarP(&rawHeaders, "headers", "H", "", "Extra HTTP headers (newline-separated)")
	f.StringVar(&cfg.Proxy, "proxy", "", "HTTP proxy (e.g. 'http://127.0.0.1:8080')")
	f.StringVarP(&cfg.RequestFile, "request-file", "r", "", "Load HTTP request from file")
	f.StringVarP(&cfg.BulkFile, "bulk-file", "m", "", "Scan multiple targets from file")

	// Detection
	f.StringVarP(&technique, "technique", "t", "BT", "SQL injection techniques to use (B=boolean, E=error, T=time)")
	f.StringVar(&cfg.DBMS, "dbms", "", "Force back-end DBMS (e.g. MySQL)")
	f.IntVar(&cfg.Level, "level", 1, "Level of tests to perform (1-5)")
	f.StringVar(&cfg.Param, "test-parameter", "", "Comma-separated list of parameters to test")
	f.StringVar(&cfg.Prefix, "prefix", "", "Injection payload prefix string")
	f.StringVar(&cfg.Suffix, "suffix", "", "Injection payload suffix string")
	f.StringVar(&cfg.MatchString, "string", "", "String to match when query is evaluated as True")
	f.StringVar(&cfg.NotString, "not-string", "", "String to match when query is evaluated as False")
	f.IntVar(&cfg.Code, "code", 0, "HTTP code to match when query is evaluated as True")
	f.BoolVar(&cfg.TextOnly, "text-only", false, "Compare pages based only on their textual content")

	// Request
	f.Float64Var(&delay, "delay", 0, "Delay in seconds between each HTTP request")
	f.Float64Var(&timeout, "timeout", 30, "Seconds to wait before timeout connection")
	f.Float64Var(&timeSec, "time-sec", 5, "Seconds to delay the response for time-based injection")
	f.IntVar(&cfg.Retry, "retries", 3, "Retries when the connection timeouts")
	f.IntVar(&cfg.Threads, "threads", 1, "Max number of concurrent HTTP requests")
	f.BoolVar(&cfg.SkipURLEnc, "skip-urlencode", false, "Skip URL encoding of payload data")
	f.StringVar(&cfg.SafeChars, "safe-chars", "", "Skip URL encoding of specific characters in payload")
	f.BoolVar(&cfg.RandomAgent, "random-agent", false, "Use randomly selected HTTP User-Agent header value")
	f.BoolVar(&cfg.MobileAgent, "mobile", false, "Imitate smartphone through HTTP User-Agent")
	f.StringVar(&followRedir, "follow-redirect", "", "Follow HTTP redirects (true/false)")
	f.BoolVar(&cfg.ForceSSL, "force-ssl", false, "Force usage of SSL/HTTPS")

	// Optimization
	f.StringVar(&cfg.FetchUsing, "fetch-using", "", "Fetch data using operator: greater/between/in/equal")

	// Session
	f.StringVar(&cfg.SessionDir, "session-dir", "", "Override session directory path")
	f.BoolVar(&cfg.FlushSession, "flush-session", false, "Flush session files for current target")
	f.BoolVar(&cfg.FreshQueries, "fresh-queries", false, "Ignore query results stored in session file")

	// Enumeration
	f.BoolVar(&cfg.GetBanner, "banner", false, "Retrieve DBMS banner")
	f.BoolVar(&cfg.CurrentUser, "current-user", false, "Retrieve DBMS current user")
	f.BoolVar(&cfg.CurrentDB, "current-db", false, "Retrieve DBMS current database")
	f.BoolVar(&cfg.Hostname, "hostname", false, "Retrieve DBMS server hostname")
	f.BoolVar(&cfg.GetDBs, "dbs", false, "Enumerate DBMS databases")
	f.BoolVar(&cfg.GetTables, "tables", false, "Enumerate DBMS database tables")
	f.BoolVar(&cfg.GetColumns, "columns", false, "Enumerate DBMS database table columns")
	f.BoolVar(&cfg.Dump, "dump", false, "Dump DBMS database table entries")
	f.BoolVar(&cfg.CountOnly, "count", false, "Retrieve number of entries for table(s)")
	f.StringVarP(&cfg.DB, "db", "D", "", "DBMS database to enumerate")
	f.StringVarP(&cfg.Table, "table", "T", "", "DBMS database table to enumerate")
	f.StringVarP(&cfg.Columns, "col", "C", "", "DBMS database table column(s) to enumerate")
	f.IntVar(&cfg.StartLimit, "start", 0, "First dump table entry to retrieve")
	f.IntVar(&cfg.StopLimit, "stop", 0, "Last dump table entry to retrieve")

	// Misc
	f.BoolVarP(&cfg.Batch, "batch", "b", false, "Never ask for user input, use default behaviour")
	f.IntVarP(&cfg.Verbose, "verbose", "v", 1, "Verbosity level (0-6)")
	f.BoolVar(&cfg.SQLShell, "sql-shell", false, "Prompt for an interactive SQL shell")

	return cmd
}

func parseHeaders(raw string) http.Header {
	h := make(http.Header)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		h.Add(k, v)
	}
	return h
}
