// Package main is the entrypoint for the csg CLI.
//
// csg is CloudSpendGuard, a unified FinOps and cloud security posture tool.
// See https://github.com/wisnuanggoro/cloudspendguard for full documentation.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
)

// version is overridden at release time with
// -ldflags "-X main.version=$(git describe --tags)".
var version = "0.2.0-analyze-alpha"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run executes one CLI invocation and returns the process exit code. It is
// separated from main so the CLI can be exercised in tests.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	var err error
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "csg", version)
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	case "ingest":
		err = cmdIngest(ctx, args[1:], stdout)
	case "query":
		err = cmdQuery(ctx, args[1:], stdout)
	case "analyze":
		err = cmdAnalyze(ctx, args[1:], stdout)
	case "report", "run":
		fmt.Fprintf(stderr, "csg %s: planned for Unit 6 (v0.6.0-beta); use `csg analyze` for now\n", args[0])
		return 2
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		printUsage(stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		if _, ok := err.(usageError); ok {
			return 2
		}
		return 1
	}
	return 0
}

type usageError string

func (e usageError) Error() string { return string(e) }

func printUsage(w io.Writer) {
	fmt.Fprint(w, `csg, CloudSpendGuard: unified FinOps and cloud security posture for AWS

Usage:
  csg <command> [flags]

Commands:
  ingest cur <path>...         Load AWS CUR exports (.parquet, .csv, .csv.gz, or a directory)
  ingest cloudtrail <path>...  Load CloudTrail JSON logs (.json, .json.gz, or a directory)
  ingest tfstate <path>        Load a terraform.tfstate file
  query "<SQL>"                Run a read-only SQL query (tables: cur, cloudtrail_events, tf_resources)
  analyze                      Run cost and security rules and print a prioritized backlog
  version                      Print version
  help                         Print this help

Common flags:
  --db <path>        Local database file (default .csg/csg.db, or $CSG_DB)

analyze flags:
  --profile <name>   Weighting profile: devops (default), finops, security, cxo
  --format <fmt>     Output format: table (default) or json

Examples:
  csg ingest cur ./testdata/sample-cur.parquet
  csg ingest cloudtrail ./testdata/sample-events.json
  csg ingest tfstate ./testdata/terraform.tfstate
  csg query "SELECT service, ROUND(SUM(cost), 2) AS cost FROM cur GROUP BY 1 ORDER BY 2 DESC"
  csg analyze --profile finops

Docs: https://github.com/wisnuanggoro/cloudspendguard
`)
}
