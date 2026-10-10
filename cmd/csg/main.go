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
var version = "0.6.0-beta"

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
	case "anomalies":
		err = cmdAnomalies(ctx, args[1:], stdout)
	case "remediate":
		err = cmdRemediate(ctx, args[1:], stdout)
	case "run":
		err = cmdRun(ctx, args[1:], stdout)
	case "report":
		err = cmdReport(ctx, args[1:], stdout)
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
  ingest tfstate <path>        Load a terraform.tfstate file or a directory of *.tf files
  query "<SQL>"                Run a read-only SQL query (tables: cur, cloudtrail_events, tf_resources)
  analyze                      Run 15 cost and 20 security rules and print a prioritized backlog
  anomalies                    Show the STL + Isolation Forest cost-anomaly scores per series
  remediate <finding-id>       Generate a Terraform patch with an LLM and verify it (never applied)
  run                          Ingest, analyze, rank, and report in one step (--sample or --input <dir>)
  report                       Render the backlog from the local store as html, markdown, json, or sarif
  version                      Print version
  help                         Print this help

Common flags:
  --db <path>        Local database file (default .csg/csg.db, or $CSG_DB)

analyze flags:
  --profile <name>   Weighting profile: devops (default), finops, security, cxo
  --weights a,b,g    Explicit alpha,beta,gamma, overrides --profile (e.g. 0.6,0.3,0.1)
  --format <fmt>     Output format: table (default) or json
  --top <n>          Show only the first n backlog items

anomalies flags:
  --series <key>     Print every day of one series (e.g. AmazonEC2/booking)

run flags:
  --sample           Analyze the bundled sample account (no files, no AWS credentials)
  --input <dir>      Directory with CUR (.parquet/.csv), CloudTrail (.json), and Terraform (.tfstate/.tf) files
  --report <path>    Write a report; the format follows the extension (.html, .md, .json, .sarif)
  --profile, --weights, --top   As for analyze
  --stats            Print stage timings, throughput, and memory use
  --db <path>        Keep the local database (default: temporary)

report flags:
  --format <fmt>     html, markdown (default), json, or sarif
  --out <path>       Write to a file instead of standard output
  --profile, --weights, --top, --sarif-uri

remediate flags:
  --llm-provider <p> ollama (default, local), openai (needs --allow-remote), or replay
  --model <name>     Model (default llama3.1:8b for ollama)
  --fixture <file>   Recorded responses for --llm-provider replay
  --record <file>    Save the live model's responses as a fixture

Examples:
  csg run --sample --report out.html
  csg run --input ./testdata --report out.sarif --stats
  csg report --format sarif --out csg.sarif
  csg ingest cur ./testdata/sample-cur.parquet
  csg ingest cloudtrail ./testdata/sample-events.json
  csg ingest tfstate ./testdata/terraform.tfstate
  csg query "SELECT service, ROUND(SUM(cost), 2) AS cost FROM cur GROUP BY 1 ORDER BY 2 DESC"
  csg analyze --profile finops --top 10
  csg anomalies --series AmazonEC2/booking
  csg remediate SEC-EC2-IMDSV2-001:i-0a1b2c3d4e5f60042 --llm-provider replay --fixture testdata/llm/imdsv2-approved.json

Docs: https://github.com/wisnuanggoro/cloudspendguard
`)
}
