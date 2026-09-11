// Package main is the entrypoint for the csg CLI.
//
// csg is CloudSpendGuard — a unified FinOps + Cloud Security Posture tool.
// See https://github.com/wisnuanggoro/cloudspendguard for full documentation.
package main

import (
	"fmt"
	"os"
)

const version = "0.0.1-scaffold"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println("csg", version)
	case "ingest":
		fmt.Println("TODO: ingest CUR / CloudTrail / Terraform state")
	case "analyze":
		fmt.Println("TODO: run cost + security analyzers and prioritize")
	case "report":
		fmt.Println("TODO: render Markdown / HTML / JSON / SARIF report")
	case "run":
		fmt.Println("TODO: ingest -> analyze -> report pipeline")
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Println(`csg — CloudSpendGuard

Usage:
  csg <command> [flags]

Commands:
  ingest    Ingest CUR / CloudTrail / Terraform state into the local store
  analyze   Run cost + security analyzers and produce a prioritized backlog
  report    Render a report (markdown|html|json|sarif)
  run       End-to-end: ingest -> analyze -> report
  version   Print version
  help      Print this help

Docs: https://github.com/wisnuanggoro/cloudspendguard`)
}
