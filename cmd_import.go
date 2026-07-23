package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"orion-auth-backend/config"
	"orion-auth-backend/database"
	"orion-auth-backend/importer"
	"orion-auth-backend/importer/logto"
)

// runImport handles `orion-auth import <source> [flags]` and returns a process
// exit code. It is dispatched from main() before the HTTP server boots.
func runImport(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: orion-auth import <source> [flags]")
		fmt.Fprintln(os.Stderr, "  sources: logto")
		return 2
	}
	switch args[0] {
	case "logto":
		return runImportLogto(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown import source %q (supported: logto)\n", args[0])
		return 2
	}
}

func runImportLogto(args []string) int {
	fs := flag.NewFlagSet("import logto", flag.ContinueOnError)
	dsn := fs.String("source-dsn", "", "Logto Postgres DSN (required), e.g. postgres://user:pass@host:5432/logto?sslmode=disable")
	tenant := fs.String("tenant", "default", "Logto tenant id to import")
	mappingPath := fs.String("mapping", "", "path to the mapping JSON file (required)")
	dryRun := fs.Bool("dry-run", false, "resolve and report without writing to the target database")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dsn == "" || *mappingPath == "" {
		fmt.Fprintln(os.Stderr, "both --source-dsn and --mapping are required")
		fs.Usage()
		return 2
	}

	mapping, err := loadMapping(*mappingPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load mapping: %v\n", err)
		return 1
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 1
	}
	db, err := database.Connect(&cfg.Database)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect target db: %v\n", err)
		return 1
	}

	ctx := context.Background()
	src, err := logto.Open(ctx, *dsn, *tenant)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open logto source: %v\n", err)
		return 1
	}
	defer src.Close()

	engine, err := importer.NewEngine(db, mapping, src.Name(), *dryRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	users, err := src.Users(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read logto users: %v\n", err)
		return 1
	}
	fmt.Printf("read %d user(s) from logto tenant %q\n", len(users), *tenant)

	rep, err := engine.Import(ctx, users)
	printReport(rep, *dryRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "import aborted: %v\n", err)
		return 1
	}
	return 0
}

func loadMapping(path string) (importer.Mapping, error) {
	var m importer.Mapping
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("parse mapping json: %w", err)
	}
	return m, nil
}

func printReport(rep *importer.Report, dryRun bool) {
	if rep == nil {
		return
	}
	mode := "imported"
	if dryRun {
		mode = "would import (dry-run)"
	}
	fmt.Println("─── import report ───")
	fmt.Printf("  total source users : %d\n", rep.Total)
	fmt.Printf("  %-18s : %d\n", mode, rep.Created)
	fmt.Printf("  roles assigned     : %d\n", rep.RolesAssigned)
	fmt.Printf("  federation links   : %d\n", rep.LinksCreated)
	fmt.Printf("  forced reset       : %d (unsupported password → must set password)\n", rep.ForcedReset)
	fmt.Printf("  social-only        : %d (no source password)\n", rep.SocialOnly)
	fmt.Printf("  skipped (exists)   : %d\n", rep.SkippedExisting)
	fmt.Printf("  skipped (no email) : %d\n", rep.SkippedNoEmail)
	fmt.Printf("  skipped (no pwd)   : %d\n", rep.SkippedNoPassword)

	printCounts("unmapped identity providers (skipped)", rep.UnmappedProviders)
	printCounts("unmapped roles (skipped)", rep.UnmappedRoles)

	if len(rep.Warnings) > 0 {
		fmt.Printf("  warnings (%d):\n", len(rep.Warnings))
		for _, w := range rep.Warnings {
			fmt.Printf("    - %s\n", w)
		}
	}
}

func printCounts(label string, counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("  %s:\n", label)
	for _, k := range keys {
		fmt.Printf("    - %s: %d\n", k, counts[k])
	}
}
