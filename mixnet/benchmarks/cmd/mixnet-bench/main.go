package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if os.Getenv("MIXNET_BENCH_VERBOSE") == "" {
		log.SetOutput(io.Discard)
	}
	opts, err := parseOptions()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mixnet-bench: %v\n", err)
		os.Exit(2)
	}
	if err := runSuite(opts); err != nil {
		fmt.Fprintf(os.Stderr, "mixnet-bench: %v\n", err)
		os.Exit(1)
	}
}

func parseOptions() (suiteOptions, error) {
	defaultOutput := filepath.Join("mixnet", "benchmarks", "output", time.Now().Format("20060102-150405"))

	var (
		profile     = flag.String("profile", "full", "benchmark profile: smoke, quick, or full")
		outputDir   = flag.String("output-dir", defaultOutput, "directory for raw data, summaries, graphs, and proof artifacts")
		sizes       = flag.String("sizes", "", "comma-separated sizes like 1KB,64KB,1MB,50MB (overrides profile)")
		hops        = flag.String("hops", "", "comma-separated hop counts (overrides profile)")
		circuits    = flag.String("circuits", "", "comma-separated circuit counts (overrides profile)")
		runs        = flag.Int("runs", 0, "runs per scenario and size (overrides profile)")
		groups      = flag.String("groups", "", "comma-separated benchmark groups (overrides profile)")
		timeout     = flag.Duration("timeout", 0, "per-run timeout (default depends on selected sizes)")
		visualProof = flag.Bool("visual-proof", true, "generate the post-run 64KB live proof capture for quick profile")
	)
	flag.Parse()

	opts, err := profileOptions(strings.ToLower(strings.TrimSpace(*profile)))
	if err != nil {
		return suiteOptions{}, err
	}
	opts.OutputDir = *outputDir
	opts.Timeout = *timeout
	opts.VisualProof = *visualProof

	if strings.TrimSpace(*sizes) != "" {
		opts.SizeSpec = *sizes
	}
	if strings.TrimSpace(*hops) != "" {
		opts.HopSpec = *hops
	}
	if strings.TrimSpace(*circuits) != "" {
		opts.CircuitSpec = *circuits
	}
	if *runs > 0 {
		opts.Runs = *runs
	}
	if strings.TrimSpace(*groups) != "" {
		opts.GroupSpec = *groups
	}

	return opts.normalize()
}
