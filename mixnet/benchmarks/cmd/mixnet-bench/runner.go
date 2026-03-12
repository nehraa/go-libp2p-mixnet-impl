package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	mrand "math/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipfs/go-cid"
	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	routingcore "github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/mixnet"
	"github.com/libp2p/go-libp2p/mixnet/ces"
	"github.com/libp2p/go-libp2p/mixnet/relay"
	"github.com/multiformats/go-multiaddr"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	groupModeOverview    = "mode-overview"
	groupHopSweep        = "hop-sweep"
	groupCircuitSweep    = "circuit-sweep"
	groupEfficiencyGrid  = "efficiency-grid"
	groupCESPipeline     = "ces-pipeline"
	groupThresholdSweep  = "threshold-sweep"
	groupFeatureOverhead = "feature-overheads"
	groupSelectionModes  = "selection-modes"
	groupCompression     = "compression-modes"
	groupFocusedOnion    = "focused-onion"

	measurementDirect = "direct"
	measurementMixnet = "mixnet"
	measurementCES    = "ces-pipeline"
	measurementLocal  = "local-session"

	directProtocol             protocol.ID = "/mixnet-bench/direct/1.0.0"
	directKeyProtocol          protocol.ID = "/mixnet-bench/direct-key/1.0.0"
	benchmarkChunkSize                     = 256 * 1024
	benchmarkLargeChunkSize1MB             = 1 * 1024 * 1024
	benchmarkLargeChunkSize2MB             = 2 * 1024 * 1024
	benchmarkLargeChunkSize4MB             = 4 * 1024 * 1024
)

var orderedGroups = []string{
	groupModeOverview,
	groupHopSweep,
	groupCircuitSweep,
	groupEfficiencyGrid,
	groupCESPipeline,
	groupThresholdSweep,
	groupFeatureOverhead,
	groupSelectionModes,
	groupCompression,
	groupFocusedOnion,
}

type suiteOptions struct {
	Profile     string
	OutputDir   string
	SizeSpec    string
	HopSpec     string
	CircuitSpec string
	GroupSpec   string
	Sizes       []int
	Hops        []int
	Circuits    []int
	Groups      map[string]bool
	Runs        int
	VisualProof bool
	// SizeRunOverrides allows a per-size run count override (bytes -> runs).
	SizeRunOverrides map[int]int
	Timeout          time.Duration
}

type scenario struct {
	ID                     string
	Category               string
	Label                  string
	Mode                   string
	Measurement            string
	StreamProfile          string
	StreamKind             string
	StreamQuality          string
	StreamWrites           bool
	StreamBitrateKbps      int
	StreamSegmentMS        int
	StreamDurationSec      int
	StreamWriteSizeBytes   int
	EnableSessionRouting   bool
	HopCount               int
	CircuitCount           int
	UseCESPipeline         bool
	UseCSE                 bool
	UseCompressionOnly     bool
	Compression            string
	ErasureThreshold       int
	SelectionMode          mixnet.SelectionMode
	RandomnessFactor       float64
	PayloadPaddingStrategy mixnet.PaddingStrategy
	PayloadPaddingMin      int
	PayloadPaddingMax      int
	PayloadPaddingBuckets  []int
	HeaderPaddingEnabled   bool
	HeaderPaddingMin       int
	HeaderPaddingMax       int
	EnableAuthTag          bool
	AuthTagSize            int
	MaxJitter              int
	Sizes                  []int
}

type runRecord struct {
	ScenarioID              string    `json:"scenario_id"`
	Category                string    `json:"category"`
	Label                   string    `json:"label"`
	Measurement             string    `json:"measurement"`
	Mode                    string    `json:"mode"`
	StreamProfile           string    `json:"stream_profile"`
	StreamKind              string    `json:"stream_kind"`
	StreamQuality           string    `json:"stream_quality"`
	StreamWrites            bool      `json:"stream_writes"`
	StreamBitrateKbps       int       `json:"stream_bitrate_kbps"`
	StreamSegmentMS         int       `json:"stream_segment_ms"`
	StreamDurationSec       int       `json:"stream_duration_sec"`
	StreamWriteSizeBytes    int       `json:"stream_write_size_bytes"`
	EnableSessionRouting    bool      `json:"enable_session_routing"`
	SizeBytes               int       `json:"size_bytes"`
	SizeLabel               string    `json:"size_label"`
	RunIndex                int       `json:"run_index"`
	TimestampUTC            time.Time `json:"timestamp_utc"`
	HopCount                int       `json:"hop_count"`
	CircuitCount            int       `json:"circuit_count"`
	UseCESPipeline          bool      `json:"use_ces_pipeline"`
	UseCSE                  bool      `json:"use_cse"`
	UseCompressionOnly      bool      `json:"use_compression_only"`
	Compression             string    `json:"compression"`
	ErasureThreshold        int       `json:"erasure_threshold"`
	ErasureThresholdPercent float64   `json:"erasure_threshold_percent"`
	SelectionMode           string    `json:"selection_mode"`
	PayloadPaddingStrategy  string    `json:"payload_padding_strategy"`
	HeaderPaddingEnabled    bool      `json:"header_padding_enabled"`
	EnableAuthTag           bool      `json:"enable_auth_tag"`
	MaxJitterMS             int       `json:"max_jitter_ms"`
	ConnectMS               float64   `json:"connect_ms"`
	KeyExchangeMS           float64   `json:"key_exchange_ms"`
	TransferMS              float64   `json:"transfer_ms"`
	PipelineProcessMS       float64   `json:"pipeline_process_ms"`
	PipelineReconstructMS   float64   `json:"pipeline_reconstruct_ms"`
	TotalMS                 float64   `json:"total_ms"`
	PerHopMS                float64   `json:"per_hop_ms"`
	ThroughputMBps          float64   `json:"throughput_mib_per_s"`
	Excluded                bool      `json:"excluded"`
	Error                   string    `json:"error,omitempty"`
}

type summaryRecord struct {
	ScenarioID              string  `json:"scenario_id"`
	Category                string  `json:"category"`
	Label                   string  `json:"label"`
	Measurement             string  `json:"measurement"`
	Mode                    string  `json:"mode"`
	StreamProfile           string  `json:"stream_profile"`
	StreamKind              string  `json:"stream_kind"`
	StreamQuality           string  `json:"stream_quality"`
	StreamWrites            bool    `json:"stream_writes"`
	StreamBitrateKbps       int     `json:"stream_bitrate_kbps"`
	StreamSegmentMS         int     `json:"stream_segment_ms"`
	StreamDurationSec       int     `json:"stream_duration_sec"`
	StreamWriteSizeBytes    int     `json:"stream_write_size_bytes"`
	EnableSessionRouting    bool    `json:"enable_session_routing"`
	SizeBytes               int     `json:"size_bytes"`
	SizeLabel               string  `json:"size_label"`
	HopCount                int     `json:"hop_count"`
	CircuitCount            int     `json:"circuit_count"`
	UseCESPipeline          bool    `json:"use_ces_pipeline"`
	UseCSE                  bool    `json:"use_cse"`
	UseCompressionOnly      bool    `json:"use_compression_only"`
	Compression             string  `json:"compression"`
	ErasureThreshold        int     `json:"erasure_threshold"`
	ErasureThresholdPercent float64 `json:"erasure_threshold_percent"`
	SelectionMode           string  `json:"selection_mode"`
	PayloadPaddingStrategy  string  `json:"payload_padding_strategy"`
	HeaderPaddingEnabled    bool    `json:"header_padding_enabled"`
	EnableAuthTag           bool    `json:"enable_auth_tag"`
	MaxJitterMS             int     `json:"max_jitter_ms"`
	TotalRuns               int     `json:"total_runs"`
	KeptRuns                int     `json:"kept_runs"`
	ExcludedRunIndex        int     `json:"excluded_run_index"`
	ConnectMeanMS           float64 `json:"connect_mean_ms"`
	ConnectStdDevMS         float64 `json:"connect_stddev_ms"`
	KeyExchangeMeanMS       float64 `json:"key_exchange_mean_ms"`
	KeyExchangeStdDevMS     float64 `json:"key_exchange_stddev_ms"`
	TransferMeanMS          float64 `json:"transfer_mean_ms"`
	TransferStdDevMS        float64 `json:"transfer_stddev_ms"`
	ProcessMeanMS           float64 `json:"pipeline_process_mean_ms"`
	ProcessStdDevMS         float64 `json:"pipeline_process_stddev_ms"`
	ReconstructMeanMS       float64 `json:"pipeline_reconstruct_mean_ms"`
	ReconstructStdDevMS     float64 `json:"pipeline_reconstruct_stddev_ms"`
	TotalMeanMS             float64 `json:"total_mean_ms"`
	TotalStdDevMS           float64 `json:"total_stddev_ms"`
	PerHopMeanMS            float64 `json:"per_hop_mean_ms"`
	PerHopStdDevMS          float64 `json:"per_hop_stddev_ms"`
	ThroughputMeanMBps      float64 `json:"throughput_mean_mib_per_s"`
	ThroughputStdDevMBps    float64 `json:"throughput_stddev_mib_per_s"`
}

type streamWorkloadPreset struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Quality     string `json:"quality"`
	Label       string `json:"label"`
	BitrateKbps int    `json:"bitrate_kbps"`
	SegmentMS   int    `json:"segment_ms"`
	DurationSec int    `json:"duration_sec"`
}

var quickMediaProfiles = []streamWorkloadPreset{
	{ID: "audio-low", Kind: "audio", Quality: "low", Label: "Audio low", BitrateKbps: 96, SegmentMS: 1000, DurationSec: 30},
	{ID: "audio-medium", Kind: "audio", Quality: "medium", Label: "Audio medium", BitrateKbps: 192, SegmentMS: 1000, DurationSec: 30},
	{ID: "audio-high", Kind: "audio", Quality: "high", Label: "Audio high", BitrateKbps: 320, SegmentMS: 1000, DurationSec: 30},
	{ID: "video-480p", Kind: "video", Quality: "480p", Label: "Video 480p", BitrateKbps: 1500, SegmentMS: 1000, DurationSec: 60},
	{ID: "video-720p", Kind: "video", Quality: "720p", Label: "Video 720p", BitrateKbps: 4000, SegmentMS: 1000, DurationSec: 60},
	{ID: "video-1080p", Kind: "video", Quality: "1080p", Label: "Video 1080p", BitrateKbps: 8000, SegmentMS: 1000, DurationSec: 60},
}

type bestRecord struct {
	Mode            string  `json:"mode"`
	SizeBytes       int     `json:"size_bytes"`
	SizeLabel       string  `json:"size_label"`
	ScenarioID      string  `json:"scenario_id"`
	Label           string  `json:"label"`
	HopCount        int     `json:"hop_count"`
	CircuitCount    int     `json:"circuit_count"`
	TotalMeanMS     float64 `json:"total_mean_ms"`
	ThroughputMBps  float64 `json:"throughput_mean_mib_per_s"`
	PerHopMeanMS    float64 `json:"per_hop_mean_ms"`
	KeyExchangeMean float64 `json:"key_exchange_mean_ms"`
	TransferMeanMS  float64 `json:"transfer_mean_ms"`
}

type staticRouting struct {
	providers []peer.AddrInfo
	peers     map[peer.ID]peer.AddrInfo
}

type benchmarkNetwork struct {
	origin    *mixnet.Mixnet
	dest      *mixnet.Mixnet
	relays    []*mixnet.Mixnet
	cleanup   func()
	relayHost []host.Host
}

func profileOptions(name string) (suiteOptions, error) {
	switch name {
	case "smoke":
		return suiteOptions{
			Profile:     name,
			SizeSpec:    "1KB,64KB,1MB",
			HopSpec:     "1,2",
			CircuitSpec: "1,2,4",
			GroupSpec:   strings.Join([]string{groupModeOverview, groupHopSweep, groupCircuitSweep, groupCESPipeline, groupCompression}, ","),
			Runs:        12,
		}, nil
	case "quick":
		return suiteOptions{
			Profile:     name,
			SizeSpec:    "16MB,32MB,64MB,128MB,256MB,512MB,1GB",
			HopSpec:     "2",
			CircuitSpec: "1",
			GroupSpec:   groupFocusedOnion,
			Runs:        12,
		}, nil
	case "full":
		return suiteOptions{
			Profile:     name,
			SizeSpec:    "1KB,4KB,16KB,64KB,256KB,1MB,4MB,16MB,32MB,50MB",
			HopSpec:     "1,2,3,4",
			CircuitSpec: "1,2,3,4,5,6",
			GroupSpec:   strings.Join(orderedGroups, ","),
			Runs:        12,
		}, nil
	default:
		return suiteOptions{}, fmt.Errorf("unknown profile %q", name)
	}
}

func (o suiteOptions) normalize() (suiteOptions, error) {
	sizes, err := parseSizeList(o.SizeSpec)
	if err != nil {
		return suiteOptions{}, err
	}
	hops, err := parseIntList(o.HopSpec)
	if err != nil {
		return suiteOptions{}, err
	}
	circuits, err := parseIntList(o.CircuitSpec)
	if err != nil {
		return suiteOptions{}, err
	}
	groups, err := parseGroups(o.GroupSpec)
	if err != nil {
		return suiteOptions{}, err
	}
	if o.Runs < 1 {
		return suiteOptions{}, fmt.Errorf("runs must be at least 1")
	}
	o.Sizes = sizes
	o.Hops = hops
	o.Circuits = circuits
	o.Groups = groups
	if o.Timeout <= 0 {
		o.Timeout = defaultRunTimeoutForSizes(sizes)
	}
	return o, nil
}

func defaultRunTimeoutForSizes(sizes []int) time.Duration {
	maxSize := 0
	for _, size := range sizes {
		if size > maxSize {
			maxSize = size
		}
	}
	switch {
	case maxSize >= 512*1024*1024:
		return 10 * time.Minute
	case maxSize >= 128*1024*1024:
		return 5 * time.Minute
	default:
		return 2 * time.Minute
	}
}

func runSuite(opts suiteOptions) error {
	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	if os.Getenv("MIXNET_STREAM_TIMEOUT") == "" {
		_ = os.Setenv("MIXNET_STREAM_TIMEOUT", opts.Timeout.String())
	}
	if os.Getenv("MIXNET_MAX_ENCRYPTED_PAYLOAD") == "" {
		maxSize := opts.Sizes[len(opts.Sizes)-1]
		// Leave headroom for framing, onion overhead, padding, and the single-circuit baseline cases.
		payloadLimit := maxInt(256*1024, maxSize*2)
		_ = os.Setenv("MIXNET_MAX_ENCRYPTED_PAYLOAD", strconv.Itoa(payloadLimit))
	}

	scenarios := buildScenarios(opts)
	fmt.Printf("mixnet-bench: profile=%s scenarios=%d sizes=%d runs=%s output=%s\n",
		opts.Profile, len(scenarios), len(opts.Sizes), opts.runsSummary(), opts.OutputDir)

	totalWork := 0
	for _, sc := range scenarios {
		for _, size := range scenarioSizes(opts, sc) {
			totalWork += opts.runsForSize(size)
		}
	}
	runRecords := make([]*runRecord, 0, totalWork)
	workIndex := 0

	for _, sc := range scenarios {
		for _, size := range scenarioSizes(opts, sc) {
			runs := opts.runsForSize(size)
			for runIdx := 1; runIdx <= runs; runIdx++ {
				workIndex++
				fmt.Printf("[%d/%d] %s size=%s run=%d\n", workIndex, totalWork, sc.ID, formatBytes(size), runIdx)
				rec, err := executeScenario(opts, sc, size, runIdx)
				if err != nil {
					return err
				}
				runRecords = append(runRecords, rec)
				releaseBenchmarkMemoryForSize(size)
			}
		}
	}

	summaries, err := summarizeRuns(runRecords)
	if err != nil {
		return err
	}
	best := bestEfficiencySummaries(summaries)

	if err := writeMetadata(opts, scenarios); err != nil {
		return err
	}
	if err := writeRawRecords(opts.OutputDir, runRecords); err != nil {
		return err
	}
	if err := writeSummaryRecords(opts.OutputDir, summaries); err != nil {
		return err
	}
	if err := writeBestRecords(opts.OutputDir, best); err != nil {
		return err
	}

	var proofs []visualProofScenario
	if opts.VisualProof && opts.Profile == "quick" {
		proofs, err = runQuickVisualProof(opts)
		if err != nil {
			return err
		}
		if err := writeVisualProofFiles(opts.OutputDir, proofs); err != nil {
			return err
		}
	}
	if err := writeReport(opts.OutputDir, opts, summaries, best, proofs); err != nil {
		return err
	}

	fmt.Printf("mixnet-bench: complete. report=%s\n", filepath.Join(opts.OutputDir, "report.html"))
	return nil
}

func scenarioSizes(opts suiteOptions, sc scenario) []int {
	if len(sc.Sizes) > 0 {
		return sc.Sizes
	}
	return opts.Sizes
}

func releaseBenchmarkMemory() {
	runtime.GC()
	debug.FreeOSMemory()
	time.Sleep(100 * time.Millisecond)
}

func releaseBenchmarkMemoryForSize(size int) {
	releaseBenchmarkMemory()
	if size >= 2*1024*1024*1024 {
		time.Sleep(1 * time.Second)
	}
}

func buildScenarios(opts suiteOptions) []scenario {
	var out []scenario
	hasGroup := func(name string) bool { return opts.Groups[name] }

	if hasGroup(groupModeOverview) {
		out = append(out,
			scenario{ID: "direct-baseline", Category: groupModeOverview, Label: "Direct baseline", Mode: "direct", Measurement: measurementDirect},
			newMixnetScenario("header-only-base", groupModeOverview, "Header-only base", "header-only", 2, 1, false),
			newMixnetScenario("full-base", groupModeOverview, "Full onion base", "full", 2, 1, false),
			newMixnetScenario("header-only-ces", groupModeOverview, "Header-only + CES", "header-only", 2, 4, true),
			newMixnetScenario("full-ces", groupModeOverview, "Full onion + CES", "full", 2, 4, true),
		)
	}

	if hasGroup(groupHopSweep) {
		for _, hopCount := range opts.Hops {
			out = append(out,
				newMixnetScenario(fmt.Sprintf("header-only-hop-%d", hopCount), groupHopSweep, fmt.Sprintf("Header-only hops=%d", hopCount), "header-only", hopCount, 1, false),
				newMixnetScenario(fmt.Sprintf("full-hop-%d", hopCount), groupHopSweep, fmt.Sprintf("Full onion hops=%d", hopCount), "full", hopCount, 1, false),
			)
		}
	}

	if hasGroup(groupCircuitSweep) {
		for _, circuitCount := range opts.Circuits {
			out = append(out,
				newMixnetScenario(fmt.Sprintf("header-only-circuit-%d", circuitCount), groupCircuitSweep, fmt.Sprintf("Header-only circuits=%d", circuitCount), "header-only", 2, circuitCount, false),
				newMixnetScenario(fmt.Sprintf("full-circuit-%d", circuitCount), groupCircuitSweep, fmt.Sprintf("Full onion circuits=%d", circuitCount), "full", 2, circuitCount, false),
			)
		}
	}

	if hasGroup(groupEfficiencyGrid) {
		for _, hopCount := range opts.Hops {
			for _, circuitCount := range opts.Circuits {
				if circuitCount < 2 {
					continue
				}
				out = append(out,
					newMixnetScenario(fmt.Sprintf("header-only-eff-h%d-c%d", hopCount, circuitCount), groupEfficiencyGrid, fmt.Sprintf("Header-only CES hops=%d circuits=%d", hopCount, circuitCount), "header-only", hopCount, circuitCount, true),
					newMixnetScenario(fmt.Sprintf("full-eff-h%d-c%d", hopCount, circuitCount), groupEfficiencyGrid, fmt.Sprintf("Full CES hops=%d circuits=%d", hopCount, circuitCount), "full", hopCount, circuitCount, true),
				)
			}
		}
	}

	if hasGroup(groupCESPipeline) {
		out = append(out,
			scenario{ID: "ces-pipeline-gzip", Category: groupCESPipeline, Label: "CES pipeline gzip", Mode: "pipeline", Measurement: measurementCES, HopCount: 3, CircuitCount: 4, UseCESPipeline: true, Compression: "gzip", ErasureThreshold: 2},
			scenario{ID: "ces-pipeline-snappy", Category: groupCESPipeline, Label: "CES pipeline snappy", Mode: "pipeline", Measurement: measurementCES, HopCount: 3, CircuitCount: 4, UseCESPipeline: true, Compression: "snappy", ErasureThreshold: 2},
		)
	}

	if hasGroup(groupThresholdSweep) {
		baseCircuits := maxInt(4, opts.Circuits[len(opts.Circuits)-1])
		for _, pct := range []int{50, 60, 75, 80} {
			threshold := int(math.Ceil(float64(baseCircuits) * float64(pct) / 100.0))
			if threshold >= baseCircuits {
				threshold = baseCircuits - 1
			}
			out = append(out, scenario{
				ID:               fmt.Sprintf("threshold-%d", pct),
				Category:         groupThresholdSweep,
				Label:            fmt.Sprintf("CES threshold %d%%", pct),
				Mode:             "pipeline",
				Measurement:      measurementCES,
				HopCount:         3,
				CircuitCount:     baseCircuits,
				UseCESPipeline:   true,
				Compression:      "gzip",
				ErasureThreshold: threshold,
			})
		}
	}

	if hasGroup(groupFeatureOverhead) {
		for _, mode := range []string{"header-only", "full"} {
			out = append(out,
				scenario{ID: fmt.Sprintf("%s-header-padding", mode), Category: groupFeatureOverhead, Label: fmt.Sprintf("%s + header padding", modeLabel(mode)), Mode: mode, Measurement: measurementMixnet, HopCount: 2, CircuitCount: 4, UseCESPipeline: true, Compression: "gzip", SelectionMode: mixnet.SelectionModeRTT, HeaderPaddingEnabled: true, HeaderPaddingMin: 16, HeaderPaddingMax: 256},
				scenario{ID: fmt.Sprintf("%s-payload-random", mode), Category: groupFeatureOverhead, Label: fmt.Sprintf("%s + payload random padding", modeLabel(mode)), Mode: mode, Measurement: measurementMixnet, HopCount: 2, CircuitCount: 4, UseCESPipeline: true, Compression: "gzip", SelectionMode: mixnet.SelectionModeRTT, PayloadPaddingStrategy: mixnet.PaddingStrategyRandom, PayloadPaddingMin: 32, PayloadPaddingMax: 256},
				scenario{ID: fmt.Sprintf("%s-payload-buckets", mode), Category: groupFeatureOverhead, Label: fmt.Sprintf("%s + payload bucket padding", modeLabel(mode)), Mode: mode, Measurement: measurementMixnet, HopCount: 2, CircuitCount: 4, UseCESPipeline: true, Compression: "gzip", SelectionMode: mixnet.SelectionModeRTT, PayloadPaddingStrategy: mixnet.PaddingStrategyBuckets, PayloadPaddingBuckets: []int{1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 52428800}},
				scenario{ID: fmt.Sprintf("%s-auth-tag", mode), Category: groupFeatureOverhead, Label: fmt.Sprintf("%s + auth tag", modeLabel(mode)), Mode: mode, Measurement: measurementMixnet, HopCount: 2, CircuitCount: 4, UseCESPipeline: true, Compression: "gzip", SelectionMode: mixnet.SelectionModeRTT, EnableAuthTag: true, AuthTagSize: 16},
				scenario{ID: fmt.Sprintf("%s-jitter", mode), Category: groupFeatureOverhead, Label: fmt.Sprintf("%s + jitter", modeLabel(mode)), Mode: mode, Measurement: measurementMixnet, HopCount: 2, CircuitCount: 4, UseCESPipeline: true, Compression: "gzip", SelectionMode: mixnet.SelectionModeRTT, MaxJitter: 25},
			)
		}
	}

	if hasGroup(groupSelectionModes) {
		for _, mode := range []string{"header-only", "full"} {
			out = append(out,
				scenario{ID: fmt.Sprintf("%s-selection-rtt", mode), Category: groupSelectionModes, Label: fmt.Sprintf("%s selection RTT", modeLabel(mode)), Mode: mode, Measurement: measurementMixnet, HopCount: 2, CircuitCount: 4, UseCESPipeline: true, Compression: "gzip", SelectionMode: mixnet.SelectionModeRTT, RandomnessFactor: 0.3},
				scenario{ID: fmt.Sprintf("%s-selection-random", mode), Category: groupSelectionModes, Label: fmt.Sprintf("%s selection random", modeLabel(mode)), Mode: mode, Measurement: measurementMixnet, HopCount: 2, CircuitCount: 4, UseCESPipeline: true, Compression: "gzip", SelectionMode: mixnet.SelectionModeRandom, RandomnessFactor: 1.0},
				scenario{ID: fmt.Sprintf("%s-selection-hybrid", mode), Category: groupSelectionModes, Label: fmt.Sprintf("%s selection hybrid", modeLabel(mode)), Mode: mode, Measurement: measurementMixnet, HopCount: 2, CircuitCount: 4, UseCESPipeline: true, Compression: "gzip", SelectionMode: mixnet.SelectionModeHybrid, RandomnessFactor: 0.5},
			)
		}
	}

	if hasGroup(groupCompression) {
		for _, mode := range []string{"header-only", "full"} {
			out = append(out,
				scenario{ID: fmt.Sprintf("%s-compression-gzip", mode), Category: groupCompression, Label: fmt.Sprintf("%s compression gzip", modeLabel(mode)), Mode: mode, Measurement: measurementMixnet, HopCount: 2, CircuitCount: 4, UseCESPipeline: true, Compression: "gzip", SelectionMode: mixnet.SelectionModeRTT},
				scenario{ID: fmt.Sprintf("%s-compression-snappy", mode), Category: groupCompression, Label: fmt.Sprintf("%s compression snappy", modeLabel(mode)), Mode: mode, Measurement: measurementMixnet, HopCount: 2, CircuitCount: 4, UseCESPipeline: true, Compression: "snappy", SelectionMode: mixnet.SelectionModeRTT},
			)
		}
	}

	if hasGroup(groupFocusedOnion) {
		out = append(out,
			newDirectScenario("focused-direct-baseline", groupFocusedOnion, "Direct stream", true),
		)
		if opts.Profile == "quick" {
			out = append(out,
				newRoutedStreamMixnetScenario("focused-header-only-c1-routed", groupFocusedOnion, "Header-only routed stream 2 hops 1 circuit", "header-only", 2, 1, false),
				newStreamMixnetScenario("focused-full-c1-legacy", groupFocusedOnion, "Full onion legacy stream 2 hops 1 circuit", "full", 2, 1, false),
			)
			for _, profile := range quickMediaProfiles {
				out = append(out, newQuickMediaScenarios(groupFocusedOnion, profile)...)
			}
		} else {
			out = append(out,
				scenario{ID: "focused-local-c1", Category: groupFocusedOnion, Label: "Local session 1 circuit", Mode: "local", Measurement: measurementLocal, HopCount: 2, CircuitCount: 1},
				scenario{ID: "focused-local-c3", Category: groupFocusedOnion, Label: "Local session 3 circuits", Mode: "local", Measurement: measurementLocal, HopCount: 2, CircuitCount: 3},
				scenario{ID: "focused-ces-local-c1", Category: groupFocusedOnion, Label: "CES local 1 circuit", Mode: "pipeline", Measurement: measurementCES, HopCount: 2, CircuitCount: 1, UseCESPipeline: true, Compression: "gzip"},
				scenario{ID: "focused-ces-local-c3", Category: groupFocusedOnion, Label: "CES local 3 circuits", Mode: "pipeline", Measurement: measurementCES, HopCount: 2, CircuitCount: 3, UseCESPipeline: true, Compression: "gzip"},
				newStreamMixnetScenario("focused-header-only-c1", groupFocusedOnion, "Header-only legacy stream 2 hops 1 circuit", "header-only", 2, 1, false),
				newStreamMixnetScenario("focused-full-c1", groupFocusedOnion, "Full onion legacy stream 2 hops 1 circuit", "full", 2, 1, false),
				newStreamMixnetScenario("focused-header-only-c3", groupFocusedOnion, "Header-only legacy stream 2 hops 3 circuits", "header-only", 2, 3, false),
				newStreamMixnetScenario("focused-full-c3", groupFocusedOnion, "Full onion legacy stream 2 hops 3 circuits", "full", 2, 3, false),
				newMixnetScenario("focused-header-only-c1-ces", groupFocusedOnion, "Header-only 2 hops 1 circuit + CES", "header-only", 2, 1, true),
				newMixnetScenario("focused-full-c1-ces", groupFocusedOnion, "Full onion 2 hops 1 circuit + CES", "full", 2, 1, true),
				newMixnetScenario("focused-header-only-c3-ces", groupFocusedOnion, "Header-only 2 hops 3 circuits + CES", "header-only", 2, 3, true),
				newMixnetScenario("focused-full-c3-ces", groupFocusedOnion, "Full onion 2 hops 3 circuits + CES", "full", 2, 3, true),
				newCSEScenario("focused-header-only-c3-cse", groupFocusedOnion, "Header-only 2 hops 3 circuits CSE", "header-only", 2, 3),
				newCSEScenario("focused-full-c3-cse", groupFocusedOnion, "Full onion 2 hops 3 circuits CSE", "full", 2, 3),
			)
		}
	}

	return out
}

func mediaPayloadSizeBytes(profile streamWorkloadPreset) int {
	bytesPerSecond := float64(profile.BitrateKbps*1000) / 8.0
	return maxInt(1, int(math.Round(bytesPerSecond*float64(profile.DurationSec))))
}

func mediaWriteSizeBytes(profile streamWorkloadPreset) int {
	bytesPerSecond := float64(profile.BitrateKbps*1000) / 8.0
	return maxInt(1, int(math.Round(bytesPerSecond*float64(profile.SegmentMS)/1000.0)))
}

func quickMediaScenarioID(profile streamWorkloadPreset, variant string) string {
	return fmt.Sprintf("focused-%s-%s", profile.ID, variant)
}

func newQuickMediaScenarios(category string, profile streamWorkloadPreset) []scenario {
	sizeBytes := mediaPayloadSizeBytes(profile)
	writeSize := mediaWriteSizeBytes(profile)
	baseLabel := fmt.Sprintf("%s stream %s", profile.Label, formatBytes(sizeBytes))
	base := scenario{
		Category:             category,
		StreamProfile:        profile.ID,
		StreamKind:           profile.Kind,
		StreamQuality:        profile.Quality,
		StreamWrites:         true,
		StreamBitrateKbps:    profile.BitrateKbps,
		StreamSegmentMS:      profile.SegmentMS,
		StreamDurationSec:    profile.DurationSec,
		StreamWriteSizeBytes: writeSize,
		Sizes:                []int{sizeBytes},
	}
	return []scenario{
		{
			ID:                   quickMediaScenarioID(profile, "direct"),
			Label:                fmt.Sprintf("Direct %s", baseLabel),
			Mode:                 "direct",
			Measurement:          measurementDirect,
			Category:             base.Category,
			StreamProfile:        base.StreamProfile,
			StreamKind:           base.StreamKind,
			StreamQuality:        base.StreamQuality,
			StreamWrites:         base.StreamWrites,
			StreamBitrateKbps:    base.StreamBitrateKbps,
			StreamSegmentMS:      base.StreamSegmentMS,
			StreamDurationSec:    base.StreamDurationSec,
			StreamWriteSizeBytes: base.StreamWriteSizeBytes,
			Sizes:                append([]int(nil), base.Sizes...),
		},
		{
			ID:                   quickMediaScenarioID(profile, "header-routed"),
			Label:                fmt.Sprintf("Header-only routed %s", baseLabel),
			Mode:                 "header-only",
			Measurement:          measurementMixnet,
			Category:             base.Category,
			StreamProfile:        base.StreamProfile,
			StreamKind:           base.StreamKind,
			StreamQuality:        base.StreamQuality,
			StreamWrites:         base.StreamWrites,
			StreamBitrateKbps:    base.StreamBitrateKbps,
			StreamSegmentMS:      base.StreamSegmentMS,
			StreamDurationSec:    base.StreamDurationSec,
			StreamWriteSizeBytes: base.StreamWriteSizeBytes,
			EnableSessionRouting: true,
			HopCount:             2,
			CircuitCount:         1,
			Sizes:                append([]int(nil), base.Sizes...),
		},
		{
			ID:                   quickMediaScenarioID(profile, "full-legacy"),
			Label:                fmt.Sprintf("Full onion legacy %s", baseLabel),
			Mode:                 "full",
			Measurement:          measurementMixnet,
			Category:             base.Category,
			StreamProfile:        base.StreamProfile,
			StreamKind:           base.StreamKind,
			StreamQuality:        base.StreamQuality,
			StreamWrites:         base.StreamWrites,
			StreamBitrateKbps:    base.StreamBitrateKbps,
			StreamSegmentMS:      base.StreamSegmentMS,
			StreamDurationSec:    base.StreamDurationSec,
			StreamWriteSizeBytes: base.StreamWriteSizeBytes,
			HopCount:             2,
			CircuitCount:         1,
			Sizes:                append([]int(nil), base.Sizes...),
		},
	}
}

func newMixnetScenario(id, category, label, mode string, hops, circuits int, useCES bool) scenario {
	return scenario{
		ID:               id,
		Category:         category,
		Label:            label,
		Mode:             mode,
		Measurement:      measurementMixnet,
		HopCount:         hops,
		CircuitCount:     circuits,
		UseCESPipeline:   useCES,
		Compression:      "gzip",
		SelectionMode:    mixnet.SelectionModeRTT,
		RandomnessFactor: 0.3,
	}
}

func newRoutedMixnetScenario(id, category, label, mode string, hops, circuits int, useCES bool) scenario {
	sc := newMixnetScenario(id, category, label, mode, hops, circuits, useCES)
	sc.EnableSessionRouting = true
	return sc
}

func newDirectScenario(id, category, label string, streamWrites bool) scenario {
	return scenario{
		ID:           id,
		Category:     category,
		Label:        label,
		Mode:         "direct",
		Measurement:  measurementDirect,
		StreamWrites: streamWrites,
	}
}

func newStreamMixnetScenario(id, category, label, mode string, hops, circuits int, useCES bool) scenario {
	sc := newMixnetScenario(id, category, label, mode, hops, circuits, useCES)
	sc.StreamWrites = true
	return sc
}

func newRoutedStreamMixnetScenario(id, category, label, mode string, hops, circuits int, useCES bool) scenario {
	sc := newStreamMixnetScenario(id, category, label, mode, hops, circuits, useCES)
	sc.EnableSessionRouting = true
	return sc
}

func newCSEScenario(id, category, label, mode string, hops, circuits int) scenario {
	sc := newMixnetScenario(id, category, label, mode, hops, circuits, false)
	sc.UseCSE = true
	return sc
}

func newCompressedScenario(id, category, label, mode string, hops, circuits int) scenario {
	sc := newMixnetScenario(id, category, label, mode, hops, circuits, false)
	if mode == "direct" {
		sc.Measurement = measurementDirect
	}
	sc.UseCompressionOnly = true
	return sc
}

func executeScenario(opts suiteOptions, sc scenario, size int, runIdx int) (*runRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	payload := makePayload(size)
	rec := &runRecord{
		ScenarioID:              sc.ID,
		Category:                sc.Category,
		Label:                   sc.Label,
		Measurement:             sc.Measurement,
		Mode:                    sc.Mode,
		StreamProfile:           sc.StreamProfile,
		StreamKind:              sc.StreamKind,
		StreamQuality:           sc.StreamQuality,
		StreamWrites:            sc.StreamWrites,
		StreamBitrateKbps:       sc.StreamBitrateKbps,
		StreamSegmentMS:         sc.StreamSegmentMS,
		StreamDurationSec:       sc.StreamDurationSec,
		StreamWriteSizeBytes:    sc.StreamWriteSizeBytes,
		EnableSessionRouting:    sc.EnableSessionRouting,
		SizeBytes:               size,
		SizeLabel:               formatBytes(size),
		RunIndex:                runIdx,
		TimestampUTC:            time.Now().UTC(),
		HopCount:                sc.HopCount,
		CircuitCount:            sc.CircuitCount,
		UseCESPipeline:          sc.UseCESPipeline,
		UseCSE:                  sc.UseCSE,
		UseCompressionOnly:      sc.UseCompressionOnly,
		Compression:             sc.Compression,
		ErasureThreshold:        effectiveThreshold(sc),
		ErasureThresholdPercent: thresholdPercent(sc),
		SelectionMode:           string(defaultSelectionMode(sc.SelectionMode)),
		PayloadPaddingStrategy:  string(sc.PayloadPaddingStrategy),
		HeaderPaddingEnabled:    sc.HeaderPaddingEnabled,
		EnableAuthTag:           sc.EnableAuthTag,
		MaxJitterMS:             sc.MaxJitter,
	}

	var err error
	switch sc.Measurement {
	case measurementDirect:
		err = runDirectTransfer(ctx, sc, payload, rec)
	case measurementLocal:
		err = runLocalSessionPipeline(ctx, sc, payload, rec)
	case measurementCES:
		err = runCESPipeline(ctx, sc, payload, rec)
	default:
		err = runMixnetTransfer(ctx, sc, payload, rec)
	}
	if err != nil {
		rec.Error = err.Error()
		return nil, fmt.Errorf("%s size=%s run=%d: %w", sc.ID, formatBytes(size), runIdx, err)
	}
	return rec, nil
}

func runDirectTransfer(ctx context.Context, sc scenario, payload []byte, rec *runRecord) error {
	wirePayload, decodeReceived, err := prepareCompressionPayload(sc, payload, rec)
	if err != nil {
		return err
	}
	origin, err := newBenchHost()
	if err != nil {
		return err
	}
	defer origin.Close()
	dest, err := newBenchHost()
	if err != nil {
		_ = origin.Close()
		return err
	}
	defer dest.Close()

	destInfo := peer.AddrInfo{ID: dest.ID(), Addrs: dest.Addrs()}
	// Benchmark mixnet runs on a fully connected underlay before circuit setup is
	// timed. Warm the direct path the same way so "direct baseline" is not paying
	// an extra first-dial cost that the mixnet scenarios never include.
	if err := origin.Connect(ctx, destInfo); err != nil {
		return fmt.Errorf("preconnect direct hosts: %w", err)
	}

	received := make(chan []byte, 1)
	readDoneCh := make(chan struct{}, 1)
	errCh := make(chan error, 2)
	dest.SetStreamHandler(directProtocol, func(s network.Stream) {
		defer s.Close()
		if sc.UseCompressionOnly {
			data, err := readDirectSessionPayload(s, len(wirePayload))
			if err != nil {
				reportAsyncError(errCh, fmt.Errorf("read direct payload: %w", err))
				return
			}
			received <- data
			return
		}
		if err := verifyDirectSessionPayload(s, wirePayload); err != nil {
			reportAsyncError(errCh, fmt.Errorf("verify direct payload: %w", err))
			return
		}
		readDoneCh <- struct{}{}
	})

	connectStart := time.Now()
	if err := origin.Connect(ctx, destInfo); err != nil {
		return fmt.Errorf("connect direct hosts: %w", err)
	}
	rec.ConnectMS = millisSince(connectStart)

	rec.KeyExchangeMS = 0

	stream, err := origin.NewStream(ctx, dest.ID(), directProtocol)
	if err != nil {
		return fmt.Errorf("open direct stream: %w", err)
	}
	if flusher, ok := stream.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			_ = stream.Reset()
			return fmt.Errorf("flush direct stream negotiation: %w", err)
		}
	}

	transferStart := time.Now()
	chunkSize := transferChunkSize(sc, len(wirePayload))
	for offset := 0; offset < len(wirePayload); offset += chunkSize {
		end := offset + chunkSize
		if end > len(wirePayload) {
			end = len(wirePayload)
		}
		ciphertext, keyData, err := mixnet.EncryptSessionPayload(wirePayload[offset:end])
		if err != nil {
			_ = stream.Close()
			return fmt.Errorf("encrypt direct payload chunk: %w", err)
		}
		if err := writeDirectFrame(stream, keyData); err != nil {
			_ = stream.Close()
			return fmt.Errorf("write direct session key: %w", err)
		}
		if err := writeDirectFrame(stream, ciphertext); err != nil {
			_ = stream.Close()
			return fmt.Errorf("write direct payload chunk: %w", err)
		}
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close direct stream: %w", err)
	}
	select {
	case err := <-errCh:
		return fmt.Errorf("receive direct payload: %w", err)
	case <-readDoneCh:
	case data := <-received:
		if sc.UseCompressionOnly {
			decoded, err := decodeReceived(data)
			if err != nil {
				return fmt.Errorf("decode direct payload: %w", err)
			}
			if !bytes.Equal(decoded, payload) {
				return fmt.Errorf("direct payload mismatch: got=%d want=%d", len(decoded), len(payload))
			}
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	rec.TransferMS = millisSince(transferStart)
	rec.TotalMS = rec.ConnectMS + rec.KeyExchangeMS + rec.TransferMS + rec.PipelineProcessMS + rec.PipelineReconstructMS
	rec.ThroughputMBps = mibPerSecond(len(payload), rec.TotalMS)
	return nil
}

func runMixnetTransfer(ctx context.Context, sc scenario, payload []byte, rec *runRecord) error {
	wirePayload, decodeReceived, err := prepareCompressionPayload(sc, payload, rec)
	if err != nil {
		return err
	}
	cfg, err := sc.config()
	if err != nil {
		return err
	}

	relayCount := cfg.HopCount * cfg.CircuitCount * 3
	origin, dest, cleanup, err := setupMixnetNetwork(ctx, cfg, relayCount)
	if err != nil {
		return err
	}
	defer cleanup()

	connectStart := time.Now()
	circuits, err := origin.EstablishConnection(ctx, dest.Host().ID())
	if err != nil {
		return fmt.Errorf("establish connection: %w", err)
	}
	rec.ConnectMS = millisSince(connectStart)

	keyStart := time.Now()
	if err := origin.EnsureCircuitKeysForBenchmark(ctx, circuits); err != nil {
		return fmt.Errorf("ensure circuit keys: %w", err)
	}
	rec.KeyExchangeMS = millisSince(keyStart)

	readCh := make(chan []byte, 1)
	readDoneCh := make(chan struct{}, 1)
	errCh := make(chan error, 1)
	go func() {
		stream, err := dest.AcceptStream(ctx)
		if err != nil {
			errCh <- err
			return
		}
		defer stream.Close()

		if sc.UseCompressionOnly {
			out, readErr := readMixnetPayload(stream, len(wirePayload))
			if readErr != nil {
				errCh <- readErr
				return
			}
			readCh <- out
			return
		}

		if readErr := verifyMixnetPayload(stream, payload); readErr != nil {
			errCh <- readErr
			return
		}
		readDoneCh <- struct{}{}
	}()

	originStream, err := origin.OpenStream(ctx, dest.Host().ID())
	if err != nil {
		return fmt.Errorf("open mixnet stream: %w", err)
	}
	defer originStream.Close()

	transferStart := time.Now()
	chunkSize := transferChunkSize(sc, len(wirePayload))
	for offset := 0; offset < len(wirePayload); offset += chunkSize {
		end := offset + chunkSize
		if end > len(wirePayload) {
			end = len(wirePayload)
		}
		if _, err := originStream.Write(wirePayload[offset:end]); err != nil {
			return fmt.Errorf("write mixnet payload chunk: %w", err)
		}
	}
	select {
	case err := <-errCh:
		return fmt.Errorf("receive mixnet payload: %w", err)
	case <-readDoneCh:
		// The common mixnet path already verified bytes incrementally without
		// buffering a second 512 MiB copy on the destination side.
	case data := <-readCh:
		decoded, err := decodeReceived(data)
		if err != nil {
			return fmt.Errorf("decode mixnet payload: %w", err)
		}
		if !bytes.Equal(decoded, payload) {
			return fmt.Errorf("mixnet payload mismatch: got=%d want=%d", len(decoded), len(payload))
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	rec.TransferMS = millisSince(transferStart)
	rec.TotalMS = rec.ConnectMS + rec.KeyExchangeMS + rec.TransferMS + rec.PipelineProcessMS + rec.PipelineReconstructMS
	if sc.HopCount > 0 {
		rec.PerHopMS = rec.TotalMS / float64(sc.HopCount)
	}
	rec.ThroughputMBps = mibPerSecond(len(payload), rec.TotalMS)
	return nil
}

func readMixnetPayload(stream *mixnet.MixStream, expectedLen int) ([]byte, error) {
	buf := make([]byte, benchmarkReadBufferSize(expectedLen))
	out := make([]byte, 0, expectedLen)
	for len(out) < expectedLen {
		n, err := stream.Read(buf)
		if err != nil {
			return nil, err
		}
		out = append(out, buf[:n]...)
	}
	if len(out) > expectedLen {
		out = out[:expectedLen]
	}
	return out, nil
}

func verifyMixnetPayload(stream *mixnet.MixStream, expected []byte) error {
	buf := make([]byte, benchmarkReadBufferSize(len(expected)))
	received := 0
	for received < len(expected) {
		n, err := stream.Read(buf)
		if err != nil {
			return err
		}
		end := received + n
		if end > len(expected) {
			return fmt.Errorf("mixnet payload overflow: got=%d want=%d", end, len(expected))
		}
		if !bytes.Equal(buf[:n], expected[received:end]) {
			return fmt.Errorf("mixnet payload mismatch at offset=%d", received)
		}
		received = end
	}
	return nil
}

type benchmarkSessionKeyStore struct {
	mu      sync.Mutex
	keyData []byte
}

func (s *benchmarkSessionKeyStore) Set(keyData []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyData = append(s.keyData[:0], keyData...)
}

func (s *benchmarkSessionKeyStore) Take() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	data := append([]byte(nil), s.keyData...)
	s.keyData = nil
	return data
}

func installDirectSessionKeyHandler(h host.Host, store *benchmarkSessionKeyStore, errCh chan<- error) {
	h.SetStreamHandler(directKeyProtocol, func(s network.Stream) {
		defer s.Close()
		data, err := io.ReadAll(s)
		if err != nil {
			reportAsyncError(errCh, err)
			return
		}
		if _, err := mixnet.DecodeSessionKeyData(data); err != nil {
			reportAsyncError(errCh, fmt.Errorf("decode exchanged session key: %w", err))
			return
		}
		if store != nil {
			store.Set(data)
		}
		if _, err := s.Write([]byte{1}); err != nil {
			reportAsyncError(errCh, fmt.Errorf("ack session key exchange: %w", err))
		}
	})
}

func exchangeDirectSessionKey(ctx context.Context, h host.Host, dest peer.ID, keyData []byte) error {
	s, err := h.NewStream(ctx, dest, directKeyProtocol)
	if err != nil {
		return err
	}
	defer s.Close()
	if _, err := s.Write(keyData); err != nil {
		return err
	}
	if err := s.CloseWrite(); err != nil {
		return err
	}
	ack := make([]byte, 1)
	if _, err := io.ReadFull(s, ack); err != nil {
		return err
	}
	if ack[0] != 1 {
		return fmt.Errorf("invalid session key exchange ack")
	}
	return nil
}

func benchmarkSessionKeyData() ([]byte, error) {
	_, keyData, err := mixnet.EncryptSessionPayload([]byte("benchmark-destination-session"))
	return keyData, err
}

type benchmarkSessionMaterial struct {
	nonce []byte
	key   []byte
}

func benchmarkDirectSessionMaterial() ([]byte, benchmarkSessionMaterial, error) {
	keyData, err := benchmarkSessionKeyData()
	if err != nil {
		return nil, benchmarkSessionMaterial{}, err
	}
	session, err := decodeBenchmarkSessionKeyData(keyData)
	if err != nil {
		return nil, benchmarkSessionMaterial{}, err
	}
	return keyData, session, nil
}

func decodeBenchmarkSessionKeyData(data []byte) (benchmarkSessionMaterial, error) {
	const (
		nonceSize = 24
		keySize   = 32
	)
	if len(data) != nonceSize+keySize {
		return benchmarkSessionMaterial{}, fmt.Errorf("invalid key data length")
	}
	return benchmarkSessionMaterial{
		nonce: append([]byte(nil), data[:nonceSize]...),
		key:   append([]byte(nil), data[nonceSize:]...),
	}, nil
}

func deriveChunkNonce(base []byte, chunkIndex uint64) []byte {
	nonce := append([]byte(nil), base...)
	if len(nonce) >= 8 {
		start := len(nonce) - 8
		cur := binary.LittleEndian.Uint64(nonce[start:])
		binary.LittleEndian.PutUint64(nonce[start:], cur+chunkIndex)
	}
	return nonce
}

func encryptDirectChunk(session benchmarkSessionMaterial, chunkIndex uint64, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(session.key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, deriveChunkNonce(session.nonce, chunkIndex), plaintext, nil), nil
}

func decryptDirectChunk(session benchmarkSessionMaterial, chunkIndex uint64, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(session.key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, deriveChunkNonce(session.nonce, chunkIndex), ciphertext, nil)
}

func writeDirectFrame(w io.Writer, payload []byte) error {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readDirectFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	payloadLen := int(binary.LittleEndian.Uint32(lenBuf[:]))
	if payloadLen < 0 {
		return nil, fmt.Errorf("invalid direct frame length")
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func readDirectSessionPayload(r io.Reader, expectedLen int) ([]byte, error) {
	out := make([]byte, 0, expectedLen)
	for len(out) < expectedLen {
		keyData, err := readDirectFrame(r)
		if err != nil {
			return nil, err
		}
		if len(keyData) == 0 {
			return nil, fmt.Errorf("missing direct session key")
		}
		session, err := mixnet.DecodeSessionKeyData(keyData)
		if err != nil {
			return nil, err
		}
		ciphertext, err := readDirectFrame(r)
		if err != nil {
			return nil, err
		}
		plaintext, err := mixnet.DecryptSessionPayload(ciphertext, session)
		if err != nil {
			return nil, err
		}
		out = append(out, plaintext...)
	}
	if len(out) > expectedLen {
		out = out[:expectedLen]
	}
	return out, nil
}

func verifyDirectSessionPayload(r io.Reader, expected []byte) error {
	received := 0
	for received < len(expected) {
		keyData, err := readDirectFrame(r)
		if err != nil {
			return err
		}
		if len(keyData) == 0 {
			return fmt.Errorf("missing direct session key")
		}
		session, err := mixnet.DecodeSessionKeyData(keyData)
		if err != nil {
			return err
		}
		ciphertext, err := readDirectFrame(r)
		if err != nil {
			return err
		}
		plaintext, err := mixnet.DecryptSessionPayload(ciphertext, session)
		if err != nil {
			return err
		}
		end := received + len(plaintext)
		if end > len(expected) {
			return fmt.Errorf("direct payload overflow: got=%d want=%d", end, len(expected))
		}
		if !bytes.Equal(plaintext, expected[received:end]) {
			return fmt.Errorf("direct payload mismatch at offset=%d", received)
		}
		received = end
	}
	return nil
}

func readDirectPayload(r io.Reader, expectedLen int) ([]byte, error) {
	out := make([]byte, 0, expectedLen)
	for len(out) < expectedLen {
		payload, err := readDirectFrame(r)
		if err != nil {
			return nil, err
		}
		out = append(out, payload...)
	}
	if len(out) > expectedLen {
		out = out[:expectedLen]
	}
	return out, nil
}

func verifyDirectPayload(r io.Reader, expected []byte) error {
	received := 0
	for received < len(expected) {
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return err
		}
		payloadLen := int(binary.LittleEndian.Uint32(lenBuf[:]))
		if payloadLen < 0 {
			return fmt.Errorf("invalid direct frame length")
		}
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return err
		}
		end := received + len(payload)
		if end > len(expected) {
			return fmt.Errorf("direct payload overflow: got=%d want=%d", end, len(expected))
		}
		if !bytes.Equal(payload, expected[received:end]) {
			return fmt.Errorf("direct payload mismatch at offset=%d", received)
		}
		received = end
	}
	return nil
}

func readDirectEncryptedChunks(r io.Reader, session benchmarkSessionMaterial, expectedLen int) ([]byte, error) {
	out := make([]byte, 0, expectedLen)
	for chunkIndex := uint64(0); len(out) < expectedLen; chunkIndex++ {
		payload, err := readDirectFrame(r)
		if err != nil {
			return nil, err
		}
		plaintext, err := decryptDirectChunk(session, chunkIndex, payload)
		if err != nil {
			return nil, err
		}
		out = append(out, plaintext...)
	}
	if len(out) > expectedLen {
		out = out[:expectedLen]
	}
	return out, nil
}

func verifyDirectEncryptedChunks(r io.Reader, session benchmarkSessionMaterial, expected []byte) error {
	received := 0
	for chunkIndex := uint64(0); received < len(expected); chunkIndex++ {
		payload, err := readDirectFrame(r)
		if err != nil {
			return err
		}
		plaintext, err := decryptDirectChunk(session, chunkIndex, payload)
		if err != nil {
			return err
		}
		end := received + len(plaintext)
		if end > len(expected) {
			return fmt.Errorf("direct payload overflow: got=%d want=%d", end, len(expected))
		}
		if !bytes.Equal(plaintext, expected[received:end]) {
			return fmt.Errorf("direct payload mismatch at offset=%d", received)
		}
		received = end
	}
	return nil
}

func benchmarkIOChunkSize(totalBytes int) int {
	switch {
	case totalBytes >= 512*1024*1024:
		return benchmarkLargeChunkSize4MB
	case totalBytes >= 64*1024*1024:
		return benchmarkLargeChunkSize2MB
	case totalBytes >= 16*1024*1024:
		return benchmarkLargeChunkSize1MB
	default:
		return benchmarkChunkSize
	}
}

func transferChunkSize(sc scenario, totalBytes int) int {
	if sc.StreamWriteSizeBytes > 0 {
		return sc.StreamWriteSizeBytes
	}
	if sc.StreamWrites {
		return benchmarkChunkSize
	}
	return benchmarkIOChunkSize(totalBytes)
}

func benchmarkReadBufferSize(expectedLen int) int {
	return benchmarkIOChunkSize(expectedLen)
}

func reportAsyncError(errCh chan<- error, err error) {
	if err == nil || errCh == nil {
		return
	}
	select {
	case errCh <- err:
	default:
	}
}

func prepareCompressionPayload(sc scenario, payload []byte, rec *runRecord) ([]byte, func([]byte) ([]byte, error), error) {
	if !sc.UseCompressionOnly {
		return payload, func(data []byte) ([]byte, error) { return data, nil }, nil
	}
	compressor := ces.NewCompressor(fallbackCompression(sc.Compression))
	processStart := time.Now()
	compressed, err := compressor.Compress(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("compress benchmark payload: %w", err)
	}
	rec.PipelineProcessMS = millisSince(processStart)
	return compressed, func(data []byte) ([]byte, error) {
		reconstructStart := time.Now()
		out, err := compressor.Decompress(data)
		rec.PipelineReconstructMS = millisSince(reconstructStart)
		if err != nil {
			return nil, err
		}
		return out, nil
	}, nil
}

func runCESPipeline(ctx context.Context, sc scenario, payload []byte, rec *runRecord) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	pipe := ces.NewPipeline(&ces.Config{
		HopCount:         maxInt(1, sc.HopCount),
		CircuitCount:     maxInt(1, sc.CircuitCount),
		Compression:      fallbackCompression(sc.Compression),
		ErasureThreshold: effectiveThreshold(sc),
	})

	processStart := time.Now()
	compressed, err := pipe.Compressor().Compress(payload)
	if err != nil {
		return fmt.Errorf("compress: %w", err)
	}
	encrypted, keyData, err := mixnet.EncryptSessionPayload(compressed)
	if err != nil {
		return fmt.Errorf("encrypt session payload: %w", err)
	}
	shards, err := pipe.Sharder().Shard(encrypted)
	if err != nil {
		return fmt.Errorf("shard payload: %w", err)
	}
	rec.PipelineProcessMS = millisSince(processStart)

	key, err := mixnet.DecodeSessionKeyData(keyData)
	if err != nil {
		return fmt.Errorf("decode session key: %w", err)
	}

	subset := pickThresholdSubset(shards, pipe.Sharder().Threshold())
	reconstructStart := time.Now()
	reconstructedEncrypted, err := pipe.Sharder().Reconstruct(subset)
	if err != nil {
		return fmt.Errorf("reconstruct threshold subset: %w", err)
	}
	decrypted, err := mixnet.DecryptSessionPayload(reconstructedEncrypted, key)
	if err != nil {
		return fmt.Errorf("decrypt reconstructed payload: %w", err)
	}
	out, err := pipe.Compressor().Decompress(decrypted)
	if err != nil {
		return fmt.Errorf("decompress reconstructed payload: %w", err)
	}
	rec.PipelineReconstructMS = millisSince(reconstructStart)
	if len(out) != len(payload) {
		return fmt.Errorf("pipeline output length mismatch: got=%d want=%d", len(out), len(payload))
	}

	rec.TotalMS = rec.PipelineProcessMS + rec.PipelineReconstructMS
	if sc.HopCount > 0 {
		rec.PerHopMS = rec.TotalMS / float64(sc.HopCount)
	}
	rec.ThroughputMBps = mibPerSecond(len(payload), rec.TotalMS)
	return nil
}

func runLocalSessionPipeline(ctx context.Context, sc scenario, payload []byte, rec *runRecord) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	shardCount := maxInt(1, sc.CircuitCount)

	processStart := time.Now()
	encrypted, keyData, err := mixnet.EncryptSessionPayload(payload)
	if err != nil {
		return fmt.Errorf("encrypt session payload: %w", err)
	}
	shards, err := shardPayloadEvenly(encrypted, shardCount)
	if err != nil {
		return fmt.Errorf("shard payload: %w", err)
	}
	rec.PipelineProcessMS = millisSince(processStart)

	key, err := mixnet.DecodeSessionKeyData(keyData)
	if err != nil {
		return fmt.Errorf("decode session key: %w", err)
	}

	reconstructStart := time.Now()
	sort.Slice(shards, func(i, j int) bool { return shards[i].Index < shards[j].Index })
	combined := make([]byte, 0, len(encrypted))
	for _, shard := range shards {
		combined = append(combined, shard.Data...)
	}
	out, err := mixnet.DecryptSessionPayload(combined, key)
	if err != nil {
		return fmt.Errorf("decrypt session payload: %w", err)
	}
	rec.PipelineReconstructMS = millisSince(reconstructStart)
	if !bytes.Equal(out, payload) {
		return fmt.Errorf("local session output mismatch: got=%d want=%d", len(out), len(payload))
	}

	rec.TotalMS = rec.PipelineProcessMS + rec.PipelineReconstructMS
	if sc.HopCount > 0 {
		rec.PerHopMS = rec.TotalMS / float64(sc.HopCount)
	}
	rec.ThroughputMBps = mibPerSecond(len(payload), rec.TotalMS)
	return nil
}

func shardPayloadEvenly(data []byte, total int) ([]*ces.Shard, error) {
	if total <= 0 {
		return nil, fmt.Errorf("invalid shard count: %d", total)
	}
	parts := make([]*ces.Shard, total)
	base := len(data) / total
	remainder := len(data) % total
	offset := 0
	for i := 0; i < total; i++ {
		size := base
		if i < remainder {
			size++
		}
		end := offset + size
		if end > len(data) {
			end = len(data)
		}
		chunk := make([]byte, end-offset)
		copy(chunk, data[offset:end])
		parts[i] = &ces.Shard{Index: i, Data: chunk}
		offset = end
	}
	return parts, nil
}

func (s scenario) config() (*mixnet.MixnetConfig, error) {
	cfg := mixnet.DefaultConfig()
	cfg.HopCount = s.HopCount
	cfg.CircuitCount = s.CircuitCount
	cfg.EnableSessionRouting = s.EnableSessionRouting
	cfg.UseCESPipeline = s.UseCESPipeline
	cfg.UseCSE = s.UseCSE
	cfg.Compression = fallbackCompression(s.Compression)
	cfg.ErasureThreshold = effectiveThreshold(s)
	cfg.MaxJitter = s.MaxJitter
	cfg.EnableAuthTag = s.EnableAuthTag
	cfg.AuthTagSize = authTagSizeOrDefault(s)
	cfg.HeaderPaddingEnabled = s.HeaderPaddingEnabled
	cfg.HeaderPaddingMin = s.HeaderPaddingMin
	cfg.HeaderPaddingMax = s.HeaderPaddingMax
	cfg.PayloadPaddingStrategy = payloadStrategyOrNone(s.PayloadPaddingStrategy)
	cfg.PayloadPaddingMin = s.PayloadPaddingMin
	cfg.PayloadPaddingMax = s.PayloadPaddingMax
	cfg.PayloadPaddingBuckets = append([]int(nil), s.PayloadPaddingBuckets...)
	cfg.SelectionMode = defaultSelectionMode(s.SelectionMode)
	cfg.RandomnessFactor = randomnessFactorOrDefault(s.RandomnessFactor)
	if s.Mode == "header-only" {
		cfg.EncryptionMode = mixnet.EncryptionModeHeaderOnly
	} else {
		cfg.EncryptionMode = mixnet.EncryptionModeFull
	}
	cfg.SamplingSize = maxInt(cfg.HopCount*cfg.CircuitCount*3, cfg.HopCount*cfg.CircuitCount)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func setupMixnetNetwork(ctx context.Context, cfg *mixnet.MixnetConfig, relayCount int) (*mixnet.Mixnet, *mixnet.Mixnet, func(), error) {
	network, err := setupBenchmarkNetwork(ctx, cfg, relayCount)
	if err != nil {
		return nil, nil, nil, err
	}
	return network.origin, network.dest, network.cleanup, nil
}

func setupBenchmarkNetwork(ctx context.Context, cfg *mixnet.MixnetConfig, relayCount int) (*benchmarkNetwork, error) {
	originHost, err := newBenchHost()
	if err != nil {
		return nil, err
	}
	destHost, err := newBenchHost()
	if err != nil {
		_ = originHost.Close()
		return nil, err
	}
	relayHosts := make([]host.Host, relayCount)
	for i := range relayHosts {
		h, err := newBenchHost()
		if err != nil {
			for _, relayHost := range relayHosts[:i] {
				if relayHost != nil {
					_ = relayHost.Close()
				}
			}
			_ = originHost.Close()
			_ = destHost.Close()
			return nil, err
		}
		relayHosts[i] = h
	}

	providers := make([]peer.AddrInfo, 0, relayCount)
	peerMap := map[peer.ID]peer.AddrInfo{
		originHost.ID(): {ID: originHost.ID(), Addrs: originHost.Addrs()},
		destHost.ID():   {ID: destHost.ID(), Addrs: destHost.Addrs()},
	}
	for _, h := range relayHosts {
		info := peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()}
		providers = append(providers, info)
		peerMap[h.ID()] = info
	}

	origin, err := mixnet.NewMixnet(cloneConfig(cfg), originHost, &staticRouting{providers: providers, peers: peerMap})
	if err != nil {
		return nil, fmt.Errorf("new origin mixnet: %w", err)
	}
	dest, err := mixnet.NewMixnet(cloneConfig(cfg), destHost, nil)
	if err != nil {
		origin.ForceCloseForTest()
		return nil, fmt.Errorf("new destination mixnet: %w", err)
	}
	origin.RelayHandler().EnableLibp2pResourceManager(false)
	origin.RelayHandler().SetMaxBandwidth(0)
	origin.DisableBandwidthLimitsForBenchmark()
	dest.RelayHandler().EnableLibp2pResourceManager(false)
	dest.RelayHandler().SetMaxBandwidth(0)
	dest.DisableBandwidthLimitsForBenchmark()

	relayMixes := make([]*mixnet.Mixnet, 0, len(relayHosts))
	for _, h := range relayHosts {
		relayMix, relayErr := mixnet.NewMixnet(mixnet.DefaultConfig(), h, nil)
		if relayErr != nil {
			origin.ForceCloseForTest()
			dest.ForceCloseForTest()
			for _, existing := range relayMixes {
				existing.ForceCloseForTest()
			}
			return nil, fmt.Errorf("new relay mixnet: %w", relayErr)
		}
		relayMix.RelayHandler().EnableLibp2pResourceManager(false)
		relayMix.RelayHandler().SetMaxBandwidth(0)
		relayMix.DisableBandwidthLimitsForBenchmark()
		relayMixes = append(relayMixes, relayMix)
	}

	allHosts := []host.Host{originHost, destHost}
	allHosts = append(allHosts, relayHosts...)
	if err := connectAllHosts(ctx, allHosts); err != nil {
		origin.ForceCloseForTest()
		dest.ForceCloseForTest()
		for _, relayMix := range relayMixes {
			relayMix.ForceCloseForTest()
		}
		return nil, err
	}
	registerProtocols(allHosts, destHost.ID(), destHost.Addrs(), protocol.ID(mixnet.ProtocolID))
	for _, h := range relayHosts {
		registerProtocols(allHosts, h.ID(), h.Addrs(), protocol.ID(mixnet.ProtocolID), protocol.ID(relay.ProtocolID), protocol.ID(mixnet.KeyExchangeProtocolID))
	}

	cleanup := func() {
		origin.ForceCloseForTest()
		dest.ForceCloseForTest()
		for _, relayMix := range relayMixes {
			relayMix.ForceCloseForTest()
		}
	}
	return &benchmarkNetwork{
		origin:    origin,
		dest:      dest,
		relays:    relayMixes,
		cleanup:   cleanup,
		relayHost: relayHosts,
	}, nil
}

func newBenchHost() (host.Host, error) {
	return libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
	)
}

func connectAllHosts(ctx context.Context, hosts []host.Host) error {
	for i := range hosts {
		for j := range hosts {
			if i == j {
				continue
			}
			info := peer.AddrInfo{ID: hosts[j].ID(), Addrs: hosts[j].Addrs()}
			if err := hosts[i].Connect(ctx, info); err != nil {
				return fmt.Errorf("connect %s -> %s: %w", hosts[i].ID(), hosts[j].ID(), err)
			}
		}
	}
	return nil
}

func registerProtocols(hosts []host.Host, target peer.ID, addrs []multiaddr.Multiaddr, protos ...protocol.ID) {
	for _, h := range hosts {
		if h.ID() == target {
			continue
		}
		h.Peerstore().AddAddrs(target, addrs, peerstore.PermanentAddrTTL)
		_ = h.Peerstore().AddProtocols(target, protos...)
	}
}

func cloneConfig(cfg *mixnet.MixnetConfig) *mixnet.MixnetConfig {
	cp := *cfg
	cp.PayloadPaddingBuckets = append([]int(nil), cfg.PayloadPaddingBuckets...)
	return &cp
}

func summarizeRuns(records []*runRecord) ([]summaryRecord, error) {
	grouped := make(map[string][]*runRecord)
	for _, rec := range records {
		if rec.Error != "" {
			return nil, errors.New(rec.Error)
		}
		key := fmt.Sprintf("%s|%d", rec.ScenarioID, rec.SizeBytes)
		grouped[key] = append(grouped[key], rec)
	}

	summaries := make([]summaryRecord, 0, len(grouped))
	for _, group := range grouped {
		sort.Slice(group, func(i, j int) bool { return group[i].RunIndex < group[j].RunIndex })
		values := make([]float64, len(group))
		for i, rec := range group {
			values[i] = rec.TotalMS
		}
		excluded := outlierIndices(values, outlierTrimCount(len(group)))
		kept := make([]*runRecord, 0, len(group))
		for i, rec := range group {
			rec.Excluded = excluded[i]
			if !rec.Excluded {
				kept = append(kept, rec)
			}
		}
		if len(kept) == 0 {
			return nil, fmt.Errorf("all runs excluded for %s size=%d", group[0].ScenarioID, group[0].SizeBytes)
		}

		base := group[0]
		summaries = append(summaries, summaryRecord{
			ScenarioID:              base.ScenarioID,
			Category:                base.Category,
			Label:                   base.Label,
			Measurement:             base.Measurement,
			Mode:                    base.Mode,
			StreamProfile:           base.StreamProfile,
			StreamKind:              base.StreamKind,
			StreamQuality:           base.StreamQuality,
			StreamWrites:            base.StreamWrites,
			StreamBitrateKbps:       base.StreamBitrateKbps,
			StreamSegmentMS:         base.StreamSegmentMS,
			StreamDurationSec:       base.StreamDurationSec,
			StreamWriteSizeBytes:    base.StreamWriteSizeBytes,
			EnableSessionRouting:    base.EnableSessionRouting,
			SizeBytes:               base.SizeBytes,
			SizeLabel:               base.SizeLabel,
			HopCount:                base.HopCount,
			CircuitCount:            base.CircuitCount,
			UseCESPipeline:          base.UseCESPipeline,
			UseCSE:                  base.UseCSE,
			UseCompressionOnly:      base.UseCompressionOnly,
			Compression:             base.Compression,
			ErasureThreshold:        base.ErasureThreshold,
			ErasureThresholdPercent: base.ErasureThresholdPercent,
			SelectionMode:           base.SelectionMode,
			PayloadPaddingStrategy:  base.PayloadPaddingStrategy,
			HeaderPaddingEnabled:    base.HeaderPaddingEnabled,
			EnableAuthTag:           base.EnableAuthTag,
			MaxJitterMS:             base.MaxJitterMS,
			TotalRuns:               len(group),
			KeptRuns:                len(kept),
			ExcludedRunIndex:        excludedRunIndex(group, excluded),
			ConnectMeanMS:           meanRun(kept, func(r *runRecord) float64 { return r.ConnectMS }),
			ConnectStdDevMS:         stddevRun(kept, func(r *runRecord) float64 { return r.ConnectMS }),
			KeyExchangeMeanMS:       meanRun(kept, func(r *runRecord) float64 { return r.KeyExchangeMS }),
			KeyExchangeStdDevMS:     stddevRun(kept, func(r *runRecord) float64 { return r.KeyExchangeMS }),
			TransferMeanMS:          meanRun(kept, func(r *runRecord) float64 { return r.TransferMS }),
			TransferStdDevMS:        stddevRun(kept, func(r *runRecord) float64 { return r.TransferMS }),
			ProcessMeanMS:           meanRun(kept, func(r *runRecord) float64 { return r.PipelineProcessMS }),
			ProcessStdDevMS:         stddevRun(kept, func(r *runRecord) float64 { return r.PipelineProcessMS }),
			ReconstructMeanMS:       meanRun(kept, func(r *runRecord) float64 { return r.PipelineReconstructMS }),
			ReconstructStdDevMS:     stddevRun(kept, func(r *runRecord) float64 { return r.PipelineReconstructMS }),
			TotalMeanMS:             meanRun(kept, func(r *runRecord) float64 { return r.TotalMS }),
			TotalStdDevMS:           stddevRun(kept, func(r *runRecord) float64 { return r.TotalMS }),
			PerHopMeanMS:            meanRun(kept, func(r *runRecord) float64 { return r.PerHopMS }),
			PerHopStdDevMS:          stddevRun(kept, func(r *runRecord) float64 { return r.PerHopMS }),
			ThroughputMeanMBps:      meanRun(kept, func(r *runRecord) float64 { return r.ThroughputMBps }),
			ThroughputStdDevMBps:    stddevRun(kept, func(r *runRecord) float64 { return r.ThroughputMBps }),
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].Category != summaries[j].Category {
			return summaries[i].Category < summaries[j].Category
		}
		if summaries[i].ScenarioID != summaries[j].ScenarioID {
			return summaries[i].ScenarioID < summaries[j].ScenarioID
		}
		return summaries[i].SizeBytes < summaries[j].SizeBytes
	})
	return summaries, nil
}

func excludedRunIndex(group []*runRecord, excluded map[int]bool) int {
	for idx := range group {
		if excluded[idx] {
			return group[idx].RunIndex
		}
	}
	return 0
}

func describeOutlierRule(runs int) string {
	trimCount := outlierTrimCount(runs)
	if trimCount <= 0 {
		return "no outlier excluded when only one run is recorded"
	}
	if trimCount == 1 {
		return "exclude the single run farthest from the median total latency"
	}
	return fmt.Sprintf("exclude the %d runs farthest from the median total latency", trimCount)
}

func describeOutlierRuleWithOverrides(defaultRuns int, overrides map[int]int) string {
	rule := describeOutlierRule(defaultRuns)
	if len(overrides) == 0 {
		return rule
	}
	type entry struct {
		size int
		runs int
	}
	list := make([]entry, 0, len(overrides))
	for size, runs := range overrides {
		list = append(list, entry{size: size, runs: runs})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].size < list[j].size })
	parts := make([]string, 0, len(list))
	for _, item := range list {
		parts = append(parts, fmt.Sprintf("%s uses %d runs (%s)", formatBytes(item.size), item.runs, describeOutlierRule(item.runs)))
	}
	return fmt.Sprintf("%s; overrides: %s", rule, strings.Join(parts, "; "))
}

func (o suiteOptions) runsForSize(size int) int {
	if o.SizeRunOverrides == nil {
		return o.Runs
	}
	if runs, ok := o.SizeRunOverrides[size]; ok && runs > 0 {
		return runs
	}
	return o.Runs
}

func (o suiteOptions) runsSummary() string {
	if len(o.SizeRunOverrides) == 0 {
		return strconv.Itoa(o.Runs)
	}
	type entry struct {
		size int
		runs int
	}
	list := make([]entry, 0, len(o.SizeRunOverrides))
	for size, runs := range o.SizeRunOverrides {
		list = append(list, entry{size: size, runs: runs})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].size < list[j].size })
	parts := make([]string, 0, len(list))
	for _, item := range list {
		parts = append(parts, fmt.Sprintf("%s=%d", formatBytes(item.size), item.runs))
	}
	return fmt.Sprintf("%d (overrides: %s)", o.Runs, strings.Join(parts, ", "))
}

func bestEfficiencySummaries(summaries []summaryRecord) []bestRecord {
	bestByModeAndSize := make(map[string]summaryRecord)
	for _, summary := range summaries {
		if summary.Category != groupEfficiencyGrid {
			continue
		}
		key := summary.Mode + "|" + strconv.Itoa(summary.SizeBytes)
		current, ok := bestByModeAndSize[key]
		if !ok || summary.TotalMeanMS < current.TotalMeanMS {
			bestByModeAndSize[key] = summary
		}
	}

	best := make([]bestRecord, 0, len(bestByModeAndSize))
	for _, summary := range bestByModeAndSize {
		best = append(best, bestRecord{
			Mode:            summary.Mode,
			SizeBytes:       summary.SizeBytes,
			SizeLabel:       summary.SizeLabel,
			ScenarioID:      summary.ScenarioID,
			Label:           summary.Label,
			HopCount:        summary.HopCount,
			CircuitCount:    summary.CircuitCount,
			TotalMeanMS:     summary.TotalMeanMS,
			ThroughputMBps:  summary.ThroughputMeanMBps,
			PerHopMeanMS:    summary.PerHopMeanMS,
			KeyExchangeMean: summary.KeyExchangeMeanMS,
			TransferMeanMS:  summary.TransferMeanMS,
		})
	}
	sort.Slice(best, func(i, j int) bool {
		if best[i].Mode != best[j].Mode {
			return best[i].Mode < best[j].Mode
		}
		return best[i].SizeBytes < best[j].SizeBytes
	})
	return best
}

func writeMetadata(opts suiteOptions, scenarios []scenario) error {
	meta := map[string]any{
		"profile":     opts.Profile,
		"generated":   time.Now().UTC().Format(time.RFC3339),
		"runs":        opts.Runs,
		"visualProof": opts.VisualProof,
		"sizes":       opts.Sizes,
		"hops":        opts.Hops,
		"circuits":    opts.Circuits,
		"groups":      sortedGroupNames(opts.Groups),
		"timeout":     opts.Timeout.String(),
		"scenarios":   scenarios,
		"outlierRule": describeOutlierRuleWithOverrides(opts.Runs, opts.SizeRunOverrides),
	}
	if len(opts.SizeRunOverrides) > 0 {
		meta["sizeRunOverrides"] = opts.SizeRunOverrides
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(opts.OutputDir, "metadata.json"), data, 0o644)
}

func writeRawRecords(outputDir string, records []*runRecord) error {
	jsonPath := filepath.Join(outputDir, "raw_runs.jsonl")
	jsonFile, err := os.Create(jsonPath)
	if err != nil {
		return err
	}
	defer jsonFile.Close()
	for _, rec := range records {
		line, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if _, err := jsonFile.Write(append(line, '\n')); err != nil {
			return err
		}
	}

	csvPath := filepath.Join(outputDir, "raw_runs.csv")
	csvFile, err := os.Create(csvPath)
	if err != nil {
		return err
	}
	defer csvFile.Close()
	writer := csv.NewWriter(csvFile)
	defer writer.Flush()
	header := []string{"scenario_id", "category", "label", "measurement", "mode", "stream_profile", "stream_kind", "stream_quality", "stream_writes", "stream_bitrate_kbps", "stream_segment_ms", "stream_duration_sec", "stream_write_size_bytes", "enable_session_routing", "size_bytes", "size_label", "run_index", "timestamp_utc", "hop_count", "circuit_count", "use_ces_pipeline", "use_cse", "use_compression_only", "compression", "erasure_threshold", "erasure_threshold_percent", "selection_mode", "payload_padding_strategy", "header_padding_enabled", "enable_auth_tag", "max_jitter_ms", "connect_ms", "key_exchange_ms", "transfer_ms", "pipeline_process_ms", "pipeline_reconstruct_ms", "total_ms", "per_hop_ms", "throughput_mib_per_s", "excluded"}
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, rec := range records {
		row := []string{
			rec.ScenarioID, rec.Category, rec.Label, rec.Measurement, rec.Mode, rec.StreamProfile, rec.StreamKind, rec.StreamQuality, strconv.FormatBool(rec.StreamWrites),
			strconv.Itoa(rec.StreamBitrateKbps), strconv.Itoa(rec.StreamSegmentMS), strconv.Itoa(rec.StreamDurationSec), strconv.Itoa(rec.StreamWriteSizeBytes), strconv.FormatBool(rec.EnableSessionRouting),
			strconv.Itoa(rec.SizeBytes), rec.SizeLabel, strconv.Itoa(rec.RunIndex), rec.TimestampUTC.Format(time.RFC3339),
			strconv.Itoa(rec.HopCount), strconv.Itoa(rec.CircuitCount), strconv.FormatBool(rec.UseCESPipeline), strconv.FormatBool(rec.UseCSE), strconv.FormatBool(rec.UseCompressionOnly),
			rec.Compression, strconv.Itoa(rec.ErasureThreshold), fmt.Sprintf("%.2f", rec.ErasureThresholdPercent),
			rec.SelectionMode, rec.PayloadPaddingStrategy, strconv.FormatBool(rec.HeaderPaddingEnabled),
			strconv.FormatBool(rec.EnableAuthTag), strconv.Itoa(rec.MaxJitterMS),
			fmt.Sprintf("%.6f", rec.ConnectMS), fmt.Sprintf("%.6f", rec.KeyExchangeMS), fmt.Sprintf("%.6f", rec.TransferMS),
			fmt.Sprintf("%.6f", rec.PipelineProcessMS), fmt.Sprintf("%.6f", rec.PipelineReconstructMS), fmt.Sprintf("%.6f", rec.TotalMS),
			fmt.Sprintf("%.6f", rec.PerHopMS), fmt.Sprintf("%.6f", rec.ThroughputMBps), strconv.FormatBool(rec.Excluded),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return writer.Error()
}

func writeSummaryRecords(outputDir string, summaries []summaryRecord) error {
	data, err := json.MarshalIndent(summaries, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "summary.json"), data, 0o644); err != nil {
		return err
	}

	file, err := os.Create(filepath.Join(outputDir, "summary.csv"))
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	header := []string{"scenario_id", "category", "label", "measurement", "mode", "stream_profile", "stream_kind", "stream_quality", "stream_writes", "stream_bitrate_kbps", "stream_segment_ms", "stream_duration_sec", "stream_write_size_bytes", "enable_session_routing", "size_bytes", "size_label", "hop_count", "circuit_count", "use_ces_pipeline", "use_cse", "use_compression_only", "compression", "erasure_threshold", "erasure_threshold_percent", "selection_mode", "payload_padding_strategy", "header_padding_enabled", "enable_auth_tag", "max_jitter_ms", "total_runs", "kept_runs", "excluded_run_index", "connect_mean_ms", "connect_stddev_ms", "key_exchange_mean_ms", "key_exchange_stddev_ms", "transfer_mean_ms", "transfer_stddev_ms", "pipeline_process_mean_ms", "pipeline_process_stddev_ms", "pipeline_reconstruct_mean_ms", "pipeline_reconstruct_stddev_ms", "total_mean_ms", "total_stddev_ms", "per_hop_mean_ms", "per_hop_stddev_ms", "throughput_mean_mib_per_s", "throughput_stddev_mib_per_s"}
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, s := range summaries {
		row := []string{
			s.ScenarioID, s.Category, s.Label, s.Measurement, s.Mode, s.StreamProfile, s.StreamKind, s.StreamQuality, strconv.FormatBool(s.StreamWrites),
			strconv.Itoa(s.StreamBitrateKbps), strconv.Itoa(s.StreamSegmentMS), strconv.Itoa(s.StreamDurationSec), strconv.Itoa(s.StreamWriteSizeBytes), strconv.FormatBool(s.EnableSessionRouting),
			strconv.Itoa(s.SizeBytes), s.SizeLabel, strconv.Itoa(s.HopCount), strconv.Itoa(s.CircuitCount),
			strconv.FormatBool(s.UseCESPipeline), strconv.FormatBool(s.UseCSE), strconv.FormatBool(s.UseCompressionOnly), s.Compression, strconv.Itoa(s.ErasureThreshold), fmt.Sprintf("%.2f", s.ErasureThresholdPercent),
			s.SelectionMode, s.PayloadPaddingStrategy, strconv.FormatBool(s.HeaderPaddingEnabled), strconv.FormatBool(s.EnableAuthTag), strconv.Itoa(s.MaxJitterMS),
			strconv.Itoa(s.TotalRuns), strconv.Itoa(s.KeptRuns), strconv.Itoa(s.ExcludedRunIndex),
			fmt.Sprintf("%.6f", s.ConnectMeanMS), fmt.Sprintf("%.6f", s.ConnectStdDevMS),
			fmt.Sprintf("%.6f", s.KeyExchangeMeanMS), fmt.Sprintf("%.6f", s.KeyExchangeStdDevMS),
			fmt.Sprintf("%.6f", s.TransferMeanMS), fmt.Sprintf("%.6f", s.TransferStdDevMS),
			fmt.Sprintf("%.6f", s.ProcessMeanMS), fmt.Sprintf("%.6f", s.ProcessStdDevMS),
			fmt.Sprintf("%.6f", s.ReconstructMeanMS), fmt.Sprintf("%.6f", s.ReconstructStdDevMS),
			fmt.Sprintf("%.6f", s.TotalMeanMS), fmt.Sprintf("%.6f", s.TotalStdDevMS),
			fmt.Sprintf("%.6f", s.PerHopMeanMS), fmt.Sprintf("%.6f", s.PerHopStdDevMS),
			fmt.Sprintf("%.6f", s.ThroughputMeanMBps), fmt.Sprintf("%.6f", s.ThroughputStdDevMBps),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return writer.Error()
}

func writeBestRecords(outputDir string, best []bestRecord) error {
	data, err := json.MarshalIndent(best, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "best_hops_circuits.json"), data, 0o644); err != nil {
		return err
	}

	file, err := os.Create(filepath.Join(outputDir, "best_hops_circuits.csv"))
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	if err := writer.Write([]string{"mode", "size_bytes", "size_label", "scenario_id", "label", "hop_count", "circuit_count", "total_mean_ms", "throughput_mean_mib_per_s", "per_hop_mean_ms", "key_exchange_mean_ms", "transfer_mean_ms"}); err != nil {
		return err
	}
	for _, b := range best {
		row := []string{
			b.Mode, strconv.Itoa(b.SizeBytes), b.SizeLabel, b.ScenarioID, b.Label,
			strconv.Itoa(b.HopCount), strconv.Itoa(b.CircuitCount),
			fmt.Sprintf("%.6f", b.TotalMeanMS), fmt.Sprintf("%.6f", b.ThroughputMBps),
			fmt.Sprintf("%.6f", b.PerHopMeanMS), fmt.Sprintf("%.6f", b.KeyExchangeMean), fmt.Sprintf("%.6f", b.TransferMeanMS),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return writer.Error()
}

func (s *staticRouting) FindProvidersAsync(ctx context.Context, _ cid.Cid, count int) <-chan peer.AddrInfo {
	ch := make(chan peer.AddrInfo, len(s.providers))
	go func() {
		defer close(ch)
		limit := len(s.providers)
		if count > 0 && count < limit {
			limit = count
		}
		for i := 0; i < limit; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- s.providers[i]:
			}
		}
	}()
	return ch
}

func (s *staticRouting) FindPeer(_ context.Context, id peer.ID) (peer.AddrInfo, error) {
	info, ok := s.peers[id]
	if !ok {
		return peer.AddrInfo{}, errors.New("peer not found")
	}
	return info, nil
}

func (s *staticRouting) Provide(context.Context, cid.Cid, bool) error {
	return nil
}

func (s *staticRouting) PutValue(context.Context, string, []byte, ...routingcore.Option) error {
	return nil
}

func (s *staticRouting) GetValue(context.Context, string, ...routingcore.Option) ([]byte, error) {
	return nil, errors.New("value not found")
}

func (s *staticRouting) SearchValue(context.Context, string, ...routingcore.Option) (<-chan []byte, error) {
	ch := make(chan []byte)
	close(ch)
	return ch, nil
}

func (s *staticRouting) Bootstrap(context.Context) error { return nil }

func parseGroups(spec string) (map[string]bool, error) {
	names := strings.Split(spec, ",")
	out := make(map[string]bool, len(names))
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		valid := false
		for _, allowed := range orderedGroups {
			if name == allowed {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("unknown group %q", name)
		}
		out[name] = true
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no benchmark groups selected")
	}
	return out, nil
}

func parseIntList(spec string) ([]int, error) {
	parts := strings.Split(spec, ",")
	values := make([]int, 0, len(parts))
	seen := make(map[int]struct{}, len(parts))
	for _, raw := range parts {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		v, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("parse integer %q: %w", raw, err)
		}
		if v <= 0 {
			return nil, fmt.Errorf("integer values must be > 0")
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		values = append(values, v)
	}
	sort.Ints(values)
	if len(values) == 0 {
		return nil, fmt.Errorf("empty integer list")
	}
	return values, nil
}

func parseSizeList(spec string) ([]int, error) {
	parts := strings.Split(spec, ",")
	values := make([]int, 0, len(parts))
	seen := make(map[int]struct{}, len(parts))
	for _, raw := range parts {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		v, err := parseSize(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		values = append(values, v)
	}
	sort.Ints(values)
	if len(values) == 0 {
		return nil, fmt.Errorf("empty size list")
	}
	return values, nil
}

func parseSize(raw string) (int, error) {
	upper := strings.ToUpper(strings.TrimSpace(raw))
	multiplier := 1
	switch {
	case strings.HasSuffix(upper, "KB"):
		multiplier = 1024
		upper = strings.TrimSuffix(upper, "KB")
	case strings.HasSuffix(upper, "MB"):
		multiplier = 1024 * 1024
		upper = strings.TrimSuffix(upper, "MB")
	case strings.HasSuffix(upper, "GB"):
		multiplier = 1024 * 1024 * 1024
		upper = strings.TrimSuffix(upper, "GB")
	case strings.HasSuffix(upper, "B"):
		upper = strings.TrimSuffix(upper, "B")
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(upper), 64)
	if err != nil {
		return 0, fmt.Errorf("parse size %q: %w", raw, err)
	}
	size := int(math.Round(value * float64(multiplier)))
	if size <= 0 {
		return 0, fmt.Errorf("size must be > 0")
	}
	return size, nil
}

func makePayload(size int) []byte {
	data := make([]byte, size)
	rng := mrand.New(mrand.NewSource(int64(size)*1103515245 + 12345))
	_, _ = rng.Read(data)
	return data
}

func pickThresholdSubset(shards []*ces.Shard, threshold int) []*ces.Shard {
	if threshold >= len(shards) {
		return append([]*ces.Shard(nil), shards...)
	}
	out := make([]*ces.Shard, 0, threshold)
	step := maxInt(1, len(shards)/threshold)
	for i := 0; i < len(shards) && len(out) < threshold; i += step {
		out = append(out, shards[i])
	}
	for i := len(shards) - 1; i >= 0 && len(out) < threshold; i-- {
		duplicate := false
		for _, shard := range out {
			if shard.Index == shards[i].Index {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, shards[i])
		}
	}
	return out
}

func effectiveThreshold(sc scenario) int {
	if sc.ErasureThreshold > 0 {
		return sc.ErasureThreshold
	}
	if !sc.UseCESPipeline {
		if sc.CircuitCount > 0 {
			return sc.CircuitCount
		}
		return 0
	}
	threshold := int(math.Ceil(float64(sc.CircuitCount) * 0.6))
	if threshold < 1 {
		threshold = 1
	}
	if threshold >= sc.CircuitCount {
		threshold = sc.CircuitCount - 1
	}
	return threshold
}

func thresholdPercent(sc scenario) float64 {
	if sc.CircuitCount == 0 {
		return 0
	}
	return (float64(effectiveThreshold(sc)) / float64(sc.CircuitCount)) * 100.0
}

func fallbackCompression(value string) string {
	if value == "" {
		return "gzip"
	}
	return value
}

func defaultSelectionMode(mode mixnet.SelectionMode) mixnet.SelectionMode {
	if mode == "" {
		return mixnet.SelectionModeRTT
	}
	return mode
}

func randomnessFactorOrDefault(v float64) float64 {
	if v == 0 {
		return 0.3
	}
	return v
}

func payloadStrategyOrNone(v mixnet.PaddingStrategy) mixnet.PaddingStrategy {
	if v == "" {
		return mixnet.PaddingStrategyNone
	}
	return v
}

func authTagSizeOrDefault(sc scenario) int {
	if !sc.EnableAuthTag {
		return 16
	}
	if sc.AuthTagSize == 0 {
		return 16
	}
	return sc.AuthTagSize
}

func millisSince(start time.Time) float64 {
	return float64(time.Since(start)) / float64(time.Millisecond)
}

func mibPerSecond(sizeBytes int, durationMS float64) float64 {
	if durationMS <= 0 {
		return 0
	}
	seconds := durationMS / 1000.0
	return (float64(sizeBytes) / (1024.0 * 1024.0)) / seconds
}

func outlierTrimCount(runs int) int {
	if runs <= 1 {
		return 0
	}
	if runs >= 12 {
		return 2
	}
	return 1
}

func outlierIndices(values []float64, count int) map[int]bool {
	excluded := make(map[int]bool)
	if len(values) == 0 || count <= 0 {
		return excluded
	}
	if count >= len(values) {
		count = len(values) - 1
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	median := sorted[len(sorted)/2]

	type candidate struct {
		idx      int
		distance float64
	}
	candidates := make([]candidate, 0, len(values))
	for idx, value := range values {
		candidates = append(candidates, candidate{idx: idx, distance: math.Abs(value - median)})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].distance == candidates[j].distance {
			return candidates[i].idx < candidates[j].idx
		}
		return candidates[i].distance > candidates[j].distance
	})
	for i := 0; i < count; i++ {
		excluded[candidates[i].idx] = true
	}
	return excluded
}

func meanRun(records []*runRecord, selector func(*runRecord) float64) float64 {
	if len(records) == 0 {
		return 0
	}
	total := 0.0
	for _, rec := range records {
		total += selector(rec)
	}
	return total / float64(len(records))
}

func stddevRun(records []*runRecord, selector func(*runRecord) float64) float64 {
	if len(records) <= 1 {
		return 0
	}
	mean := meanRun(records, selector)
	variance := 0.0
	for _, rec := range records {
		delta := selector(rec) - mean
		variance += delta * delta
	}
	variance /= float64(len(records) - 1)
	return math.Sqrt(variance)
}

func sortedGroupNames(groups map[string]bool) []string {
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func formatBytes(size int) string {
	if size >= 1024*1024*1024 {
		value := float64(size) / float64(1024*1024*1024)
		if math.Mod(value, 1) == 0 {
			return fmt.Sprintf("%.0fGB", value)
		}
		return fmt.Sprintf("%.2fGB", value)
	}
	if size >= 1024*1024 {
		value := float64(size) / float64(1024*1024)
		if math.Mod(value, 1) == 0 {
			return fmt.Sprintf("%.0fMB", value)
		}
		return fmt.Sprintf("%.2fMB", value)
	}
	if size >= 1024 {
		value := float64(size) / 1024.0
		if math.Mod(value, 1) == 0 {
			return fmt.Sprintf("%.0fKB", value)
		}
		return fmt.Sprintf("%.2fKB", value)
	}
	return fmt.Sprintf("%dB", size)
}

func modeLabel(mode string) string {
	switch mode {
	case "header-only":
		return "Header-only"
	case "full":
		return "Full onion"
	default:
		return strings.Title(mode)
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
