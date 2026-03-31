package mixnet

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/mixnet/ces"
)

func TestDestinationHandlerReconstructsAtThreshold(t *testing.T) {
	pipeline := ces.NewPipeline(&ces.Config{
		HopCount:         2,
		CircuitCount:     4,
		Compression:      "gzip",
		ErasureThreshold: 2,
	})

	original := bytes.Repeat([]byte("mixnet-threshold-check-"), 256)
	compressed, err := pipeline.Compressor().Compress(original)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}

	encrypted, keyData, err := encryptSessionPayload(compressed)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	shards, err := pipeline.Sharder().Shard(encrypted)
	if err != nil {
		t.Fatalf("shard: %v", err)
	}

	handler := &DestinationHandler{
		pipeline:    pipeline,
		shardBuf:    make(map[string]map[int]*ces.Shard),
		shardTags:   make(map[string]map[int][]byte),
		totalShards: make(map[string]int),
		timers:      make(map[string]*time.Timer),
		sessions:    make(map[string]*sessionMailbox),
		sessionDone: make(map[string]time.Time),
		keys:        make(map[string]sessionKey),
		keyData:     make(map[string][]byte),
		inboundCh:   make(chan string, 1),
		threshold:   2,
		timeout:     5 * time.Second,
		dataCh:      make(chan []byte, 1),
		stopCh:      make(chan struct{}),
	}

	const sessionID = "threshold-session"
	if err := handler.AddShard(sessionID, shards[1], keyData, nil, len(shards)); err != nil {
		t.Fatalf("add shard 1: %v", err)
	}
	if _, err := handler.TryReconstruct(sessionID); err == nil {
		t.Fatal("expected reconstruction to wait for the threshold")
	}

	if err := handler.AddShard(sessionID, shards[3], keyData, nil, len(shards)); err != nil {
		t.Fatalf("add shard 3: %v", err)
	}
	reconstructed, err := handler.TryReconstruct(sessionID)
	if err != nil {
		t.Fatalf("reconstruct at threshold: %v", err)
	}
	if !bytes.Equal(reconstructed, original) {
		t.Fatal("reconstructed payload mismatch")
	}
}

func TestSingleShardSharderRoundTrips(t *testing.T) {
	sharder := ces.NewSharder(1, 1)
	payload := bytes.Repeat([]byte("single-shard-ces-"), 64)

	shards, err := sharder.Shard(payload)
	if err != nil {
		t.Fatalf("shard: %v", err)
	}
	if len(shards) != 1 {
		t.Fatalf("expected 1 shard, got %d", len(shards))
	}

	out, err := sharder.Reconstruct(shards)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatal("single-shard round-trip mismatch")
	}
}

func TestDestinationHandlerReconstructsNonCESPerShardEncryption(t *testing.T) {
	original := bytes.Repeat([]byte("mixnet-nonces-hard-stop-"), 256)
	shards, keyData, err := encryptSessionShards(original, 3)
	if err != nil {
		t.Fatalf("encrypt shards: %v", err)
	}

	handler := &DestinationHandler{
		pipeline:    nil,
		shardBuf:    make(map[string]map[int]*ces.Shard),
		shardTags:   make(map[string]map[int][]byte),
		totalShards: make(map[string]int),
		timers:      make(map[string]*time.Timer),
		sessions:    make(map[string]*sessionMailbox),
		sessionDone: make(map[string]time.Time),
		keys:        make(map[string]sessionKey),
		keyData:     make(map[string][]byte),
		inboundCh:   make(chan string, 1),
		threshold:   3,
		timeout:     5 * time.Second,
		dataCh:      make(chan []byte, 1),
		stopCh:      make(chan struct{}),
	}

	const sessionID = "non-ces-shard-session"
	order := []int{2, 0, 1}
	for _, idx := range order {
		if err := handler.AddShard(sessionID, shards[idx], keyData, nil, len(shards)); err != nil {
			t.Fatalf("add shard %d: %v", idx, err)
		}
	}

	reconstructed, err := handler.TryReconstruct(sessionID)
	if err != nil {
		t.Fatalf("reconstruct non-CES shards: %v", err)
	}
	if !bytes.Equal(reconstructed, original) {
		t.Fatal("non-CES reconstructed payload mismatch")
	}
}

func TestDestinationHandlerTryReconstructConcurrentCallersShareResult(t *testing.T) {
	pipeline := ces.NewPipeline(&ces.Config{
		HopCount:         2,
		CircuitCount:     4,
		Compression:      "gzip",
		ErasureThreshold: 2,
	})

	original := make([]byte, 1<<20)
	for i := range original {
		original[i] = byte(i)
	}
	compressed, err := pipeline.Compressor().Compress(original)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	encrypted, keyData, err := encryptSessionPayload(compressed)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	shards, err := pipeline.Sharder().Shard(encrypted)
	if err != nil {
		t.Fatalf("shard: %v", err)
	}

	handler := &DestinationHandler{
		pipeline:       pipeline,
		shardBuf:       make(map[string]map[int]*ces.Shard),
		shardTags:      make(map[string]map[int][]byte),
		totalShards:    make(map[string]int),
		reconstructing: make(map[string]*reconstructionCall),
		timers:         make(map[string]*time.Timer),
		sessions:       make(map[string]*sessionMailbox),
		sessionDone:    make(map[string]time.Time),
		keys:           make(map[string]sessionKey),
		keyData:        make(map[string][]byte),
		inboundCh:      make(chan string, 1),
		threshold:      2,
		timeout:        5 * time.Second,
		dataCh:         make(chan []byte, 1),
		stopCh:         make(chan struct{}),
	}

	const sessionID = "concurrent-threshold-session"
	for _, idx := range []int{0, 2} {
		if err := handler.AddShard(sessionID, shards[idx], keyData, nil, len(shards)); err != nil {
			t.Fatalf("add shard %d: %v", idx, err)
		}
	}

	const callers = 8
	results := make(chan []byte, callers)
	errs := make(chan error, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup

	runCaller := func() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			data, err := handler.TryReconstruct(sessionID)
			if err != nil {
				errs <- err
				return
			}
			results <- data
		}()
	}

	for i := 0; i < callers; i++ {
		runCaller()
	}
	close(start)

	wg.Wait()
	close(errs)
	close(results)

	for err := range errs {
		t.Fatalf("TryReconstruct() error = %v", err)
	}

	count := 0
	for data := range results {
		if !bytes.Equal(data, original) {
			t.Fatal("concurrent reconstruction payload mismatch")
		}
		count++
	}
	if count != callers {
		t.Fatalf("concurrent reconstruction result count = %d, want %d", count, callers)
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	if _, ok := handler.reconstructing[sessionID]; ok {
		t.Fatal("reconstruction call leaked after completion")
	}
	if _, ok := handler.shardBuf[sessionID]; ok {
		t.Fatal("completed session retained shard buffer")
	}
}

func TestDestinationHandlerIgnoresLateShardAfterThreshold(t *testing.T) {
	pipeline := ces.NewPipeline(&ces.Config{
		HopCount:         2,
		CircuitCount:     3,
		Compression:      "gzip",
		ErasureThreshold: 2,
	})

	original := bytes.Repeat([]byte("late-threshold-shard-check-"), 128)
	compressed, err := pipeline.Compressor().Compress(original)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	encrypted, keyData, err := encryptSessionPayload(compressed)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	shards, err := pipeline.Sharder().Shard(encrypted)
	if err != nil {
		t.Fatalf("shard: %v", err)
	}

	handler := &DestinationHandler{
		pipeline:       pipeline,
		shardBuf:       make(map[string]map[int]*ces.Shard),
		shardTags:      make(map[string]map[int][]byte),
		totalShards:    make(map[string]int),
		timers:         make(map[string]*time.Timer),
		sessions:       make(map[string]*sessionMailbox),
		sessionPending: make(map[string]map[uint64][]byte),
		sessionNextSeq: make(map[string]uint64),
		sessionDone:    make(map[string]time.Time),
		keys:           make(map[string]sessionKey),
		keyData:        make(map[string][]byte),
		inboundCh:      make(chan string, 2),
		threshold:      2,
		timeout:        5 * time.Second,
		dataCh:         make(chan []byte, 1),
		stopCh:         make(chan struct{}),
	}

	const sessionID = "late-shard-threshold-session"
	handler.ensureSession(sessionID)
	select {
	case got := <-handler.inboundCh:
		if got != sessionID {
			t.Fatalf("unexpected initial session notification %q", got)
		}
	default:
		t.Fatal("expected initial session notification")
	}
	if err := handler.AddShard(sessionID, shards[0], keyData, nil, len(shards)); err != nil {
		t.Fatalf("add shard 0: %v", err)
	}
	if err := handler.AddShard(sessionID, shards[2], keyData, nil, len(shards)); err != nil {
		t.Fatalf("add shard 2: %v", err)
	}
	reconstructed, err := handler.TryReconstruct(sessionID)
	if err != nil {
		t.Fatalf("reconstruct at threshold: %v", err)
	}
	if !bytes.Equal(reconstructed, original) {
		t.Fatal("reconstructed payload mismatch")
	}

	handler.ensureSession(sessionID)
	if err := handler.AddShard(sessionID, shards[1], keyData, nil, len(shards)); err != nil {
		t.Fatalf("late shard add: %v", err)
	}

	select {
	case got := <-handler.inboundCh:
		t.Fatalf("late shard reopened completed session %q", got)
	default:
	}
	if _, ok := handler.shardBuf[sessionID]; ok {
		t.Fatal("late shard recreated shard buffer for completed session")
	}
}

func BenchmarkDestinationHandlerTryReconstructCES(b *testing.B) {
	pipeline := ces.NewPipeline(&ces.Config{
		HopCount:         2,
		CircuitCount:     4,
		Compression:      "gzip",
		ErasureThreshold: 2,
	})

	original := bytes.Repeat([]byte("mixnet-benchmark-reconstruct-"), 512)
	compressed, err := pipeline.Compressor().Compress(original)
	if err != nil {
		b.Fatalf("compress: %v", err)
	}
	encrypted, keyData, err := encryptSessionPayload(compressed)
	if err != nil {
		b.Fatalf("encrypt: %v", err)
	}
	shards, err := pipeline.Sharder().Shard(encrypted)
	if err != nil {
		b.Fatalf("shard: %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(original)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		handler := &DestinationHandler{
			pipeline:       pipeline,
			shardBuf:       make(map[string]map[int]*ces.Shard),
			shardTags:      make(map[string]map[int][]byte),
			totalShards:    make(map[string]int),
			reconstructing: make(map[string]*reconstructionCall),
			timers:         make(map[string]*time.Timer),
			sessions:       make(map[string]*sessionMailbox),
			sessionDone:    make(map[string]time.Time),
			keys:           make(map[string]sessionKey),
			keyData:        make(map[string][]byte),
			inboundCh:      make(chan string, 1),
			threshold:      2,
			timeout:        5 * time.Second,
			dataCh:         make(chan []byte, 1),
			stopCh:         make(chan struct{}),
		}

		const sessionID = "bench-threshold-session"
		if err := handler.AddShard(sessionID, shards[0], keyData, nil, len(shards)); err != nil {
			b.Fatalf("add shard 0: %v", err)
		}
		if err := handler.AddShard(sessionID, shards[2], keyData, nil, len(shards)); err != nil {
			b.Fatalf("add shard 2: %v", err)
		}
		reconstructed, err := handler.TryReconstruct(sessionID)
		if err != nil {
			b.Fatalf("TryReconstruct() error = %v", err)
		}
		if len(reconstructed) != len(original) {
			b.Fatalf("len(reconstructed) = %d, want %d", len(reconstructed), len(original))
		}
	}
}
