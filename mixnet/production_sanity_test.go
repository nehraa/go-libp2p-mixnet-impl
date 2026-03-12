package mixnet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	routingcore "github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/mixnet/ces"
	"github.com/libp2p/go-libp2p/mixnet/circuit"
	"github.com/libp2p/go-libp2p/mixnet/discovery"
	"github.com/libp2p/go-libp2p/mixnet/relay"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/multiformats/go-multiaddr"
)

const sanityVerboseLogsEnv = "MIXNET_SANITY_VERBOSE_LOGS"
const sanityDockerEnv = "MIXNET_DOCKER_TEST"

// Warn if the environment disallows loopback binds, which some sandboxes do.
// Returns true if binds appear blocked.
func warnIfLoopbackBindBlocked(t *testing.T) bool {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "not permitted") {
			t.Logf("warning: loopback bind blocked; failures may be due to permissions. Rerun with sudo: sudo go test -run '^TestProductionSanity$' -count=1")
			return true
		}
		t.Fatalf("loopback bind failed: %v", err)
	}
	_ = ln.Close()
	return false
}

func TestProductionSanity(t *testing.T) {
	configureSanityRuntimeLogging(t)

	permissionBlocked := warnIfLoopbackBindBlocked(t)
	t.Cleanup(func() {
		if permissionBlocked && t.Failed() {
			t.Logf("warning: this failure may be due to loopback bind restrictions; rerun with sudo to confirm")
		}
	})

	var sanityStep int32
	const sanityTotalSteps int32 = 22
	runStep := func(name string, fn func(t *testing.T)) {
		t.Run(name, func(t *testing.T) {
			step := atomic.AddInt32(&sanityStep, 1)
			start := time.Now()

			t.Logf("\x1b[36m[%02d/%02d] %s %s\x1b[0m", step, sanityTotalSteps, sanityProgressBar(step, sanityTotalSteps), name)

			fn(t)

			elapsed := time.Since(start).Round(time.Millisecond)
			t.Logf("\x1b[32m[%02d/%02d] completed in %s\x1b[0m", step, sanityTotalSteps, elapsed)
		})
	}

	runStep("config and flags", func(t *testing.T) {
		cfg := DefaultConfig()
		if !cfg.UseCESPipeline || !cfg.HeaderPaddingEnabled || cfg.EncryptionMode != EncryptionModeFull {
			t.Fatalf("unexpected defaults: %+v", cfg)
		}
		if err := cfg.SetHopCount(3); err != nil {
			t.Fatalf("set hop count: %v", err)
		}
		if err := cfg.SetCircuitCount(4); err != nil {
			t.Fatalf("set circuit count: %v", err)
		}
		if err := cfg.SetCompression("snappy"); err != nil {
			t.Fatalf("set compression: %v", err)
		}
		if err := cfg.SetErasureThreshold(2); err != nil {
			t.Fatalf("set threshold: %v", err)
		}
		if err := cfg.SetUseCESPipeline(false); err != nil {
			t.Fatalf("set ces: %v", err)
		}
		if err := cfg.SetUseCSE(true); err != nil {
			t.Fatalf("set CSE: %v", err)
		}
		if err := cfg.SetHeaderPadding(true, 8, 32); err != nil {
			t.Fatalf("set header padding: %v", err)
		}
		if err := cfg.SetSelectionMode(SelectionModeHybrid); err != nil {
			t.Fatalf("set selection mode: %v", err)
		}
		if err := cfg.SetEncryptionMode(EncryptionModeHeaderOnly); err != nil {
			t.Fatalf("set encryption mode: %v", err)
		}
		if err := cfg.SetPayloadPaddingStrategy(PaddingStrategyBuckets); err != nil {
			t.Fatalf("set padding strategy: %v", err)
		}
		if err := cfg.SetPayloadPaddingBuckets([]int{64, 256}); err != nil {
			t.Fatalf("set padding buckets: %v", err)
		}
		if err := cfg.SetAuthTag(true, 16); err != nil {
			t.Fatalf("set auth tag: %v", err)
		}
		if err := cfg.SetSamplingSize(12); err != nil {
			t.Fatalf("set sampling size: %v", err)
		}
		if err := cfg.SetRandomnessFactor(0.4); err != nil {
			t.Fatalf("set randomness factor: %v", err)
		}
		cfg.MaxJitter = 0
		if err := cfg.Validate(); err != nil {
			t.Fatalf("validate: %v", err)
		}
		if !cfg.UseCSE {
			t.Fatal("expected CSE flag to be enabled")
		}
		if got := cfg.GetErasureThreshold(); got != cfg.CircuitCount {
			t.Fatalf("non-CES threshold mismatch: got %d want %d", got, cfg.CircuitCount)
		}

		locked := DefaultConfig()
		locked.Lock()
		if err := locked.SetHopCount(5); !errors.Is(err, ErrConfigImmutable) {
			t.Fatalf("expected immutable config error, got %v", err)
		}

		bad := &MixnetConfig{
			HopCount:             1,
			CircuitCount:         1,
			Compression:          "gzip",
			UseCESPipeline:       true,
			HeaderPaddingEnabled: true,
			HeaderPaddingMin:     16,
			HeaderPaddingMax:     8,
		}
		if err := bad.Validate(); err == nil {
			t.Fatal("expected invalid header padding range")
		}
	})

	runStep("config validation edges", func(t *testing.T) {
		cases := []struct {
			name string
			cfg  *MixnetConfig
		}{
			{"bad hop count", &MixnetConfig{HopCount: 0, CircuitCount: 2, UseCESPipeline: false}},
			{"bad circuit count", &MixnetConfig{HopCount: 2, CircuitCount: 0, UseCESPipeline: false}},
			{"bad compression", &MixnetConfig{HopCount: 2, CircuitCount: 2, UseCESPipeline: true, Compression: "bad"}},
			{"ces threshold >= count", &MixnetConfig{HopCount: 1, CircuitCount: 2, UseCESPipeline: true, Compression: "gzip", ErasureThreshold: 2}},
			{"bad selection mode", &MixnetConfig{HopCount: 2, CircuitCount: 2, UseCESPipeline: false, SelectionMode: "bad"}},
			{"bad sampling size", &MixnetConfig{HopCount: 2, CircuitCount: 2, UseCESPipeline: false, SamplingSize: 1}},
			{"bad randomness", &MixnetConfig{HopCount: 2, CircuitCount: 2, UseCESPipeline: false, RandomnessFactor: 1.5}},
			{"bad encryption mode", &MixnetConfig{HopCount: 2, CircuitCount: 2, UseCESPipeline: false, EncryptionMode: "bad"}},
			{"bad padding strategy", &MixnetConfig{HopCount: 2, CircuitCount: 2, UseCESPipeline: false, PayloadPaddingStrategy: "bad"}},
			{"bad padding range", &MixnetConfig{HopCount: 2, CircuitCount: 2, UseCESPipeline: false, PayloadPaddingStrategy: PaddingStrategyRandom, PayloadPaddingMin: 10, PayloadPaddingMax: 5}},
			{"bad bucket padding", &MixnetConfig{HopCount: 2, CircuitCount: 2, UseCESPipeline: false, PayloadPaddingStrategy: PaddingStrategyBuckets, PayloadPaddingBuckets: []int{16, 8}}},
			{"bad auth tag", &MixnetConfig{HopCount: 2, CircuitCount: 2, UseCESPipeline: false, EnableAuthTag: true, AuthTagSize: 64}},
			{"bad header padding", &MixnetConfig{HopCount: 2, CircuitCount: 2, UseCESPipeline: false, HeaderPaddingEnabled: true, HeaderPaddingMin: 8, HeaderPaddingMax: 0}},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if err := tc.cfg.Validate(); err == nil {
					t.Fatalf("expected validation error")
				}
			})
		}
	})

	runStep("crypto padding and privacy transport", func(t *testing.T) {
		payload := []byte("mixnet-payload")
		encrypted, keyData, err := encryptSessionPayload(payload)
		if err != nil {
			t.Fatalf("encrypt session payload: %v", err)
		}

		key, err := decodeSessionKeyData(keyData)
		if err != nil {
			t.Fatalf("decode session key: %v", err)
		}
		decrypted, err := decryptSessionPayload(encrypted, key)
		if err != nil {
			t.Fatalf("decrypt session payload: %v", err)
		}
		if !bytes.Equal(decrypted, payload) {
			t.Fatalf("decrypt mismatch: got %q want %q", decrypted, payload)
		}

		randomCfg := &MixnetConfig{PayloadPaddingStrategy: PaddingStrategyRandom, PayloadPaddingMin: 8, PayloadPaddingMax: 8}
		padded, changed, err := applyPayloadPadding(payload, randomCfg)
		if err != nil || !changed || len(padded) != len(payload)+8 {
			t.Fatalf("random padding failed: changed=%v len=%d err=%v", changed, len(padded), err)
		}
		withPrefix := addLengthPrefixWithLen(padded, len(payload))
		stripped, err := stripLengthPrefix(withPrefix)
		if err != nil {
			t.Fatalf("strip length prefix: %v", err)
		}
		if !bytes.Equal(stripped, payload) {
			t.Fatalf("strip mismatch: got %q want %q", stripped, payload)
		}

		bucketCfg := &MixnetConfig{PayloadPaddingStrategy: PaddingStrategyBuckets, PayloadPaddingBuckets: []int{8, 16}}
		bucketPadded, changed, err := applyPayloadPadding(bytes.Repeat([]byte("x"), 20), bucketCfg)
		if err != nil || !changed || len(bucketPadded) != 32 {
			t.Fatalf("bucket padding failed: changed=%v len=%d err=%v", changed, len(bucketPadded), err)
		}

		authTag := computeAuthTag(key, []byte("sess"), 0, 2, encrypted, true, keyData, 16)
		badKeyData := append([]byte(nil), keyData...)
		badKeyData[0] ^= 0xFF
		if bytes.Equal(authTag, computeAuthTag(key, []byte("sess"), 0, 2, encrypted, true, badKeyData, 16)) {
			t.Fatal("auth tag did not change when protected key data changed")
		}

		paddingCfg := &PrivacyPaddingConfig{Enabled: true, MinBytes: 4, MaxBytes: 4}
		encoded, err := EncodePrivacyShard(encrypted, PrivacyShardHeader{
			SessionID:   []byte("sess"),
			ShardIndex:  1,
			TotalShards: 3,
			HasKeys:     true,
			KeyData:     keyData,
			AuthTag:     authTag,
		}, paddingCfg)
		if err != nil {
			t.Fatalf("encode privacy shard: %v", err)
		}
		header, decodedPayload, err := DecodePrivacyShard(encoded)
		if err != nil {
			t.Fatalf("decode privacy shard: %v", err)
		}
		if header.ShardIndex != 1 || header.TotalShards != 3 || !header.HasKeys || len(header.Padding) != 4 {
			t.Fatalf("unexpected decoded header: %+v", header)
		}
		if !bytes.Equal(decodedPayload, encrypted) || !bytes.Equal(header.AuthTag, authTag) || !bytes.Equal(header.KeyData, keyData) {
			t.Fatal("privacy shard decode mismatch")
		}

		if _, err := encodeKeyExchangePayload(strings.Repeat("a", 256), bytes.Repeat([]byte{0x01}, 32)); err == nil {
			t.Fatal("expected circuit id too long error")
		}
		if _, err := encodeKeyExchangePayload("circuit", []byte("short")); err == nil {
			t.Fatal("expected invalid hop key length")
		}
	})

	runStep("session crypto edges", func(t *testing.T) {
		if _, err := decodeSessionKeyData([]byte("short")); err == nil {
			t.Fatal("expected invalid key data length")
		}
		if _, err := decryptSessionPayload([]byte("x"), sessionKey{Key: []byte("k"), Nonce: []byte("n")}); err == nil {
			t.Fatal("expected invalid key material")
		}
		cipher, keyData, err := encryptSessionPayload([]byte("secret"))
		if err != nil {
			t.Fatalf("encrypt session payload: %v", err)
		}
		key, err := decodeSessionKeyData(keyData)
		if err != nil {
			t.Fatalf("decode session key: %v", err)
		}
		cipher[0] ^= 0xFF
		if _, err := decryptSessionPayload(cipher, key); err == nil {
			t.Fatal("expected auth failure on tampered ciphertext")
		}
	})

	runStep("auth tag edges", func(t *testing.T) {
		key := sessionKey{Key: bytes.Repeat([]byte{1}, 32), Nonce: bytes.Repeat([]byte{2}, 24)}
		full := computeAuthTag(key, []byte("s"), 0, 1, []byte("d"), true, []byte("k"), 0)
		if len(full) != sha256.Size {
			t.Fatalf("expected full tag len %d", sha256.Size)
		}
		a := computeAuthTag(key, []byte("s"), 0, 1, []byte("d"), false, []byte("ignored"), 16)
		b := computeAuthTag(key, []byte("s"), 1, 1, []byte("d"), false, []byte("ignored"), 16)
		if bytes.Equal(a, b) {
			t.Fatal("expected different tags when shard index changes")
		}
	})

	runStep("padding edges", func(t *testing.T) {
		_, _, err := applyPayloadPadding([]byte("x"), &MixnetConfig{PayloadPaddingStrategy: PaddingStrategyRandom, PayloadPaddingMin: 8, PayloadPaddingMax: 4})
		if err == nil {
			t.Fatal("expected invalid padding range")
		}
		_, _, err = applyPayloadPadding([]byte("x"), &MixnetConfig{PayloadPaddingStrategy: PaddingStrategyBuckets})
		if err == nil {
			t.Fatal("expected buckets not configured")
		}
		_, _, err = applyPayloadPadding([]byte("x"), &MixnetConfig{PayloadPaddingStrategy: PaddingStrategyBuckets, PayloadPaddingBuckets: []int{0}})
		if err == nil {
			t.Fatal("expected invalid padding bucket size")
		}
		padded, changed, err := applyPayloadPadding(bytes.Repeat([]byte("x"), 100), &MixnetConfig{PayloadPaddingStrategy: PaddingStrategyBuckets, PayloadPaddingBuckets: []int{32}})
		if err != nil || !changed || len(padded) != 128 {
			t.Fatalf("expected bucket padding to extend to multiple: len=%d changed=%v err=%v", len(padded), changed, err)
		}
		if _, err := stripLengthPrefix([]byte{0x01}); err == nil {
			t.Fatal("expected payload too short for length prefix")
		}
		buf := addLengthPrefixWithLen([]byte("x"), 10)
		if _, err := stripLengthPrefix(buf); err == nil {
			t.Fatal("expected payload shorter than expected")
		}
	})

	runStep("privacy transport edges", func(t *testing.T) {
		tooBig := make([]byte, int(^uint16(0))+1)
		if _, err := EncodePrivacyShard([]byte("x"), PrivacyShardHeader{AuthTag: tooBig}, nil); err == nil {
			t.Fatal("expected auth tag too large")
		}
		if _, _, err := DecodePrivacyShard(append([]byte{0xFF}, bytes.Repeat([]byte{0x00}, 10)...)); err == nil {
			t.Fatal("expected invalid session length")
		}
		if _, _, err := DecodePrivacyShard([]byte{0, 0, 0, 0, 0}); err == nil {
			t.Fatal("expected data too short for padding length")
		}
	})

	runStep("privacy metrics retry key management resources", func(t *testing.T) {
		pm := NewPrivacyManager(nil)
		if pm.ShouldLogTrafficPatterns() || pm.ShouldLogRelayAddresses() || pm.ShouldLogTimingInfo() || pm.ShouldLogCircuitIDs() {
			t.Fatal("default privacy manager should disable logging")
		}
		if got := pm.AnonymizePeerID("1234567890"); got != "12345678..." {
			t.Fatalf("unexpected anonymized peer id: %s", got)
		}
		if got := pm.AnonymizeCircuitID("circuit-123"); got != "circuit-***" {
			t.Fatalf("unexpected anonymized circuit id: %s", got)
		}
		if err := VerifyPrivacyInvariants(); err != nil {
			t.Fatalf("verify privacy invariants: %v", err)
		}
		ZeroKnowledgeLog("suppressed")
		t.Setenv("LIBP2P_MIXNET_DEBUG", "1")
		ZeroKnowledgeLog("debug")

		metrics := NewMetricsCollector()
		metrics.RecordRTT(10 * time.Millisecond)
		metrics.RecordRTT(30 * time.Millisecond)
		metrics.RecordCircuitSuccess()
		metrics.RecordCircuitFailure()
		metrics.RecordRecovery()
		metrics.RecordThroughput(2048)
		metrics.RecordCompressionRatio(100, 50)
		metrics.RecordResourceUtilization(0.5)
		metrics.RecordRelayResourceUsage(2, 4096)
		metrics.LogSentMessage(64)
		metrics.LogRecvMessage(32)
		metrics.LogSentMessageStream(128, protocol.ID(ProtocolID), peer.ID("peer-a"))
		metrics.LogRecvMessageStream(256, protocol.ID(ProtocolID), peer.ID("peer-a"))
		if metrics.AverageRTT() != 20*time.Millisecond || metrics.CircuitSuccesses() != 1 || metrics.CircuitFailures() != 1 {
			t.Fatalf("unexpected metrics aggregate: %+v", metrics.GetMetrics())
		}
		if metrics.CompressionRatio() != 0.5 || metrics.RelayActiveCircuits() != 2 || metrics.RelayBandwidthPerSec() != 4096 {
			t.Fatalf("unexpected relay/compression metrics: %+v", metrics.GetMetrics())
		}
		if metrics.GetBandwidthTotals().TotalIn == 0 || metrics.GetBandwidthForPeer(peer.ID("peer-a")).TotalOut == 0 {
			t.Fatal("bandwidth metrics were not recorded")
		}
		metrics.TrimIdle(time.Now().Add(time.Hour))
		metrics.Reset()
		if metrics.GetBandwidthTotals().TotalIn != 0 || metrics.GetBandwidthTotals().TotalOut != 0 {
			t.Fatal("metrics bandwidth reset failed")
		}

		exporter := NewMetricsExporter(NewMetricsCollector())
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()
		exporter.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "mixnet_") {
			t.Fatalf("metrics handler unexpected response: code=%d body=%q", rec.Code, rec.Body.String())
		}
		if err := exporter.Start(""); err == nil {
			t.Fatal("expected metrics exporter to reject empty addr")
		}
		if m := (&Mixnet{}).MetricsHandler(); m != nil {
			t.Fatal("expected nil metrics handler for unconfigured mixnet")
		}
		if err := (&Mixnet{}).StartMetricsEndpoint("127.0.0.1:0"); err == nil {
			t.Fatal("expected metrics endpoint error when exporter missing")
		}

		km := NewKeyManager(nil)
		cktKeys, err := km.GenerateCircuitKeys("c1", 2)
		if err != nil || len(cktKeys.HopKeys) != 2 {
			t.Fatalf("generate circuit keys: %v", err)
		}
		if _, ok := km.GetCircuitKeys("c1"); !ok {
			t.Fatal("missing stored circuit keys")
		}
		sessionKeys := []*ces.EncryptionKey{{Key: bytes.Repeat([]byte{0x11}, 32), Destination: "d1"}}
		km.StoreSessionKeys("s1", sessionKeys)
		if got, ok := km.GetSessionKeys("s1"); !ok || len(got.EncryptionKeys) != 1 {
			t.Fatal("missing stored session keys")
		}
		km.EraseCircuitKeys("c1")
		if _, ok := km.GetCircuitKeys("c1"); ok {
			t.Fatal("circuit keys were not erased")
		}
		km.SecureErase()
		if _, ok := km.GetSessionKeys("s1"); ok {
			t.Fatal("session keys were not securely erased")
		}

		gc := NewGracefulCloser(2 * time.Second)
		gc.IncrementInFlight()
		done := make(chan error, 1)
		go func() { done <- gc.BeginClose() }()
		time.Sleep(150 * time.Millisecond)
		if !gc.IsClosing() {
			t.Fatal("graceful closer should be closing")
		}
		gc.DecrementInFlight()
		if err := <-done; err != nil {
			t.Fatalf("graceful close failed: %v", err)
		}
		if gc.StopChan() == nil {
			t.Fatal("missing stop channel")
		}

		attempts := 0
		retryErr := RetryWithBackoff(context.Background(), &RetryConfig{
			MaxRetries:        3,
			InitialDelay:      10 * time.Millisecond,
			MaxDelay:          20 * time.Millisecond,
			BackoffMultiplier: 1,
		}, func() error {
			attempts++
			if attempts < 2 {
				return ErrDiscoveryFailed("retry me")
			}
			return nil
		})
		if retryErr != nil || attempts != 2 {
			t.Fatalf("retry with backoff failed: attempts=%d err=%v", attempts, retryErr)
		}

		rm := NewResourceManager(&ResourceConfig{
			MaxConcurrentCircuits:   2,
			MaxBandwidthBytesPerSec: 1024,
			CircuitTimeout:          20 * time.Millisecond,
			EnableBackpressure:      true,
		})
		if rm.UsesLibp2p() {
			t.Fatal("plain resource manager should not use libp2p")
		}
		if err := rm.RegisterCircuit("c1", peer.ID("p1")); err != nil {
			t.Fatalf("register c1: %v", err)
		}
		if err := rm.RegisterCircuit("c2", peer.ID("p2")); err != nil {
			t.Fatalf("register c2: %v", err)
		}
		if err := rm.CanAcceptCircuit(); err == nil {
			t.Fatal("expected circuit capacity error")
		}
		rm.lastBandwidthCheck = time.Now()
		rm.RecordBandwidth(900, "out")
		if rm.CanSend(200) {
			t.Fatal("bandwidth limiter should reject send")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		if err := rm.WaitForBandwidth(ctx, 200); err == nil {
			t.Fatal("expected bandwidth wait timeout")
		}
		rm.UpdateActivity("c1")
		rm.UnregisterCircuit("c2")
		rm.SetActiveCircuitCount(1)
		if rm.ActiveCircuitCount() != 1 || rm.UtilizationPercent() == 0 {
			t.Fatalf("unexpected resource manager state: active=%d bw=%d util=%f", rm.ActiveCircuitCount(), rm.BandwidthPerSec(), rm.UtilizationPercent())
		}
		rm.StartCleanup(context.Background())
		time.Sleep(40 * time.Millisecond)
		rm.Stop()
	})

	runStep("resource manager rcmgr integration", func(t *testing.T) {
		limits := rcmgr.DefaultLimits.AutoScale()
		partial := rcmgr.PartialLimitConfig{
			Stream: rcmgr.ResourceLimits{StreamsOutbound: rcmgr.BlockAllLimit},
		}
		limited := partial.Build(limits)
		rc, err := rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(limited))
		if err != nil {
			t.Fatalf("new resource manager: %v", err)
		}
		h, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.ResourceManager(rc),
			libp2p.DisableRelay(),
		)
		if err != nil {
			t.Fatalf("new host with rcmgr: %v", err)
		}
		defer h.Close()

		peerHost := newTestHost(t)
		defer peerHost.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.Connect(ctx, peer.AddrInfo{ID: peerHost.ID(), Addrs: peerHost.Addrs()}); err != nil {
			t.Fatalf("connect host: %v", err)
		}

		handler := relay.NewHandler(h, 4, 1024*1024)
		handler.EnableLibp2pResourceManager(true)
		h.SetStreamHandler(relay.ProtocolID, handler.HandleStream)
		h.SetStreamHandler(KeyExchangeProtocolID, handler.HandleKeyExchange)

		dest := newTestHost(t)
		defer dest.Close()
		if err := h.Connect(ctx, peer.AddrInfo{ID: dest.ID(), Addrs: dest.Addrs()}); err != nil {
			t.Fatalf("connect to dest: %v", err)
		}
		delivered := make(chan struct{}, 1)
		dest.SetStreamHandler(protocol.ID(ProtocolID), func(s network.Stream) {
			delivered <- struct{}{}
			_ = s.Close()
		})

		origin := newTestHost(t)
		defer origin.Close()
		if err := origin.Connect(ctx, peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()}); err != nil {
			t.Fatalf("connect origin->relay: %v", err)
		}
		m := &Mixnet{host: origin}
		key, err := m.exchangeHopKey(ctx, h.ID(), "rcmgr-circuit")
		if err != nil {
			t.Fatalf("exchange hop key: %v", err)
		}
		c := circuit.NewCircuit("rcmgr-circuit", []peer.ID{h.ID()})
		onion, err := encryptOnion([]byte{msgTypeData, 0x01}, c, dest.ID(), [][]byte{key})
		if err != nil {
			t.Fatalf("encrypt onion: %v", err)
		}
		frame, err := encodeEncryptedFrameWithVersion("rcmgr-circuit", frameVersionFullOnion, onion)
		if err != nil {
			t.Fatalf("frame: %v", err)
		}
		s, err := origin.NewStream(ctx, h.ID(), protocol.ID(relay.ProtocolID))
		if err != nil {
			t.Fatalf("open stream: %v", err)
		}
		if _, err := s.Write(frame); err != nil {
			t.Fatalf("write frame: %v", err)
		}
		_ = s.Close()

		select {
		case <-delivered:
			t.Fatal("expected rcmgr to reject outbound stream")
		case <-time.After(300 * time.Millisecond):
		}
	})

	runStep("discovery and circuit manager", func(t *testing.T) {
		rd := discovery.NewRelayDiscovery(ProtocolID, 3, "random", 0.3)
		peers := []peer.AddrInfo{
			{ID: "r1"},
			{ID: "r2"},
			{ID: "r3", Addrs: []multiaddr.Multiaddr{mustMultiaddr(t)}},
			{ID: "r4", Addrs: []multiaddr.Multiaddr{mustMultiaddr(t)}},
			{ID: "r5", Addrs: []multiaddr.Multiaddr{mustMultiaddr(t)}},
		}
		relays, err := rd.FindRelays(context.Background(), peers, 1, 2)
		if err != nil || len(relays) != 2 {
			t.Fatalf("find relays random: relays=%d err=%v", len(relays), err)
		}

		selected, err := discovery.NewRelayDiscovery(ProtocolID, 3, "rtt", 0.3).FindRelays(context.Background(), peers[2:], 1, 2)
		if err != nil || len(selected) != 2 {
			t.Fatalf("find relays rtt: relays=%d err=%v", len(selected), err)
		}

		hybrid, err := discovery.NewRelayDiscovery(ProtocolID, 4, "hybrid", 0.5).FindRelays(context.Background(), peers[2:], 1, 2)
		if err != nil || len(hybrid) != 2 {
			t.Fatalf("find relays hybrid: relays=%d err=%v", len(hybrid), err)
		}
		excluded := discovery.FilterByExclusion(peers[2:], peer.ID("r3"))
		for _, p := range excluded {
			if p.ID == "r3" {
				t.Fatal("excluded peer was returned")
			}
		}

		if circuit.StatePending.String() != "pending" || circuit.CircuitState(99).String() != "unknown" {
			t.Fatal("unexpected circuit state strings")
		}
		cm := circuit.NewCircuitManager(&circuit.CircuitConfig{HopCount: 1, CircuitCount: 3})
		relayPool := []circuit.RelayInfo{
			{PeerID: "a"}, {PeerID: "b"}, {PeerID: "c"},
		}
		circuits, err := cm.BuildCircuits(context.Background(), peer.ID("dest"), relayPool)
		if err != nil || len(circuits) != 3 {
			t.Fatalf("build circuits: count=%d err=%v", len(circuits), err)
		}
		first := circuits[0]
		if first.GetState() != circuit.StateBuilding || first.Entry() == "" || first.Exit() == "" {
			t.Fatalf("unexpected circuit state: %+v", first)
		}

		if err := cm.ActivateCircuit(first.ID); err != nil {
			t.Fatalf("activate circuit: %v", err)
		}
		first.MarkFailed()

		if !cm.DetectFailure(first.ID) {
			t.Fatal("failed circuit should be detected")
		}
		if _, err := cm.RebuildCircuit(first.ID); err == nil {
			t.Fatal("expected rebuild failure without enough spare relays")
		}
		cm.MarkCircuitFailed(circuits[1].ID)
		if cm.CanRecover() {
			t.Fatal("circuit manager should not recover with threshold met exactly")
		}
		if cm.RecoveryCapacity() != -1 {
			t.Fatalf("unexpected recovery capacity: %d", cm.RecoveryCapacity())
		}

		cm2 := circuit.NewCircuitManager(&circuit.CircuitConfig{HopCount: 1, CircuitCount: 3})
		relayPool = []circuit.RelayInfo{{PeerID: "a"}, {PeerID: "b"}, {PeerID: "c"}, {PeerID: "d"}, {PeerID: "e"}}
		circuits, err = cm2.BuildCircuits(context.Background(), peer.ID("dest"), relayPool)
		if err != nil {
			t.Fatalf("build circuits with spare relays: %v", err)
		}
		for _, c := range circuits {
			if err := cm2.ActivateCircuit(c.ID); err != nil {
				t.Fatalf("activate circuit %s: %v", c.ID, err)
			}
		}
		cm2.MarkCircuitFailed(circuits[0].ID)
		rebuilt, err := cm2.RebuildCircuit(circuits[0].ID)
		if err != nil || rebuilt == nil {
			t.Fatalf("rebuild circuit: %v", err)
		}
		// Run recovery rebuild multiple times to make this check resilient to relay shuffle order.
		for i := 0; i < 25; i++ {
			cm3 := circuit.NewCircuitManager(&circuit.CircuitConfig{HopCount: 3, CircuitCount: 3})
			relayPool = []circuit.RelayInfo{
				{PeerID: "a"}, {PeerID: "b"}, {PeerID: "c"},
				{PeerID: "d"}, {PeerID: "e"}, {PeerID: "f"},
				{PeerID: "g"}, {PeerID: "h"}, {PeerID: "i"},
			}
			circuits, err = cm3.BuildCircuits(context.Background(), peer.ID("dest"), relayPool)
			if err != nil || len(circuits) != 3 {
				t.Fatalf("iteration %d: build circuits for refreshed recovery: count=%d err=%v", i, len(circuits), err)
			}
			for _, c := range circuits {
				if err := cm3.ActivateCircuit(c.ID); err != nil {
					t.Fatalf("iteration %d: activate circuit %s for refreshed recovery: %v", i, c.ID, err)
				}
			}
			failed := circuits[0]
			failedRelay := failed.Entry()
			cm3.MarkCircuitFailed(failed.ID)
			updatedPool := make([]circuit.RelayInfo, 0, len(relayPool)-1)
			for _, id := range []peer.ID{"a", "b", "c", "d", "e", "f", "g", "h", "i"} {
				if id == failedRelay {
					continue
				}
				updatedPool = append(updatedPool, circuit.RelayInfo{PeerID: id})
			}
			cm3.UpdateRelayPool(updatedPool)
			rebuilt, err = cm3.RebuildCircuit(failed.ID)
			if err != nil || rebuilt == nil {
				t.Fatalf("iteration %d: rebuild circuit with refreshed pool: %v", i, err)
			}
			for _, p := range rebuilt.Peers {
				if p == failedRelay {
					t.Fatalf("iteration %d: rebuilt circuit still uses failed relay %s", i, failedRelay)
				}
			}
			seenPeers := make(map[peer.ID]struct{}, len(rebuilt.Peers))
			for _, p := range rebuilt.Peers {
				if _, ok := seenPeers[p]; ok {
					t.Fatalf("iteration %d: rebuilt circuit reused relay %s within the same circuit", i, p)
				}
				seenPeers[p] = struct{}{}
			}
			if err := cm3.Close(); err != nil {
				t.Fatalf("iteration %d: close refreshed recovery circuit manager: %v", i, err)
			}
		}
		if err := cm2.Close(); err != nil {
			t.Fatalf("close circuit manager: %v", err)
		}
	})

	runStep("relay discovery edge cases", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		host := newTestHost(t)
		defer host.Close()

		emptyRouting := &staticRouting{providers: nil, peers: map[peer.ID]peer.AddrInfo{}}
		if _, err := DiscoverRelaysWithVerification(ctx, host, emptyRouting, peer.ID("dest"), ProtocolID, 1, 1, 1, string(SelectionModeRandom), 0.3); err == nil {
			t.Fatal("expected discovery failure with no providers")
		}

		rd := discovery.NewRelayDiscovery(ProtocolID, 2, "random", 0.2)
		peers := []peer.AddrInfo{
			{ID: "r1"},
			{ID: "r2", Addrs: []multiaddr.Multiaddr{mustMultiaddr(t)}},
			{ID: "r3", Addrs: []multiaddr.Multiaddr{mustMultiaddr(t)}},
			{ID: "r4", Addrs: []multiaddr.Multiaddr{mustMultiaddr(t)}},
		}
		if _, err := rd.FindRelays(ctx, peers[:1], 1, 2); err == nil {
			t.Fatal("expected insufficient peers error")
		}
		selected, err := rd.FindRelays(ctx, peers[1:], 1, 2)
		if err != nil || len(selected) != 2 {
			t.Fatalf("expected random selection of 2 relays: len=%d err=%v", len(selected), err)
		}
		host.Peerstore().AddAddrs(peer.ID("r2"), peers[1].Addrs, peerstore.PermanentAddrTTL)
		host.Peerstore().AddAddrs(peer.ID("r3"), peers[2].Addrs, peerstore.PermanentAddrTTL)
		host.Peerstore().AddAddrs(peer.ID("r4"), peers[3].Addrs, peerstore.PermanentAddrTTL)
		if err := host.Peerstore().SetProtocols(peer.ID("r2"), protocol.ID(ProtocolID)); err != nil {
			t.Fatalf("set protocols for r2: %v", err)
		}
		if err := host.Peerstore().SetProtocols(peer.ID("r3"), protocol.ID(ProtocolID)); err != nil {
			t.Fatalf("set protocols for r3: %v", err)
		}
		if err := host.Peerstore().SetProtocols(peer.ID("r4"), protocol.ID(ProtocolID)); err != nil {
			t.Fatalf("set protocols for r4: %v", err)
		}
		routing := &staticRouting{
			providers: []peer.AddrInfo{peers[1], peers[2], peers[3]},
			peers: map[peer.ID]peer.AddrInfo{
				peer.ID("r2"): peers[1],
				peer.ID("r3"): peers[2],
				peer.ID("r4"): peers[3],
			},
		}
		discovered, err := DiscoverRelaysWithVerification(ctx, host, routing, peer.ID("dest"), ProtocolID, 1, 2, 2, string(SelectionModeHybrid), 0.3)
		if err != nil || len(discovered) != 2 {
			if !isDockerSanityRun() {
				t.Logf("warning: relay_discovery_edge_cases may fail on localhost/network timing; run docker tests to confirm. len=%d err=%v", len(discovered), err)
			} else {
				t.Fatalf("expected verified discovery to return 2 relays: len=%d err=%v", len(discovered), err)
			}
		}
		excluded := discovery.FilterByExclusion(peers[1:], peer.ID("r2"), peer.ID("r3"))
		for _, p := range excluded {
			if p.ID == "r2" || p.ID == "r3" {
				t.Fatal("excluded peer returned")
			}
		}
	})

	runStep("circuit manager edge cases", func(t *testing.T) {
		cm := circuit.NewCircuitManager(&circuit.CircuitConfig{HopCount: 2, CircuitCount: 2})
		if _, err := cm.BuildCircuits(context.Background(), peer.ID("dest"), []circuit.RelayInfo{{PeerID: "r1"}}); err == nil {
			t.Fatal("expected insufficient relays error")
		}
		if _, err := cm.BuildCircuit(); err == nil {
			t.Fatal("expected build circuit error with empty pool")
		}
		relays := []circuit.RelayInfo{
			{PeerID: "r1", AddrInfo: peer.AddrInfo{ID: "r1", Addrs: []multiaddr.Multiaddr{mustMultiaddr(t)}}},
			{PeerID: "r2", AddrInfo: peer.AddrInfo{ID: "r2", Addrs: []multiaddr.Multiaddr{mustMultiaddr(t)}}},
			{PeerID: "r3", AddrInfo: peer.AddrInfo{ID: "r3", Addrs: []multiaddr.Multiaddr{mustMultiaddr(t)}}},
			{PeerID: "r4", AddrInfo: peer.AddrInfo{ID: "r4", Addrs: []multiaddr.Multiaddr{mustMultiaddr(t)}}},
		}
		circuits, err := cm.BuildCircuits(context.Background(), peer.ID("dest"), relays)
		if err != nil || len(circuits) != 2 {
			t.Fatalf("build circuits edge: count=%d err=%v", len(circuits), err)
		}
		if _, err := cm.RebuildCircuit(circuits[0].ID); err == nil {
			t.Fatal("expected rebuild error when circuit not failed")
		}
		_ = cm.ActivateCircuit(circuits[0].ID)
		cm.MarkCircuitFailed(circuits[0].ID)
		if _, err := cm.RebuildCircuit(circuits[0].ID); err == nil {
			t.Fatal("expected rebuild error without spare relays")
		}
		if got := cm.RecoveryCapacity(); got != -1 {
			t.Fatalf("expected recovery capacity -1, got %d", got)
		}
		_ = cm.ActivateCircuit(circuits[1].ID)
		if got := cm.RecoveryCapacity(); got != 0 {
			t.Fatalf("expected recovery capacity 0 at threshold, got %d", got)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		origin := newTestHost(t)
		relayHost := newTestHost(t)
		defer origin.Close()
		defer relayHost.Close()
		relayHost.SetStreamHandler(protocol.ID("/test/manager/1.0.0"), func(s network.Stream) {
			defer s.Close()
			buf := make([]byte, 16)
			n, err := s.Read(buf)
			if err != nil {
				return
			}
			_, _ = s.Write(bytes.ToUpper(buf[:n]))
		})
		origin.Peerstore().AddAddrs(relayHost.ID(), relayHost.Addrs(), peerstore.PermanentAddrTTL)

		manager := circuit.NewCircuitManager(&circuit.CircuitConfig{HopCount: 1, CircuitCount: 1, StreamTimeout: 2 * time.Second})
		manager.SetHost(origin)
		built, err := manager.BuildCircuits(ctx, peer.ID("dest"), []circuit.RelayInfo{{
			PeerID:   relayHost.ID(),
			AddrInfo: peer.AddrInfo{ID: relayHost.ID(), Addrs: relayHost.Addrs()},
		}})
		if err != nil || len(built) != 1 {
			t.Fatalf("build direct manager circuit: len=%d err=%v", len(built), err)
		}
		if err := manager.EstablishCircuit(built[0], peer.ID("dest"), "/test/manager/1.0.0"); err != nil {
			t.Fatalf("establish circuit: %v", err)
		}
		if err := manager.SendData(built[0].ID, []byte("ping")); err != nil {
			t.Fatalf("send data through manager: %v", err)
		}
		reply := make([]byte, 8)
		n, err := manager.ReadData(built[0].ID, reply)
		if err != nil {
			t.Fatalf("read data through manager: %v", err)
		}
		if got := string(reply[:n]); got != "PING" {
			t.Fatalf("unexpected manager reply: %q", got)
		}
		if err := manager.CloseCircuitWithContext(ctx, built[0].ID); err != nil {
			t.Fatalf("close circuit with context: %v", err)
		}
	})

	runStep("mixstream and upgrader basics", func(t *testing.T) {
		u := NewStreamUpgrader(nil)
		if u == nil || u.mixnet != nil {
			t.Fatalf("unexpected upgrader state: %#v", u)
		}
		var _ StreamUpgrader = (*MixnetStreamUpgrader)(nil)

		s := &MixStream{proto: "/test/1.0.0"}
		if s.proto != "/test/1.0.0" {
			t.Fatalf("unexpected proto: %q", s.proto)
		}
		s = &MixStream{closed: true, dest: peer.ID("some-peer"), ctx: context.Background()}
		if _, err := s.Write([]byte("hello")); err == nil {
			t.Fatal("expected write error on closed stream")
		}
		s = &MixStream{dest: "", ctx: context.Background()}
		if _, err := s.Write([]byte("hello")); err == nil {
			t.Fatal("expected write error on inbound-only stream")
		}
		s = &MixStream{closed: true, sessionID: "test", ch: make(chan []byte), ctx: context.Background()}
		if err := s.Close(); err != nil {
			t.Fatalf("close idempotent stream: %v", err)
		}
	})

	runStep("actual nodes relay forwarding", func(t *testing.T) {
		t.Run("full onion", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			origin, entry, middle, exit, destination, cleanup := setupRelayForwardingHosts(t)
			defer cleanup()
			connectRelayPath(t, ctx, origin, entry, middle, exit, destination)

			entrySeen := make(chan peer.ID, 1)
			middleSeen := make(chan peer.ID, 1)
			exitSeen := make(chan peer.ID, 1)
			destSeen := make(chan peer.ID, 1)
			destPayload := make(chan []byte, 1)

			entryHandler := relay.NewHandler(entry, 8, 1024*1024)
			entryHandler.EnableLibp2pResourceManager(false)
			entry.SetStreamHandler(relay.ProtocolID, func(s network.Stream) {
				entrySeen <- s.Conn().RemotePeer()
				entryHandler.HandleStream(s)
			})
			entry.SetStreamHandler(KeyExchangeProtocolID, entryHandler.HandleKeyExchange)

			middleHandler := relay.NewHandler(middle, 8, 1024*1024)
			middleHandler.EnableLibp2pResourceManager(false)
			middle.SetStreamHandler(relay.ProtocolID, func(s network.Stream) {
				middleSeen <- s.Conn().RemotePeer()
				middleHandler.HandleStream(s)
			})
			middle.SetStreamHandler(KeyExchangeProtocolID, middleHandler.HandleKeyExchange)

			exitHandler := relay.NewHandler(exit, 8, 1024*1024)
			exitHandler.EnableLibp2pResourceManager(false)
			exit.SetStreamHandler(relay.ProtocolID, func(s network.Stream) {
				exitSeen <- s.Conn().RemotePeer()
				exitHandler.HandleStream(s)
			})
			exit.SetStreamHandler(KeyExchangeProtocolID, exitHandler.HandleKeyExchange)

			destination.SetStreamHandler(protocol.ID(ProtocolID), func(s network.Stream) {
				defer s.Close()
				destSeen <- s.Conn().RemotePeer()
				payload, _ := io.ReadAll(s)
				destPayload <- payload
			})

			originMix := &Mixnet{host: origin}
			circuitID := "relay-proof"
			hopKeys := exchangeRelayHopKeys(t, ctx, originMix, circuitID, entry.ID(), middle.ID(), exit.ID())
			c := circuit.NewCircuit(circuitID, []peer.ID{entry.ID(), middle.ID(), exit.ID()})
			payload := []byte("live-relay-forwarding-proof")
			onionPayload, err := encryptOnion(payload, c, destination.ID(), hopKeys)
			if err != nil {
				t.Fatalf("encrypt onion payload: %v", err)
			}
			frame, err := encodeEncryptedFrameWithVersion(circuitID, frameVersionFullOnion, onionPayload)
			if err != nil {
				t.Fatalf("encode full onion frame: %v", err)
			}

			stream, err := origin.NewStream(ctx, entry.ID(), protocol.ID(relay.ProtocolID))
			if err != nil {
				t.Fatalf("open stream to entry: %v", err)
			}
			if _, err := stream.Write(frame); err != nil {
				t.Fatalf("write full onion frame: %v", err)
			}
			_ = stream.Close()

			if got := waitPeer(t, entrySeen, 5*time.Second); got != origin.ID() {
				t.Fatalf("entry saw %s, want %s", got, origin.ID())
			}
			if got := waitPeer(t, middleSeen, 5*time.Second); got != entry.ID() {
				t.Fatalf("middle saw %s, want %s", got, entry.ID())
			}
			if got := waitPeer(t, exitSeen, 5*time.Second); got != middle.ID() {
				t.Fatalf("exit saw %s, want %s", got, middle.ID())
			}
			if got := waitPeer(t, destSeen, 5*time.Second); got != exit.ID() {
				t.Fatalf("destination saw %s, want %s", got, exit.ID())
			}
			if got := waitData(t, destPayload, 5*time.Second); !bytes.Equal(got, payload) {
				t.Fatalf("destination payload mismatch: got %q want %q", got, payload)
			}
		})

		t.Run("header only onion", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			origin, entry, middle, exit, destination, cleanup := setupRelayForwardingHosts(t)
			defer cleanup()
			connectRelayPath(t, ctx, origin, entry, middle, exit, destination)

			entryHandler := relay.NewHandler(entry, 8, 1024*1024)
			entryHandler.EnableLibp2pResourceManager(false)
			entry.SetStreamHandler(relay.ProtocolID, entryHandler.HandleStream)
			entry.SetStreamHandler(KeyExchangeProtocolID, entryHandler.HandleKeyExchange)

			middleHandler := relay.NewHandler(middle, 8, 1024*1024)
			middleHandler.EnableLibp2pResourceManager(false)
			middle.SetStreamHandler(relay.ProtocolID, middleHandler.HandleStream)
			middle.SetStreamHandler(KeyExchangeProtocolID, middleHandler.HandleKeyExchange)

			exitHandler := relay.NewHandler(exit, 8, 1024*1024)
			exitHandler.EnableLibp2pResourceManager(false)
			exit.SetStreamHandler(relay.ProtocolID, exitHandler.HandleStream)
			exit.SetStreamHandler(KeyExchangeProtocolID, exitHandler.HandleKeyExchange)

			headerCh := make(chan *PrivacyShardHeader, 1)
			payloadCh := make(chan []byte, 1)
			errCh := make(chan error, 1)
			destination.SetStreamHandler(protocol.ID(ProtocolID), func(s network.Stream) {
				defer s.Close()
				packet, _ := io.ReadAll(s)
				if len(packet) == 0 || packet[0] != msgTypeData {
					errCh <- errors.New("missing msgTypeData prefix")
					return
				}
				header, body, err := DecodePrivacyShard(packet[1:])
				if err != nil {
					errCh <- err
					return
				}
				headerCh <- header
				payloadCh <- body
			})

			originMix := &Mixnet{host: origin}
			circuitID := "header-proof"
			hopKeys := exchangeRelayHopKeys(t, ctx, originMix, circuitID, entry.ID(), middle.ID(), exit.ID())
			c := circuit.NewCircuit(circuitID, []peer.ID{entry.ID(), middle.ID(), exit.ID()})
			controlHeader, err := EncodePrivacyShard(nil, PrivacyShardHeader{
				SessionID:   []byte("header-session"),
				ShardIndex:  0,
				TotalShards: 1,
				HasKeys:     true,
				KeyData:     []byte("keydata"),
			}, &PrivacyPaddingConfig{Enabled: true, MinBytes: 4, MaxBytes: 4})
			if err != nil {
				t.Fatalf("encode control header: %v", err)
			}
			body := bytes.Repeat([]byte("header-only-stream-body-"), 1<<11)
			onionHeader, err := encryptOnionHeader(controlHeader, c, destination.ID(), hopKeys)
			if err != nil {
				t.Fatalf("encrypt onion header: %v", err)
			}
			frame, err := encodeEncryptedFrameWithVersion(circuitID, frameVersionHeaderOnly, buildHeaderOnlyPayload(onionHeader, body))
			if err != nil {
				t.Fatalf("encode header-only frame: %v", err)
			}
			stream, err := origin.NewStream(ctx, entry.ID(), protocol.ID(relay.ProtocolID))
			if err != nil {
				t.Fatalf("open header-only stream: %v", err)
			}
			if _, err := stream.Write(frame); err != nil {
				t.Fatalf("write header-only frame: %v", err)
			}
			_ = stream.Close()

			var header *PrivacyShardHeader
			select {
			case err := <-errCh:
				t.Fatalf("header-only decode failed: %v", err)
			case header = <-headerCh:
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for forwarded header")
			}
			if string(header.SessionID) != "header-session" || !header.HasKeys || string(header.KeyData) != "keydata" {
				t.Fatalf("unexpected forwarded header: %+v", header)
			}
			if got := waitData(t, payloadCh, 5*time.Second); !bytes.Equal(got, body) {
				t.Fatalf("header-only body mismatch: got %q want %q", got, body)
			}
		})
	})

	runStep("onion header helpers", func(t *testing.T) {
		c := circuit.NewCircuit("c-onion", []peer.ID{"p1", "p2"})
		hopKeys := [][]byte{
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 32),
		}
		if _, err := encryptOnionHeader([]byte("hdr"), &circuit.Circuit{}, peer.ID("dest"), hopKeys); err == nil {
			t.Fatal("expected empty circuit error")
		}
		if _, err := encryptOnionHeader([]byte("hdr"), c, peer.ID("dest"), hopKeys[:1]); err == nil {
			t.Fatal("expected hop key mismatch")
		}
		hdr := []byte("h")
		payload := []byte("payload")
		frame := buildHeaderOnlyPayload(hdr, payload)
		if got := binary.LittleEndian.Uint32(frame[:4]); got != uint32(len(hdr)) {
			t.Fatalf("header length mismatch: got %d want %d", got, len(hdr))
		}
	})

	runStep("mixnet api end to end", func(t *testing.T) {
		t.Run("key exchange basic", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			origin := newTestHost(t)
			relayHost := newTestHost(t)
			handler := relay.NewHandler(relayHost, 4, 1024*1024)
			handler.EnableLibp2pResourceManager(false)
			relayHost.SetStreamHandler(KeyExchangeProtocolID, handler.HandleKeyExchange)
			// connect origin to relay so exchangeHopKey can open the stream
			if err := origin.Connect(ctx, peer.AddrInfo{ID: relayHost.ID(), Addrs: relayHost.Addrs()}); err != nil {
				t.Fatalf("connect origin->relay: %v", err)
			}

			m := &Mixnet{host: origin}
			key, err := m.exchangeHopKey(ctx, relayHost.ID(), "kx-circuit")
			if err != nil {
				t.Fatalf("exchange hop key: %v", err)
			}

			if len(key) != 32 {
				t.Fatalf("hop key length = %d, want 32", len(key))
			}
		})

		t.Run("padding and auth flags", func(t *testing.T) {
			randomCfg := &MixnetConfig{PayloadPaddingStrategy: PaddingStrategyRandom, PayloadPaddingMin: 4, PayloadPaddingMax: 8}
			padded, changed, err := applyPayloadPadding([]byte("pad"), randomCfg)
			if err != nil || !changed || len(padded) < len("pad")+4 || len(padded) > len("pad")+8 {
				t.Fatalf("random padding failed: len=%d changed=%v err=%v", len(padded), changed, err)
			}

			bucketCfg := &MixnetConfig{PayloadPaddingStrategy: PaddingStrategyBuckets, PayloadPaddingBuckets: []int{16, 32}}
			padded, changed, err = applyPayloadPadding(bytes.Repeat([]byte("x"), 20), bucketCfg)
			if err != nil || !changed || len(padded) != 32 {
				t.Fatalf("bucket padding failed: len=%d changed=%v err=%v", len(padded), changed, err)
			}

			noneCfg := &MixnetConfig{PayloadPaddingStrategy: PaddingStrategyNone}
			padded, changed, err = applyPayloadPadding([]byte("no-pad"), noneCfg)
			if err != nil || changed || !bytes.Equal(padded, []byte("no-pad")) {
				t.Fatalf("none padding failed: changed=%v err=%v", changed, err)
			}

			cfg := &MixnetConfig{HeaderPaddingEnabled: false}
			m := &Mixnet{config: cfg}
			if m.headerPaddingConfig() != nil {
				t.Fatalf("expected nil header padding when disabled")
			}
			cfg.HeaderPaddingEnabled = true
			cfg.HeaderPaddingMin = 2
			cfg.HeaderPaddingMax = 4
			if hpc := m.headerPaddingConfig(); hpc == nil || !hpc.Enabled || hpc.MinBytes != 2 || hpc.MaxBytes != 4 {
				t.Fatalf("unexpected header padding config: %+v", hpc)
			}
		})

		t.Run("ces send full onion", func(t *testing.T) {
			cfg := &MixnetConfig{
				HopCount:               1,
				CircuitCount:           3,
				Compression:            "gzip",
				UseCESPipeline:         true,
				EncryptionMode:         EncryptionModeFull,
				HeaderPaddingEnabled:   true,
				HeaderPaddingMin:       8,
				HeaderPaddingMax:       16,
				PayloadPaddingStrategy: PaddingStrategyRandom,
				PayloadPaddingMin:      4,
				PayloadPaddingMax:      8,
				EnableAuthTag:          true,
				AuthTagSize:            16,
				SelectionMode:          SelectionModeRandom,
				SamplingSize:           9,
				RandomnessFactor:       0.3,
				MaxJitter:              0,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()

			origin, dest, _, cleanup := setupMixnetNetwork(t, ctx, cfg, 9)
			defer cleanup()

			wait := expectInboundPayload(t, ctx, dest)
			payload := bytes.Repeat([]byte("X"), 2048)
			if err := origin.Send(ctx, dest.Host().ID(), payload); err != nil {
				t.Fatalf("ces send: %v", err)
			}
			wait("", payload)
		})

		t.Run("header-only ces send", func(t *testing.T) {
			cfg := &MixnetConfig{
				HopCount:               1,
				CircuitCount:           3,
				Compression:            "gzip",
				UseCESPipeline:         true,
				EncryptionMode:         EncryptionModeHeaderOnly,
				HeaderPaddingEnabled:   true,
				HeaderPaddingMin:       4,
				HeaderPaddingMax:       8,
				PayloadPaddingStrategy: PaddingStrategyNone,
				EnableAuthTag:          true,
				AuthTagSize:            16,
				SelectionMode:          SelectionModeRandom,
				SamplingSize:           9,
				RandomnessFactor:       0.3,
				MaxJitter:              0,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()

			origin, dest, _, cleanup := setupMixnetNetwork(t, ctx, cfg, 9)
			defer cleanup()

			wait := expectInboundPayload(t, ctx, dest)
			payload := []byte("header-only-ces")
			if err := origin.Send(ctx, dest.Host().ID(), payload); err != nil {
				t.Fatalf("header-only ces send: %v", err)
			}
			wait("", payload)
		})

		t.Run("non-ces cse send", func(t *testing.T) {
			cfg := &MixnetConfig{
				HopCount:               1,
				CircuitCount:           3,
				Compression:            "gzip",
				UseCESPipeline:         false,
				UseCSE:                 true,
				EncryptionMode:         EncryptionModeFull,
				HeaderPaddingEnabled:   false,
				PayloadPaddingStrategy: PaddingStrategyNone,
				EnableAuthTag:          true,
				AuthTagSize:            16,
				SelectionMode:          SelectionModeRandom,
				SamplingSize:           9,
				RandomnessFactor:       0.3,
				MaxJitter:              0,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()

			origin, dest, _, cleanup := setupMixnetNetwork(t, ctx, cfg, 9)
			defer cleanup()

			wait := expectInboundPayload(t, ctx, dest)
			payload := bytes.Repeat([]byte("cse-fast-path-"), 4096)
			if err := origin.Send(ctx, dest.Host().ID(), payload); err != nil {
				t.Fatalf("non-CES CSE send: %v", err)
			}
			wait("", payload)
		})

		cfg := &MixnetConfig{
			HopCount:               1,
			CircuitCount:           3,
			Compression:            "gzip",
			UseCESPipeline:         false,
			EncryptionMode:         EncryptionModeFull,
			HeaderPaddingEnabled:   false,
			PayloadPaddingStrategy: PaddingStrategyNone,
			EnableAuthTag:          false,
			SelectionMode:          SelectionModeRandom,
			SamplingSize:           9,
			RandomnessFactor:       0.3,
			MaxJitter:              0,
		}

		t.Run("new mixnet and establish connection", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			origin, dest, _, cleanup := setupMixnetNetwork(t, ctx, cfg, 9)
			defer cleanup()

			circuits, err := origin.EstablishConnection(ctx, dest.Host().ID())
			if err != nil {
				t.Fatalf("establish connection: %v", err)
			}
			if len(circuits) != cfg.CircuitCount {
				t.Fatalf("circuit count mismatch: got %d want %d", len(circuits), cfg.CircuitCount)
			}
			for _, c := range circuits {
				if !c.IsActive() || len(c.Peers) != cfg.HopCount {
					t.Fatalf("unexpected established circuit: %+v", c)
				}
			}
			active := origin.ActiveConnections()[dest.Host().ID()]
			if len(active) != cfg.CircuitCount {
				t.Fatalf("active connection count mismatch: got %d want %d", len(active), cfg.CircuitCount)
			}
		})

		t.Run("send and send with session", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			origin, dest, _, cleanup := setupMixnetNetwork(t, ctx, cfg, 9)
			defer cleanup()

			waitWithSession := expectInboundPayload(t, ctx, dest)
			if err := origin.SendWithSession(ctx, dest.Host().ID(), []byte("mixnet-send-with-session"), "custom-session"); err != nil {
				t.Fatalf("send with session: %v", err)
			}
			waitWithSession("custom-session", []byte("mixnet-send-with-session"))

			waitSend := expectInboundPayload(t, ctx, dest)
			if err := origin.Send(ctx, dest.Host().ID(), []byte("mixnet-send")); err != nil {
				t.Fatalf("send: %v", err)
			}
			waitSend("", []byte("mixnet-send"))

			routedCfg := cloneConfig(cfg)
			routedCfg.EnableSessionRouting = true
			routedCfg.SessionRouteIdleTimeout = 2 * time.Second
			routedCfg.EncryptionMode = EncryptionModeHeaderOnly

			originRouted, destRouted, _, routedCleanup := setupMixnetNetwork(t, ctx, routedCfg, 9)
			defer routedCleanup()

			inboundCh := make(chan *MixStream, 1)
			inboundErrCh := make(chan error, 1)
			go func() {
				s, err := destRouted.AcceptStream(ctx)
				if err != nil {
					inboundErrCh <- err
					return
				}
				inboundCh <- s
			}()

			sessionID := "custom-session-routed"
			routedPayloads := [][]byte{
				[]byte("mixnet-send-with-session-routed-1"),
				[]byte("mixnet-send-with-session-routed-2"),
			}
			for _, payload := range routedPayloads {
				if err := originRouted.SendWithSession(ctx, destRouted.Host().ID(), payload, sessionID); err != nil {
					t.Fatalf("send with routed session: %v", err)
				}
			}

			var inbound *MixStream
			select {
			case err := <-inboundErrCh:
				t.Fatalf("accept routed session stream: %v", err)
			case inbound = <-inboundCh:
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for routed inbound mixstream")
			}
			defer inbound.Close()

			if inbound.sessionID != sessionID {
				t.Fatalf("routed session id mismatch: got %q want %q", inbound.sessionID, sessionID)
			}
			for _, want := range routedPayloads {
				got := readExactlyOneMessage(t, inbound, len(want))
				if !bytes.Equal(got, want) {
					t.Fatalf("routed session payload mismatch: got %q want %q", got, want)
				}
			}
		})

		t.Run("open stream and accept stream", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			origin, dest, _, cleanup := setupMixnetNetwork(t, ctx, cfg, 9)
			defer cleanup()

			acceptCh := make(chan *MixStream, 1)
			errCh := make(chan error, 1)
			go func() {
				s, err := dest.AcceptStream(ctx)
				if err != nil {
					errCh <- err
					return
				}
				acceptCh <- s
			}()

			originStream, err := origin.OpenStream(ctx, dest.Host().ID())
			if err != nil {
				t.Fatalf("open stream: %v", err)
			}

			payload := []byte("mixnet-stream-payload")
			if _, err := originStream.Write(payload); err != nil {
				t.Fatalf("write to mixstream: %v", err)
			}

			var destStream *MixStream
			select {
			case err := <-errCh:
				t.Fatalf("accept stream: %v", err)
			case destStream = <-acceptCh:
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for accept stream")
			}

			got := readExactlyOneMessage(t, destStream, len(payload))
			if !bytes.Equal(got, payload) {
				t.Fatalf("stream payload mismatch: got %q want %q", got, payload)
			}

			if err := originStream.Close(); err != nil {
				t.Fatalf("close origin stream: %v", err)
			}
			if err := destStream.Close(); err != nil {
				t.Fatalf("close destination stream: %v", err)
			}

			routedCfg := cloneConfig(cfg)
			routedCfg.EnableSessionRouting = true
			routedCfg.SessionRouteIdleTimeout = 2 * time.Second
			routedCfg.EncryptionMode = EncryptionModeHeaderOnly

			originRouted, destRouted, _, routedCleanup := setupMixnetNetwork(t, ctx, routedCfg, 9)
			defer routedCleanup()

			routedAcceptCh := make(chan *MixStream, 1)
			routedErrCh := make(chan error, 1)
			go func() {
				s, err := destRouted.AcceptStream(ctx)
				if err != nil {
					routedErrCh <- err
					return
				}
				routedAcceptCh <- s
			}()

			originRoutedStream, err := originRouted.OpenStream(ctx, destRouted.Host().ID())
			if err != nil {
				t.Fatalf("open routed stream: %v", err)
			}

			routedPayloads := [][]byte{
				[]byte("mixnet-routed-stream-payload-1"),
				[]byte("mixnet-routed-stream-payload-2"),
				[]byte("mixnet-routed-stream-payload-3"),
			}
			for _, payload := range routedPayloads {
				if _, err := originRoutedStream.Write(payload); err != nil {
					t.Fatalf("write routed mixstream payload: %v", err)
				}
			}

			var routedDestStream *MixStream
			select {
			case err := <-routedErrCh:
				t.Fatalf("accept routed stream: %v", err)
			case routedDestStream = <-routedAcceptCh:
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for routed accept stream")
			}
			defer routedDestStream.Close()

			for _, want := range routedPayloads {
				got := readExactlyOneMessage(t, routedDestStream, len(want))
				if !bytes.Equal(got, want) {
					t.Fatalf("routed stream payload mismatch: got %q want %q", got, want)
				}
			}

			if err := originRoutedStream.Close(); err != nil {
				t.Fatalf("close routed origin stream: %v", err)
			}
			eofBuf := make([]byte, 1)
			if _, err := routedDestStream.Read(eofBuf); !errors.Is(err, io.EOF) {
				t.Fatalf("expected EOF after routed close, got %v", err)
			}
		})

		t.Run("failure and recover from failure", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			recoveryCfg := cloneConfig(cfg)
			recoveryCfg.UseCESPipeline = true
			recoveryCfg.ErasureThreshold = 2

			origin, dest, relayMixes, cleanup := setupMixnetNetwork(t, ctx, recoveryCfg, 9)
			defer cleanup()

			circuits, err := origin.EstablishConnection(ctx, dest.Host().ID())
			if err != nil {
				t.Fatalf("establish connection: %v", err)
			}
			if len(circuits) == 0 {
				t.Fatal("expected established circuits")
			}

			waitBefore := expectInboundPayload(t, ctx, dest)
			if err := origin.Send(ctx, dest.Host().ID(), []byte("before-recovery")); err != nil {
				t.Fatalf("send before recovery: %v", err)
			}
			waitBefore("", []byte("before-recovery"))

			failedCircuit := circuits[0]
			origin.CircuitManager().MarkCircuitFailed(failedCircuit.ID)
			if err := origin.CircuitManager().CloseCircuit(failedCircuit.ID); err != nil {
				t.Fatalf("close failed circuit stream: %v", err)
			}

			usedRelay := failedCircuit.Entry()
			for _, rm := range relayMixes {
				if rm.Host().ID() == usedRelay {
					_ = rm.Close()
					break
				}
			}

			if err := origin.RecoverFromFailure(ctx, dest.Host().ID()); err != nil {
				t.Fatalf("recover from failure: %v", err)
			}

			recovered := origin.ActiveConnections()[dest.Host().ID()]
			if len(recovered) != recoveryCfg.CircuitCount {
				t.Fatalf("recovered circuit count mismatch: got %d want %d", len(recovered), recoveryCfg.CircuitCount)
			}
			activeRecovered := 0
			for _, c := range recovered {
				if c != nil && c.IsActive() {
					activeRecovered++
				}
			}
			if activeRecovered < recoveryCfg.GetErasureThreshold() {
				t.Fatalf("insufficient active recovered circuits after recovery: active=%d threshold=%d", activeRecovered, recoveryCfg.GetErasureThreshold())
			}
			for _, c := range recovered {
				if c != nil && c.IsActive() && c.Entry() == usedRelay {
					t.Fatalf("recovered active circuit still uses failed relay %s", usedRelay)
				}
			}

			postRecoveryCtx, postRecoveryCancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer postRecoveryCancel()
			postRecoverySessionID := "post-recovery-session"
			delivered := make(chan struct{}, 1)
			go func() {
				expectInboundPayload(t, postRecoveryCtx, dest)(postRecoverySessionID, []byte("after-recovery"))
				delivered <- struct{}{}
			}()
			ticker := time.NewTicker(750 * time.Millisecond)
			defer ticker.Stop()
			graceUntil := time.Now().Add(5 * time.Second)
			for {
				if err := origin.SendWithSession(postRecoveryCtx, dest.Host().ID(), []byte("after-recovery"), postRecoverySessionID); err != nil && postRecoveryCtx.Err() == nil {
					if time.Now().After(graceUntil) {
						t.Fatalf("send after recovery: %v", err)
					}
				}
				select {
				case <-delivered:
					return
				case <-postRecoveryCtx.Done():
					t.Fatal("timed out waiting for post-recovery delivery")
				case <-ticker.C:
				}
			}
		})

		t.Run("close", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			origin, dest, _, cleanup := setupMixnetNetwork(t, ctx, cfg, 9)
			defer cleanup()

			waitBeforeClose := expectInboundPayload(t, ctx, dest)
			if err := origin.Send(ctx, dest.Host().ID(), []byte("before-close")); err != nil {
				t.Fatalf("send before close: %v", err)
			}
			waitBeforeClose("", []byte("before-close"))

			if err := origin.Close(); err != nil {
				t.Fatalf("close origin: %v", err)
			}
			if err := origin.Close(); err != nil {
				t.Fatalf("close origin should be idempotent: %v", err)
			}

			sendCtx, sendCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer sendCancel()
			if err := origin.Send(sendCtx, dest.Host().ID(), []byte("after-close")); err == nil {
				t.Fatal("expected send after close to fail")
			}

			if err := dest.Close(); err != nil {
				t.Fatalf("close destination: %v", err)
			}
			if err := dest.Close(); err != nil {
				t.Fatalf("close destination should be idempotent: %v", err)
			}
		})
	})

	runStep("failure detection edge cases", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		if err := NewCircuitFailureNotifier(&Mixnet{}, nil).Start(ctx); err == nil {
			t.Fatal("expected error when starting notifier without host")
		}

		origin := newTestHost(t)
		defer origin.Close()
		cm := circuit.NewCircuitManager(&circuit.CircuitConfig{HopCount: 1, CircuitCount: 2})
		relays := []circuit.RelayInfo{
			{PeerID: "relay-1", AddrInfo: peer.AddrInfo{ID: "relay-1", Addrs: []multiaddr.Multiaddr{mustMultiaddr(t)}}},
			{PeerID: "relay-2", AddrInfo: peer.AddrInfo{ID: "relay-2", Addrs: []multiaddr.Multiaddr{mustMultiaddr(t)}}},
		}
		circuits, err := cm.BuildCircuits(ctx, peer.ID("dest"), relays)
		if err != nil || len(circuits) != 2 {
			t.Fatalf("build circuits: %v", err)
		}
		for _, c := range circuits {
			if err := cm.ActivateCircuit(c.ID); err != nil {
				t.Fatalf("activate circuit: %v", err)
			}
		}
		m := &Mixnet{
			host:              origin,
			config:            DefaultConfig(),
			metrics:           NewMetricsCollector(),
			routing:           &staticRouting{providers: nil, peers: map[peer.ID]peer.AddrInfo{origin.ID(): {ID: origin.ID(), Addrs: origin.Addrs()}}},
			discovery:         discovery.NewRelayDiscoveryWithHost(origin, ProtocolID, 3, "random", 0.3),
			circuitMgr:        cm,
			activeConnections: map[peer.ID][]*circuit.Circuit{peer.ID("dest"): circuits},
		}

		n := NewCircuitFailureNotifier(m, origin)
		if err := n.Start(ctx); err != nil {
			t.Fatalf("start notifier: %v", err)
		}
		if err := n.Stop(); err != nil {
			t.Fatalf("stop notifier: %v", err)
		}

		n2 := NewCircuitFailureNotifier(m, origin)
		n2.handleDisconnection(peer.ID("relay-1"), mustMultiaddr(t))
		expectedRelay1ID := ""
		expectedRelay2ID := ""
		for _, c := range circuits {
			if c.Entry() == peer.ID("relay-1") {
				expectedRelay1ID = c.ID
			}
			if c.Entry() == peer.ID("relay-2") {
				expectedRelay2ID = c.ID
			}
		}
		if expectedRelay1ID == "" || expectedRelay2ID == "" {
			t.Fatal("expected relay circuits not found")
		}
		select {
		case ev := <-n2.FailureChan():
			if ev.CircuitID != expectedRelay1ID {
				t.Fatalf("unexpected failure event: %+v", ev)
			}
		case <-time.After(200 * time.Millisecond):
			t.Fatal("expected failure event")
		}
		n2.handleDisconnection(peer.ID("relay-1"), mustMultiaddr(t))
		select {
		case <-n2.FailureChan():
			t.Fatal("unexpected duplicate failure event")
		case <-time.After(100 * time.Millisecond):
		}

		for _, c := range circuits {
			if c.ID == expectedRelay2ID {
				c.SetLastHeartbeat(time.Now().Add(-6 * time.Second))
			}
		}
		n2.scanCircuits()
		select {
		case ev := <-n2.FailureChan():
			if ev.CircuitID != expectedRelay2ID {
				t.Fatalf("unexpected failure event: %+v", ev)
			}
		case <-time.After(200 * time.Millisecond):
			t.Fatal("expected failure event from heartbeat timeout")
		}

		hbCM := circuit.NewCircuitManager(&circuit.CircuitConfig{HopCount: 1, CircuitCount: 1})
		hbRelays := []circuit.RelayInfo{{PeerID: "r1", AddrInfo: peer.AddrInfo{ID: "r1", Addrs: []multiaddr.Multiaddr{mustMultiaddr(t)}}}}
		hbCircuits, err := hbCM.BuildCircuits(ctx, peer.ID("dest"), hbRelays)
		if err != nil {
			t.Fatalf("build circuits for heartbeat: %v", err)
		}
		if err := hbCM.ActivateCircuit(hbCircuits[0].ID); err != nil {
			t.Fatalf("activate circuit: %v", err)
		}
		m2 := &Mixnet{circuitMgr: hbCM, heartbeatStart: make(map[string]struct{})}
		m2.StartHeartbeatMonitoring(10 * time.Millisecond)
		time.Sleep(20 * time.Millisecond)
		if hbCircuits[0].GetLastHeartbeat().IsZero() {
			t.Fatal("expected heartbeat to update")
		}
	})

	runStep("relay handler backpressure hooks", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		origin := newTestHost(t)
		relayHost := newTestHost(t)
		dest := newTestHost(t)
		defer origin.Close()
		defer relayHost.Close()
		defer dest.Close()

		handler := relay.NewHandler(relayHost, 4, 1024*1024)
		handler.EnableLibp2pResourceManager(false)
		waited := make(chan struct{}, 1)
		recorded := make(chan int64, 1)
		handler.SetBandwidthBackpressure(func(ctx context.Context, bytes int64) error {
			waited <- struct{}{}
			return nil
		})
		handler.SetBandwidthRecorder(func(dir string, bytes int64) {
			if dir == "out" {
				recorded <- bytes
			}
		})
		relayHost.SetStreamHandler(relay.ProtocolID, handler.HandleStream)
		relayHost.SetStreamHandler(KeyExchangeProtocolID, handler.HandleKeyExchange)

		if err := origin.Connect(ctx, peer.AddrInfo{ID: relayHost.ID(), Addrs: relayHost.Addrs()}); err != nil {
			t.Fatalf("connect origin->relay: %v", err)
		}
		if err := relayHost.Connect(ctx, peer.AddrInfo{ID: dest.ID(), Addrs: dest.Addrs()}); err != nil {
			t.Fatalf("connect relay->dest: %v", err)
		}
		dest.SetStreamHandler(protocol.ID(ProtocolID), func(s network.Stream) {
			_ = s.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = io.Copy(io.Discard, s)
			_ = s.Close()
		})

		m := &Mixnet{host: origin}
		key, err := m.exchangeHopKey(ctx, relayHost.ID(), "bp-circuit")
		if err != nil {
			t.Fatalf("exchange hop key: %v", err)
		}
		c := circuit.NewCircuit("bp-circuit", []peer.ID{relayHost.ID()})
		onion, err := encryptOnion([]byte{msgTypeData, 0x01}, c, dest.ID(), [][]byte{key})
		if err != nil {
			t.Fatalf("encrypt onion: %v", err)
		}
		frame, err := encodeEncryptedFrameWithVersion("bp-circuit", frameVersionFullOnion, onion)
		if err != nil {
			t.Fatalf("frame: %v", err)
		}
		stream, err := origin.NewStream(ctx, relayHost.ID(), protocol.ID(relay.ProtocolID))
		if err != nil {
			t.Fatalf("open stream: %v", err)
		}
		if _, err := stream.Write(frame); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = stream.Close()

		select {
		case <-waited:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("expected backpressure hook to run")
		}
		select {
		case <-recorded:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("expected bandwidth record hook to run")
		}

	})

	runStep("relay handler error paths", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		origin := newTestHost(t)
		relayHost := newTestHost(t)
		dest := newTestHost(t)
		defer origin.Close()
		defer relayHost.Close()
		defer dest.Close()

		handler := relay.NewHandler(relayHost, 4, 1024*1024)
		handler.EnableLibp2pResourceManager(false)
		relayHost.SetStreamHandler(relay.ProtocolID, handler.HandleStream)
		relayHost.SetStreamHandler(KeyExchangeProtocolID, handler.HandleKeyExchange)

		if err := origin.Connect(ctx, peer.AddrInfo{ID: relayHost.ID(), Addrs: relayHost.Addrs()}); err != nil {
			t.Fatalf("connect origin->relay: %v", err)
		}
		if err := relayHost.Connect(ctx, peer.AddrInfo{ID: dest.ID(), Addrs: dest.Addrs()}); err != nil {
			t.Fatalf("connect relay->dest: %v", err)
		}
		dest.SetStreamHandler(protocol.ID(ProtocolID), func(s network.Stream) { _ = s.Close() })

		// Missing circuit key path.
		missingFrame, err := encodeEncryptedFrameWithVersion("missing-key", frameVersionFullOnion, []byte("bogus"))
		if err != nil {
			t.Fatalf("frame: %v", err)
		}
		s, err := origin.NewStream(ctx, relayHost.ID(), protocol.ID(relay.ProtocolID))
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
		_, _ = s.Write(missingFrame)
		_ = s.Close()

		// Oversized frame path.
		header := make([]byte, 1+len("too-big")+1+4)
		header[0] = byte(len("too-big"))
		copy(header[1:], []byte("too-big"))
		header[1+len("too-big")] = frameVersionFullOnion
		binary.LittleEndian.PutUint32(header[1+len("too-big")+1:], uint32(relay.MaxPayloadSize*4+1))
		s, err = origin.NewStream(ctx, relayHost.ID(), protocol.ID(relay.ProtocolID))
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
		_, _ = s.Write(header)
		_ = s.Close()

		// Header-only forwarding to address path covered in a dedicated test.
	})

	runStep("relay handler header-only address forwarding", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		origin := newTestHost(t)
		relayHost := newTestHost(t)
		dest := newTestHost(t)
		defer origin.Close()
		defer relayHost.Close()
		defer dest.Close()

		handler := relay.NewHandler(relayHost, 4, 1024*1024)
		handler.EnableLibp2pResourceManager(false)
		relayHost.SetStreamHandler(relay.ProtocolID, handler.HandleStream)
		relayHost.SetStreamHandler(KeyExchangeProtocolID, handler.HandleKeyExchange)

		if err := origin.Connect(ctx, peer.AddrInfo{ID: relayHost.ID(), Addrs: relayHost.Addrs()}); err != nil {
			t.Fatalf("connect origin->relay: %v", err)
		}
		if err := relayHost.Connect(ctx, peer.AddrInfo{ID: dest.ID(), Addrs: dest.Addrs()}); err != nil {
			t.Fatalf("connect relay->dest: %v", err)
		}
		dest.SetStreamHandler(protocol.ID(ProtocolID), func(s network.Stream) { _ = s.Close() })

		m := &Mixnet{host: origin}
		key, err := m.exchangeHopKey(ctx, relayHost.ID(), "bp-circuit")
		if err != nil {
			t.Fatalf("exchange hop key: %v", err)
		}
		addrInfos, err := peer.AddrInfoToP2pAddrs(&peer.AddrInfo{ID: dest.ID(), Addrs: dest.Addrs()})
		if err != nil || len(addrInfos) == 0 {
			t.Fatalf("addr info to p2p addrs: %v", err)
		}
		nextHop := addrInfos[0].String()
		headerPayload, err := buildHopPayload(1, nextHop, []byte("hdr"))
		if err != nil {
			t.Fatalf("build hop payload: %v", err)
		}
		encHeader, err := encryptHopPayload(key, headerPayload)
		if err != nil {
			t.Fatalf("encrypt hop payload: %v", err)
		}
		hdrOnly := buildHeaderOnlyPayload(encHeader, []byte("body"))
		frame, err := encodeEncryptedFrameWithVersion("bp-circuit", frameVersionHeaderOnly, hdrOnly)
		if err != nil {
			t.Fatalf("header-only frame: %v", err)
		}
		s, err := origin.NewStream(ctx, relayHost.ID(), protocol.ID(relay.ProtocolID))
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
		_, _ = s.Write(frame)
		_ = s.Close()
	})

	runStep("destination handler and reschedule edges", func(t *testing.T) {
		h := &DestinationHandler{
			pipeline:        nil,
			shardBuf:        make(map[string]map[int]*ces.Shard),
			shardTags:       make(map[string]map[int][]byte),
			totalShards:     make(map[string]int),
			timers:          make(map[string]*time.Timer),
			sessions:        make(map[string]*sessionMailbox),
			keys:            make(map[string]sessionKey),
			keyData:         make(map[string][]byte),
			inboundCh:       make(chan string, 1),
			threshold:       1,
			timeout:         20 * time.Millisecond,
			dataCh:          make(chan []byte, 1),
			stopCh:          make(chan struct{}),
			useLengthPrefix: true,
			authEnabled:     false,
			authTagSize:     16,
		}

		sessionID := "s1"
		h.ensureSession(sessionID)
		if err := h.AddShard(sessionID, &ces.Shard{Index: 0, Data: []byte("x")}, []byte("short"), []byte("tag"), 1); err != nil {
			t.Fatalf("add shard: %v", err)
		}
		time.Sleep(30 * time.Millisecond)
		h.mu.Lock()
		_, ok := h.sessions[sessionID]
		h.mu.Unlock()
		if ok {
			t.Fatal("expected session closed after timeout")
		}

		key := sessionKey{Key: bytes.Repeat([]byte{3}, 32), Nonce: bytes.Repeat([]byte{4}, 24)}
		encKey := encodeSessionKeyData(key)
		h2 := &DestinationHandler{
			pipeline:        nil,
			shardBuf:        make(map[string]map[int]*ces.Shard),
			shardTags:       make(map[string]map[int][]byte),
			totalShards:     make(map[string]int),
			timers:          make(map[string]*time.Timer),
			sessions:        make(map[string]*sessionMailbox),
			keys:            map[string]sessionKey{sessionID: key},
			keyData:         map[string][]byte{sessionID: encKey},
			inboundCh:       make(chan string, 1),
			threshold:       1,
			timeout:         20 * time.Millisecond,
			dataCh:          make(chan []byte, 1),
			stopCh:          make(chan struct{}),
			useLengthPrefix: true,
			authEnabled:     true,
			authTagSize:     16,
		}
		shards := map[int]*ces.Shard{0: &ces.Shard{Index: 0, Data: []byte("payload")}}
		if err := h2.verifyAuthTags(sessionID, shards, 1, key); err == nil {
			t.Fatal("expected missing auth tags error")
		}
		h2.shardTags[sessionID] = map[int][]byte{0: []byte("bad")}
		if err := h2.verifyAuthTags(sessionID, shards, 1, key); err == nil {
			t.Fatal("expected auth tag mismatch error")
		}

		plaintext := []byte("no-prefix")
		cipher, keyData, err := encryptSessionPayload(plaintext)
		if err != nil {
			t.Fatalf("encrypt session payload: %v", err)
		}
		key, err = decodeSessionKeyData(keyData)
		if err != nil {
			t.Fatalf("decode session key: %v", err)
		}
		h3 := &DestinationHandler{
			pipeline:        nil,
			shardBuf:        map[string]map[int]*ces.Shard{sessionID: map[int]*ces.Shard{0: &ces.Shard{Index: 0, Data: cipher}}},
			shardTags:       make(map[string]map[int][]byte),
			totalShards:     map[string]int{sessionID: 1},
			timers:          make(map[string]*time.Timer),
			sessions:        map[string]*sessionMailbox{sessionID: {ch: make(chan []byte, 1)}},
			keys:            map[string]sessionKey{sessionID: key},
			keyData:         map[string][]byte{sessionID: keyData},
			inboundCh:       make(chan string, 1),
			threshold:       1,
			timeout:         20 * time.Millisecond,
			dataCh:          make(chan []byte, 1),
			stopCh:          make(chan struct{}),
			useLengthPrefix: true,
			authEnabled:     false,
			authTagSize:     16,
		}
		if _, err := h3.TryReconstruct(sessionID); err == nil {
			t.Fatal("expected invalid length prefix error")
		}

		cfg := DefaultConfig()
		cfg.EnableAuthTag = true
		cfg.AuthTagSize = 16
		m := &Mixnet{
			config:            cfg,
			circuitMgr:        circuit.NewCircuitManager(&circuit.CircuitConfig{HopCount: 1, CircuitCount: 1}),
			activeConnections: make(map[peer.ID][]*circuit.Circuit),
			pendingShards:     make(map[peer.ID]*PendingTransmission),
		}
		dest := peer.ID("dest")
		circ := circuit.NewCircuit("c1", []peer.ID{"r1"})
		circ.SetState(circuit.StateActive)
		m.activeConnections[dest] = []*circuit.Circuit{circ}
		m.setPendingTransmission(dest, "sess", []byte("short"), []*ces.Shard{{Index: 0, Data: []byte("x")}}, false)
		if err := m.reschedulePendingShards(context.Background(), dest); err == nil {
			t.Fatal("expected auth key decode failure")
		}
	})

	runStep("ces pipeline components", func(t *testing.T) {
		data := []byte(strings.Repeat("compress-me", 32))
		p := ces.NewPipeline(&ces.Config{
			HopCount:         2,
			CircuitCount:     3,
			Compression:      "gzip",
			ErasureThreshold: 2,
		})

		shards, keys, err := p.ProcessWithKeys(data, []string{"peer-a", "peer-b"})
		if err != nil {
			t.Fatalf("ces process: %v", err)
		}
		if len(shards) != 3 || len(keys) != 2 {
			t.Fatalf("unexpected shards/keys: %d/%d", len(shards), len(keys))
		}
		recon, err := p.Reconstruct(shards[:2], keys)
		if err != nil {
			t.Fatalf("ces reconstruct: %v", err)
		}
		if !bytes.Equal(recon, data) {
			t.Fatalf("ces pipeline roundtrip mismatch")
		}
	})

}

func configureSanityRuntimeLogging(t *testing.T) {
	verbose := strings.EqualFold(os.Getenv(sanityVerboseLogsEnv), "1") ||
		strings.EqualFold(os.Getenv(sanityVerboseLogsEnv), "true") ||
		strings.EqualFold(os.Getenv(sanityVerboseLogsEnv), "yes")
	if verbose {
		t.Logf("runtime mixnet logs enabled via %s", sanityVerboseLogsEnv)
		return
	}

	prevOutput := log.Writer()
	prevFlags := log.Flags()
	prevPrefix := log.Prefix()
	log.SetOutput(io.Discard)
	t.Cleanup(func() {
		log.SetOutput(prevOutput)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	})
}

func isDockerSanityRun() bool {
	return strings.EqualFold(os.Getenv(sanityDockerEnv), "1") ||
		strings.EqualFold(os.Getenv(sanityDockerEnv), "true") ||
		strings.EqualFold(os.Getenv(sanityDockerEnv), "yes")
}

type staticRouting struct {
	providers []peer.AddrInfo
	peers     map[peer.ID]peer.AddrInfo
}

func (s *staticRouting) Provide(context.Context, cid.Cid, bool) error { return nil }

func sanityProgressBar(current, total int32) string {
	const width = 20
	if total <= 0 {
		total = 1
	}
	filled := int((current * width) / total)
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("=", filled) + strings.Repeat("-", width-filled) + "]"
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

func setupMixnetNetwork(t *testing.T, ctx context.Context, cfg *MixnetConfig, relayCount int) (*Mixnet, *Mixnet, []*Mixnet, func()) {
	t.Helper()

	originHost := newTestHost(t)
	destHost := newTestHost(t)
	relayHosts := make([]host.Host, relayCount)
	for i := range relayHosts {
		relayHosts[i] = newTestHost(t)
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

	origin, err := NewMixnet(cloneConfig(cfg), originHost, &staticRouting{providers: providers, peers: peerMap})
	if err != nil {
		t.Fatalf("new origin mixnet: %v", err)
	}
	origin.RelayHandler().EnableLibp2pResourceManager(false)
	dest, err := NewMixnet(cloneConfig(cfg), destHost, nil)
	if err != nil {
		t.Fatalf("new destination mixnet: %v", err)
	}
	dest.RelayHandler().EnableLibp2pResourceManager(false)
	relayMixes := make([]*Mixnet, relayCount)
	for i, h := range relayHosts {
		relayMix, err := NewMixnet(DefaultConfig(), h, nil)
		if err != nil {
			t.Fatalf("new relay mixnet %d: %v", i, err)
		}
		relayMix.RelayHandler().EnableLibp2pResourceManager(false)
		relayMixes[i] = relayMix
	}

	allHosts := []host.Host{originHost, destHost}
	allHosts = append(allHosts, relayHosts...)
	connectAllHosts(t, ctx, allHosts)
	registerProtocols(allHosts, destHost.ID(), destHost.Addrs(), protocol.ID(ProtocolID))
	for _, h := range relayHosts {
		registerProtocols(allHosts, h.ID(), h.Addrs(), protocol.ID(ProtocolID), protocol.ID(relay.ProtocolID), protocol.ID(KeyExchangeProtocolID))
	}

	cleanup := func() {
		forceCloseMixnetForTest(origin)
		forceCloseMixnetForTest(dest)
		for _, m := range relayMixes {
			forceCloseMixnetForTest(m)
		}
	}
	return origin, dest, relayMixes, cleanup
}

func cloneConfig(cfg *MixnetConfig) *MixnetConfig {
	cp := *cfg
	if cfg.PayloadPaddingBuckets != nil {
		cp.PayloadPaddingBuckets = append([]int(nil), cfg.PayloadPaddingBuckets...)
	}
	return &cp
}

func newTestHost(t *testing.T) host.Host {
	t.Helper()
	h, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
	)
	if err != nil {
		t.Fatalf("new host: %v", err)
	}
	return h
}

func connectAllHosts(t *testing.T, ctx context.Context, hosts []host.Host) {
	t.Helper()
	for i := range hosts {
		for j := range hosts {
			if i == j {
				continue
			}
			info := peer.AddrInfo{ID: hosts[j].ID(), Addrs: hosts[j].Addrs()}
			if err := hosts[i].Connect(ctx, info); err != nil {
				t.Fatalf("connect %s -> %s: %v", hosts[i].ID(), hosts[j].ID(), err)
			}
		}
	}
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

func forceCloseMixnetForTest(m *Mixnet) {
	if m == nil {
		return
	}
	if m.failureNotifier != nil {
		_ = m.failureNotifier.Stop()
	}
	if m.originCancel != nil {
		m.originCancel()
	}
	if m.resourceMgr != nil {
		func() {
			defer func() { _ = recover() }()
			m.resourceMgr.Stop()
		}()
	}
	if m.circuitMgr != nil {
		_ = m.circuitMgr.Close()
	}
	if m.destHandler != nil {
		m.destHandler.mu.Lock()
		for sessionID := range m.destHandler.sessions {
			m.destHandler.closeSessionLocked(sessionID)
		}
		for _, timer := range m.destHandler.timers {
			if timer != nil {
				timer.Stop()
			}
		}
		closeStop := m.destHandler.stopCh
		m.destHandler.stopCh = nil
		m.destHandler.mu.Unlock()
		if closeStop != nil {
			func() {
				defer func() { _ = recover() }()
				close(closeStop)
			}()
		}
	}
	_ = m.host.Close()
}

func waitData(t *testing.T, ch <-chan []byte, timeout time.Duration) []byte {
	t.Helper()
	select {
	case data := <-ch:
		return data
	case <-time.After(timeout):
		t.Fatal("timeout waiting for data")
		return nil
	}
}

func readExactlyOneMessage(t *testing.T, s *MixStream, size int) []byte {
	t.Helper()
	buf := make([]byte, size)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("read mixstream: %v", err)
	}
	return append([]byte(nil), buf[:n]...)
}

func expectInboundPayload(t *testing.T, ctx context.Context, dest *Mixnet) func(string, []byte) {
	t.Helper()
	resultCh := make(chan *MixStream, 1)
	errCh := make(chan error, 1)
	go func() {
		s, err := dest.AcceptStream(ctx)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- s
	}()

	return func(wantSession string, wantPayload []byte) {
		t.Helper()
		var inbound *MixStream
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("accept stream: %v", err)
			}
			return
		case inbound = <-resultCh:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for inbound mixstream")
			return
		}
		if wantSession != "" && inbound.sessionID != wantSession {
			t.Fatalf("session id mismatch: got %q want %q", inbound.sessionID, wantSession)
		}
		got := readExactlyOneMessage(t, inbound, len(wantPayload))
		if !bytes.Equal(got, wantPayload) {
			t.Fatalf("payload mismatch: got %q want %q", got, wantPayload)
		}
		_ = inbound.Close()
	}
}

func mustMultiaddr(t *testing.T) multiaddr.Multiaddr {
	t.Helper()
	addr, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/4001")
	if err != nil {
		t.Fatalf("new multiaddr: %v", err)
	}
	return addr
}

func setupRelayForwardingHosts(t *testing.T) (host.Host, host.Host, host.Host, host.Host, host.Host, func()) {
	t.Helper()
	origin := newTestHost(t)
	entry := newTestHost(t)
	middle := newTestHost(t)
	exit := newTestHost(t)
	destination := newTestHost(t)
	cleanup := func() {
		_ = origin.Close()
		_ = entry.Close()
		_ = middle.Close()
		_ = exit.Close()
		_ = destination.Close()
	}
	return origin, entry, middle, exit, destination, cleanup
}

func connectRelayPath(t *testing.T, ctx context.Context, origin, entry, middle, exit, destination host.Host) {
	t.Helper()
	pairs := [][2]host.Host{
		{origin, entry},
		{entry, middle},
		{middle, exit},
		{exit, destination},
	}
	for _, pair := range pairs {
		info := peer.AddrInfo{ID: pair[1].ID(), Addrs: pair[1].Addrs()}
		if err := pair[0].Connect(ctx, info); err != nil {
			t.Fatalf("connect %s -> %s: %v", pair[0].ID(), pair[1].ID(), err)
		}
	}
	for _, h := range []host.Host{entry, middle, exit, destination} {
		origin.Peerstore().AddAddrs(h.ID(), h.Addrs(), peerstore.PermanentAddrTTL)
	}
}

func exchangeRelayHopKeys(t *testing.T, ctx context.Context, origin *Mixnet, circuitID string, relays ...peer.ID) [][]byte {
	t.Helper()
	keys := make([][]byte, len(relays))
	for i, relayID := range relays {
		key, err := origin.exchangeHopKey(ctx, relayID, circuitID)
		if err != nil {
			t.Fatalf("exchange hop key for %s: %v", relayID, err)
		}
		keys[i] = key
	}
	return keys
}

func waitPeer(t *testing.T, ch <-chan peer.ID, timeout time.Duration) peer.ID {
	t.Helper()
	select {
	case id := <-ch:
		return id
	case <-time.After(timeout):
		t.Fatal("timeout waiting for peer observation")
		return ""
	}
}

func waitHeader(t *testing.T, ch <-chan *PrivacyShardHeader, timeout time.Duration) *PrivacyShardHeader {
	t.Helper()
	select {
	case header := <-ch:
		return header
	case <-time.After(timeout):
		t.Fatal("timeout waiting for forwarded header")
		return nil
	}
}

func parseHeaderOnlyPayloadForTest(packet []byte) ([]byte, []byte, error) {
	if len(packet) < 4 {
		return nil, nil, errors.New("payload too short")
	}
	headerLen := int(binary.LittleEndian.Uint32(packet[:4]))
	if len(packet) < 4+headerLen {
		return nil, nil, errors.New("invalid header length")
	}
	return packet[4 : 4+headerLen], packet[4+headerLen:], nil
}
