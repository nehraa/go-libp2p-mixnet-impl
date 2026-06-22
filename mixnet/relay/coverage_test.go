package relay

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestRelayHandlerConfigurationHelpers(t *testing.T) {
	t.Parallel()

	handler := NewHandler(nil, 4, 1024)
	if handler == nil {
		t.Fatal("NewHandler() returned nil")
	}
	if handler.MaxCircuits() != 4 || handler.MaxBandwidth() != 1024 {
		t.Fatalf("NewHandler() limits = %d/%d", handler.MaxCircuits(), handler.MaxBandwidth())
	}
	if handler.sessionRouteTimeout() != 30*time.Second {
		t.Fatalf("default sessionRouteTimeout() = %s", handler.sessionRouteTimeout())
	}
	handler.SetSessionRouteIdleTimeout(0)
	if handler.sessionRouteTimeout() != 30*time.Second {
		t.Fatalf("SetSessionRouteIdleTimeout(0) = %s", handler.sessionRouteTimeout())
	}
	handler.SetObservationHandler(func(FrameObservation) {})
	handler.EnableLibp2pResourceManager(false)
	handler.SetResourceServiceName("relay-test")
	handler.SetBandwidthBackpressure(func(context.Context, int64) error { return nil })
	handler.SetBandwidthRecorder(func(string, int64) {})
	handler.SetUtilizationReporter(func(int) {})
	handler.SetMaxBandwidth(2048)
	if handler.MaxBandwidth() != 2048 {
		t.Fatalf("SetMaxBandwidth() = %d", handler.MaxBandwidth())
	}

	if got := frameVersionLabel(frameVersionSessionClose); got != "session-close" {
		t.Fatalf("frameVersionLabel() = %q", got)
	}
	if got := routeModeLabel(sessionRouteModeFullOnion); got != "full-onion" {
		t.Fatalf("routeModeLabel() = %q", got)
	}
	if got := peerString(peer.ID("")); got != "" {
		t.Fatalf("peerString() = %q", got)
	}
	if got := previewHex([]byte{0x01, 0x0a, 0xff}); got != "01 0a ff" {
		t.Fatalf("previewHex() = %q", got)
	}
	if got := previewText([]byte("hi\x00there")); got != "hi.there" {
		t.Fatalf("previewText() = %q", got)
	}
	if got := joinPreviewBytes([]byte("ab"), []byte("cd"), []byte("efgh")); !bytes.Equal(got, []byte("abcdefgh")) {
		t.Fatalf("joinPreviewBytes() = %q", got)
	}
	if got := peekReaderBytes(bufio.NewReader(bytes.NewReader([]byte("peek-me"))), 4); !bytes.Equal(got, []byte("peek")) {
		t.Fatalf("peekReaderBytes() = %q", got)
	}

	oldLimit := os.Getenv("MIXNET_MAX_ENCRYPTED_PAYLOAD")
	t.Cleanup(func() { _ = os.Setenv("MIXNET_MAX_ENCRYPTED_PAYLOAD", oldLimit) })
	_ = os.Setenv("MIXNET_MAX_ENCRYPTED_PAYLOAD", "1234")
	if got := MaxEncryptedPayloadSize(); got != 1234 {
		t.Fatalf("MaxEncryptedPayloadSize() = %d, want 1234", got)
	}
}

func TestRelayFrameEncodingAndDecodingHelpers(t *testing.T) {
	t.Parallel()

	var encoded bytes.Buffer
	if err := writeFrame(&encoded, []byte{0x12, 0x34}); err != nil {
		t.Fatalf("writeFrame() error = %v", err)
	}
	decoded, err := readFrame(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatalf("readFrame() error = %v", err)
	}
	if !bytes.Equal(decoded, []byte{0x12, 0x34}) {
		t.Fatalf("readFrame() = %x", decoded)
	}

	circuitID, key, err := decodeKeyExchangePayload(append([]byte{4}, []byte("circ")...))
	if err == nil || circuitID != "" || key != nil {
		t.Fatal("decodeKeyExchangePayload() should reject short payloads")
	}

	setup, err := encodeSessionSetupFramePayload("session", sessionRouteModeHeaderOnly, []byte("hdr"), []byte("key"))
	if err != nil {
		t.Fatalf("encodeSessionSetupFramePayload() error = %v", err)
	}
	baseID, mode, header, keyData, err := decodeSessionSetupFramePayload(setup)
	if err != nil {
		t.Fatalf("decodeSessionSetupFramePayload() error = %v", err)
	}
	if baseID != "session" || mode != sessionRouteModeHeaderOnly || !bytes.Equal(header, []byte("hdr")) || !bytes.Equal(keyData, []byte("key")) {
		t.Fatalf("decodeSessionSetupFramePayload() = %q %d %q %q", baseID, mode, header, keyData)
	}

	if got, err := decodeSessionPayloadBaseID([]byte{3, 'a', 'b', 'c'}, false); err != nil || got != "abc" {
		t.Fatalf("decodeSessionPayloadBaseID() = %q, %v", got, err)
	}
	if got, err := decodeSessionCloseFramePayload([]byte{3, 'a', 'b', 'c', 0, 0, 0, 0}); err != nil || got != "abc" {
		t.Fatalf("decodeSessionCloseFramePayload() = %q, %v", got, err)
	}
	if got, err := sessionFrameBaseID([]byte{3, 'a', 'b', 'c'}); err != nil || got != "abc" {
		t.Fatalf("sessionFrameBaseID() = %q, %v", got, err)
	}

}

func TestRelayBandwidthAndCryptoHelpers(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	waitCalls := 0
	recordCalls := 0
	waitBandwidth := func(context.Context, int64) error {
		waitCalls++
		return nil
	}
	recordBandwidth := func(string, int64) {
		recordCalls++
	}

	if _, err := writePayloadWithBandwidth(context.Background(), &out, []byte("hello"), 2, waitBandwidth, recordBandwidth); err != nil {
		t.Fatalf("writePayloadWithBandwidth() error = %v", err)
	}
	if out.String() != "hello" || waitCalls == 0 || recordCalls == 0 {
		t.Fatalf("writePayloadWithBandwidth() output=%q wait=%d record=%d", out.String(), waitCalls, recordCalls)
	}

	out.Reset()
	if _, err := writePayloadPartsWithBandwidth(context.Background(), &out, 2, waitBandwidth, recordBandwidth, []byte("ab"), []byte(""), []byte("cd")); err != nil {
		t.Fatalf("writePayloadPartsWithBandwidth() error = %v", err)
	}
	if out.String() != "abcd" {
		t.Fatalf("writePayloadPartsWithBandwidth() output = %q", out.String())
	}

	out.Reset()
	if _, err := writeHeaderOnlyFinalPayload(context.Background(), &out, []byte("hdr"), []byte("data"), waitBandwidth, recordBandwidth); err != nil {
		t.Fatalf("writeHeaderOnlyFinalPayload() error = %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("writeHeaderOnlyFinalPayload() produced no output")
	}

	out.Reset()
	if _, err := writeEncryptedFrameHeaderOnlyPayloadPrefix(context.Background(), &out, "cid", frameVersionHeaderOnly, 4, []byte("ctrl"), waitBandwidth, recordBandwidth); err != nil {
		t.Fatalf("writeEncryptedFrameHeaderOnlyPayloadPrefix() error = %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("writeEncryptedFrameHeaderOnlyPayloadPrefix() produced no output")
	}

	if _, err := writeHeaderOnlyFramePrefix(context.Background(), &out, "cid", []byte("hdr"), 4, waitBandwidth, recordBandwidth); err != nil {
		t.Fatalf("writeHeaderOnlyFramePrefix() error = %v", err)
	}

	src := bufio.NewReader(bytes.NewReader([]byte("payload")))
	if n, err := pipePayloadWithBandwidth(context.Background(), src, &out, 7, waitBandwidth, recordBandwidth); err != nil || n != 7 {
		t.Fatalf("pipePayloadWithBandwidth() = (%d, %v)", n, err)
	}

	key := bytes.Repeat([]byte{1}, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatalf("NewX() error = %v", err)
	}
	nonce := bytes.Repeat([]byte{2}, nonceSize)
	ciphertext := aead.Seal(nil, nonce, []byte("plaintext"), nil)
	frame := append(nonce, ciphertext...)
	if got, err := decryptHopPayloadWithAEAD(aead, frame, false); err != nil || string(got) != "plaintext" {
		t.Fatalf("decryptHopPayloadWithAEAD() = %q, %v", got, err)
	}
	if got, err := decryptHopPayloadPrepared(key, aead, frame, true); err != nil || string(got) != "plaintext" {
		t.Fatalf("decryptHopPayloadPrepared() = %q, %v", got, err)
	}
	if got, err := decryptHopPayload(key, frame, false); err != nil || string(got) != "plaintext" {
		t.Fatalf("decryptHopPayload() = %q, %v", got, err)
	}
	if _, err := decryptHopPayloadWithAEAD(nil, frame, false); err == nil {
		t.Fatal("decryptHopPayloadWithAEAD() expected missing aead error")
	}

	isFinal, nextHop, inner, err := parseHopPayload(append([]byte{1, 3, 0}, []byte("hop")...))
	if err != nil || !isFinal || nextHop != "hop" || len(inner) != 0 {
		t.Fatalf("parseHopPayload() = (%v, %q, %q, %v)", isFinal, nextHop, inner, err)
	}
}

func TestRelayRegistryHelpers(t *testing.T) {
	origin, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New(origin) error = %v", err)
	}
	t.Cleanup(func() { _ = origin.Close() })

	peerHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New(peer) error = %v", err)
	}
	t.Cleanup(func() { _ = peerHost.Close() })

	const protoID = protocol.ID("/mixnet/relay-test/1.0.0")
	peerHost.SetStreamHandler(protoID, func(s network.Stream) { _ = s.Close() })

	handler := NewHandler(origin, 2, 4096)
	handler.SetHost(origin)
	if handler.Host() != origin {
		t.Fatal("Host() did not return configured host")
	}

	origin.Peerstore().AddAddrs(peerHost.ID(), peerHost.Addrs(), time.Minute)
	stream, err := origin.NewStream(context.Background(), peerHost.ID(), protoID)
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}

	if err := handler.RegisterRelay("circuit-1", peerHost.ID(), stream); err != nil {
		t.Fatalf("RegisterRelay() error = %v", err)
	}
	if got := handler.ActiveCircuitCount(); got != 1 {
		t.Fatalf("ActiveCircuitCount() = %d, want 1", got)
	}
	info, ok := handler.GetRelayInfo("circuit-1")
	if !ok || info == nil || info.PeerID != peerHost.ID() {
		t.Fatalf("GetRelayInfo() = %#v, %v", info, ok)
	}
	handler.UnregisterRelay("circuit-1")
	if got := handler.ActiveCircuitCount(); got != 0 {
		t.Fatalf("ActiveCircuitCount() after unregister = %d, want 0", got)
	}

	handler.setCircuitKey("circuit-2", bytes.Repeat([]byte{3}, chacha20poly1305.KeySize))
	if got := handler.getCircuitKey("circuit-2"); len(got) != chacha20poly1305.KeySize {
		t.Fatalf("getCircuitKey() len = %d", len(got))
	}
	if got := handler.getCircuitAEAD("circuit-2"); got == nil {
		t.Fatal("getCircuitAEAD() returned nil")
	}
}
