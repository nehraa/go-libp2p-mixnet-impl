// Package relay implements the zero-knowledge packet forwarding for mixnet relay nodes.
package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	noiseutil "github.com/libp2p/go-libp2p/mixnet/internal/noiseutil"
)

const (
	// ProtocolID is the libp2p protocol identifier for mixnet relaying.
	ProtocolID = "/lib-mix/relay/1.0.0"

	// MaxPayloadSize is the maximum allowed size for a single packet.
	MaxPayloadSize = 64 * 1024 // 64KB

	// ReadTimeout is the duration after which an inactive relay stream is closed.
	ReadTimeout = 30 * time.Second
)

// RelayInfo contains runtime statistics and state for an active relay circuit on this node.
type RelayInfo struct {
	// PeerID is the identifier of the peer that opened the relay stream.
	PeerID       peer.ID
	// Stream is the network stream being relayed.
	Stream       network.Stream
	// CircuitID is the internal identifier for this relay circuit.
	CircuitID    string
	// BytesForwarded is the total number of bytes processed by this relay.
	BytesForwarded int64
	// LastActivity is the timestamp of the last data movement.
	LastActivity time.Time
	mu           sync.Mutex
}

// Handler manages all active relay streams and enforces resource limits.
type Handler struct {
	host         host.Host
	maxBandwidth int64
	maxCircuits  int
	activeRelays map[string]*RelayInfo // circuitID -> relay info
	protocolID   string
	mu           sync.RWMutex
}

// NewHandler creates a new relay Handler with the specified limits.
func NewHandler(host host.Host, maxCircuits int, maxBandwidth int64) *Handler {
	return &Handler{
		host:         host,
		maxBandwidth: maxBandwidth,
		maxCircuits:  maxCircuits,
		activeRelays: make(map[string]*RelayInfo),
		protocolID:   ProtocolID,
	}
}

// HandleStream handles an incoming relay stream.
// Performs a Noise NN handshake (relay is responder), then reads a
// length-prefixed encrypted routing packet, decrypts it, and forwards
// the payload to the next hop (Req 7.4, 14.3, 16.2, 20.4).
func (h *Handler) HandleStream(ctx context.Context, stream network.Stream) error {
	defer stream.Close()

	// Enforce circuit limit (Req 20.1, 20.3).
	h.mu.Lock()
	if h.maxCircuits > 0 && len(h.activeRelays) >= h.maxCircuits {
		h.mu.Unlock()
		return
	}
	circuitID := fmt.Sprintf("relay-%d", len(h.activeRelays))
	h.activeRelays[circuitID] = &RelayInfo{
		PeerID:       stream.Conn().RemotePeer(),
		Stream:       stream,
		CircuitID:    circuitID,
		LastActivity: time.Now(),
	}
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.activeRelays, circuitID)
		h.mu.Unlock()
	}()

	// Set a read deadline so the relay cannot be held open indefinitely (Req 6.3).
	stream.SetDeadline(time.Now().Add(ReadTimeout))

	// Noise NN handshake; relay is always the responder (Req 16.2).
	_, recvCS, err := noiseutil.PerformHandshake(stream, false)
	if err != nil {
		return fmt.Errorf("noise handshake failed: %w", err)
	}

	// Read length-prefixed encrypted routing packet.
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return fmt.Errorf("failed to read routing packet length: %w", err)
	}
	encLen := binary.BigEndian.Uint16(lenBuf)
	encBuf := make([]byte, encLen)
	if _, err := io.ReadFull(stream, encBuf); err != nil {
		return fmt.Errorf("failed to read routing packet: %w", err)
	}

	// Decrypt routing header (Req 14.3).
	decrypted, err := recvCS.Decrypt(nil, nil, encBuf)
	if err != nil {
		return fmt.Errorf("failed to decrypt routing header: %w", err)
	}

	// Parse: [dest_len:2][dest_bytes][payload]
	if len(decrypted) < 2 {
		return fmt.Errorf("decrypted routing packet too short")
	}
	destLen := binary.LittleEndian.Uint16(decrypted[0:2])
	if int(destLen) > len(decrypted)-2 {
		return fmt.Errorf("invalid destination length: %d", destLen)
	}
	if destLen == 0 {
		// Zero-length destination: heartbeat / keepalive probe; no forwarding needed.
		return nil
	}
	nextHop := string(decrypted[2 : 2+destLen])
	payload := decrypted[2+destLen:]
	if len(payload) == 0 {
		return fmt.Errorf("empty payload for next hop %s", nextHop)
	}

	// Parse the next hop as a peer ID; fall back to multiaddr parsing.
	nextPeer, err := peer.Decode(nextHop)
	if err != nil {
		return h.forwardByAddress(ctx, nextHop, payload)
	}

	return h.forwardToPeerStream(ctx, nextPeer, payload)
}

// forwardToPeerStream opens a stream to nextPeer, performs a Noise NN handshake
// (relay is the initiator), then sends the payload as one length-framed
// Noise-encrypted message (Req 7.4, 14.3, 16.2, 20.4).
//
// The recipient's HandleStream or handleIncomingStream will:
//  1. Complete the Noise NN responder handshake.
//  2. Read the length-prefixed encrypted message.
//  3. Noise-decrypt to obtain the inner routing packet or shard data.
func (h *Handler) forwardToPeerStream(ctx context.Context, nextPeer peer.ID, payload []byte) error {
	h.mu.RLock()
	host := h.host
	maxBandwidth := h.maxBandwidth
	h.mu.RUnlock()

	if host == nil {
		return fmt.Errorf("no host configured")
	}

	// Check if we're already connected
	if host.Network().Connectedness(nextPeer) != network.Connected {
		connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := host.Connect(connectCtx, peer.AddrInfo{ID: nextPeer}); err != nil {
			return fmt.Errorf("failed to connect to next hop: %w", err)
		}
	}

	dst, err := host.NewStream(ctx, nextPeer, ProtocolID)
	if err != nil {
		return fmt.Errorf("failed to open stream to %s: %w", nextPeer, err)
	}
	defer dst.Close()

	// Noise NN handshake: relay is initiator for forwarding streams (Req 16.2).
	sendCS, _, err := noiseutil.PerformHandshake(dst, true)
	if err != nil {
		return fmt.Errorf("noise handshake with next hop failed: %w", err)
	}

	// Apply bandwidth limit if configured (Req 20.2, 20.4).
	// Write through a rate-limited wrapper if needed.
	out, err := sendCS.Encrypt(nil, nil, payload)
	if err != nil {
		return fmt.Errorf("noise encrypt for forwarding failed: %w", err)
	}

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(out)))
	data := append(lenBuf, out...)

	var writer io.Writer = dst
	if maxBandwidth > 0 {
		writer = &rateLimitedWriter{w: dst, bytesPerSec: maxBandwidth}
	}
	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("failed to forward payload: %w", err)
	}
	return nil
}

// forwardByAddress parses addr as a multiaddr peer info string, performs a
// Noise NN handshake (relay initiator), then sends payload as one framed message.
func (h *Handler) forwardByAddress(ctx context.Context, addr string, payload []byte) error {
	h.mu.RLock()
	host := h.host
	h.mu.RUnlock()

	if host == nil {
		return fmt.Errorf("no host configured")
	}

	addrInfo, err := peer.AddrInfoFromString(addr)
	if err != nil {
		return fmt.Errorf("failed to parse address: %w", err)
	}

	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := host.Connect(connectCtx, *addrInfo); err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}

	dst, err := host.NewStream(ctx, addrInfo.ID, ProtocolID)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer dst.Close()

	// Noise NN handshake: relay is initiator (Req 16.2).
	sendCS, _, err := noiseutil.PerformHandshake(dst, true)
	if err != nil {
		return fmt.Errorf("noise handshake with next hop failed: %w", err)
	}

	out, err := sendCS.Encrypt(nil, nil, payload)
	if err != nil {
		return fmt.Errorf("noise encrypt for forwarding failed: %w", err)
	}
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(out)))
	if _, err := dst.Write(append(lenBuf, out...)); err != nil {
		return fmt.Errorf("failed to forward payload: %w", err)
	}
	return nil
}

type rateLimitedWriter struct {
	w           io.Writer
	bytesPerSec int64
}

func (r *rateLimitedWriter) Write(p []byte) (n int, err error) {
	if r.bytesPerSec > 0 && int64(len(p)) > 0 {
		delay := time.Duration(int64(time.Second) * int64(len(p)) / r.bytesPerSec)
		if delay > 0 {
			time.Sleep(delay)
		}
	}
	return r.w.Write(p)
}

// MaxCircuits returns the maximum number of concurrent circuits allowed by the handler.
func (h *Handler) MaxCircuits() int {
	return h.maxCircuits
}

// MaxBandwidth returns the maximum bandwidth allowed per circuit.
func (h *Handler) MaxBandwidth() int64 {
	return h.maxBandwidth
}

// ActiveCircuitCount returns the current number of active relay circuits.
func (h *Handler) ActiveCircuitCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.activeRelays)
}

// RegisterRelay manually registers an active relay circuit (primarily for testing).
func (h *Handler) RegisterRelay(circuitID string, peerID peer.ID, stream network.Stream) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.activeRelays) >= h.maxCircuits {
		return fmt.Errorf("max circuits reached")
	}

	h.activeRelays[circuitID] = &RelayInfo{
		PeerID:       peerID,
		Stream:       stream,
		CircuitID:    circuitID,
		LastActivity: time.Now(),
	}

	return nil
}

// UnregisterRelay removes a relay circuit and closes its stream.
func (h *Handler) UnregisterRelay(circuitID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if relay, ok := h.activeRelays[circuitID]; ok {
		relay.Stream.Close()
		delete(h.activeRelays, circuitID)
	}
}

// GetRelayInfo retrieves information about an active relay circuit.
func (h *Handler) GetRelayInfo(circuitID string) (*RelayInfo, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	relay, ok := h.activeRelays[circuitID]
	return relay, ok
}

// Host returns the libp2p host used by the handler.
func (h *Handler) Host() host.Host {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.host
}

// SetHost sets the libp2p host for the handler.
func (h *Handler) SetHost(host host.Host) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.host = host
}
