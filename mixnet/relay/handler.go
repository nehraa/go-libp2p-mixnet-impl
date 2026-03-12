// Package relay implements the zero-knowledge packet forwarding for mixnet relay nodes.
package relay

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// ProtocolID is the libp2p protocol identifier for mixnet relaying.
	ProtocolID = "/lib-mix/relay/1.0.0"
	// FinalProtocolID is the protocol identifier used when forwarding to the destination.
	FinalProtocolID = "/lib-mix/1.0.0"

	// MaxPayloadSize is the maximum allowed size for a single packet.
	MaxPayloadSize = 64 * 1024 // 64KB

	// ReadTimeout is the duration after which an inactive relay stream is closed.
	ReadTimeout = 30 * time.Second

	// nonceSize is the nonce size for ChaCha20-Poly1305 (12 bytes for standard, 24 for X)
	nonceSize      = 24 // XChaCha20-Poly1305
	writeChunkSize = 256 * 1024

	frameVersionFullOnion              byte = 0x01
	frameVersionHeaderOnly             byte = 0x02
	frameVersionSessionSetupHeaderOnly byte = 0x03
	frameVersionSessionDataHeaderOnly  byte = 0x04
	frameVersionSessionSetupFullOnion  byte = 0x05
	frameVersionSessionDataFullOnion   byte = 0x06
	frameVersionSessionClose           byte = 0x07
)

var relayChunkPool = sync.Pool{
	New: func() any {
		buf := make([]byte, writeChunkSize)
		return &buf
	},
}

const (
	msgTypeData                byte = 0x00
	msgTypeCloseReq            byte = 0x01
	msgTypeCloseAck            byte = 0x02
	msgTypeSessionSetup        byte = 0x03
	msgTypeSessionData         byte = 0x04
	msgTypeSessionClose        byte = 0x05
	sessionDataFlagSequenced   byte = 0x01
	sessionRouteModeHeaderOnly byte = 0x01
	sessionRouteModeFullOnion  byte = 0x02
)

type sessionRouteEntry struct {
	baseSessionID string
	nextHop       string
	nextPeer      peer.ID
	isFinal       bool
	mode          byte
	finalTemplate []byte
	dst           network.Stream
	lastActivity  time.Time
}

func MaxEncryptedPayloadSize() int {
	const defaultMultiplier = 4

	if raw := os.Getenv("MIXNET_MAX_ENCRYPTED_PAYLOAD"); raw != "" {
		if size, err := strconv.Atoi(raw); err == nil && size > 0 {
			return size
		}
	}

	return MaxPayloadSize * defaultMultiplier
}

// RelayInfo contains runtime statistics and state for an active relay circuit on this node.
type RelayInfo struct {
	// PeerID is the identifier of the peer that opened the relay stream.
	PeerID peer.ID
	// Stream is the network stream being relayed.
	Stream network.Stream
	// CircuitID is the internal identifier for this relay circuit.
	CircuitID string
	// BytesForwarded is the total number of bytes processed by this relay.
	BytesForwarded int64
	// LastActivity is the timestamp of the last data movement.
	LastActivity time.Time
	mu           sync.Mutex
}

// Handler manages all active relay streams and enforces resource limits.
type Handler struct {
	host                    host.Host
	maxBandwidth            int64
	maxCircuits             int
	useRCMgr                bool
	serviceName             string
	sessionRouteIdleTimeout time.Duration
	activeRelays            map[string]*RelayInfo // circuitID -> relay info
	protocolID              string
	mu                      sync.RWMutex
	muKeys                  sync.RWMutex
	circuitKeys             map[string][]byte // circuitID -> hop key
	waitBandwidth           func(context.Context, int64) error
	recordBandwidth         func(string, int64)
	reportUtilization       func(int)
}

// NewHandler creates a new relay Handler with the specified limits.
func NewHandler(host host.Host, maxCircuits int, maxBandwidth int64) *Handler {
	return &Handler{
		host:                    host,
		maxBandwidth:            maxBandwidth,
		maxCircuits:             maxCircuits,
		useRCMgr:                true,
		serviceName:             "mixnet-relay",
		sessionRouteIdleTimeout: 30 * time.Second,
		activeRelays:            make(map[string]*RelayInfo),
		protocolID:              ProtocolID,
		circuitKeys:             make(map[string][]byte),
	}
}

// SetSessionRouteIdleTimeout configures the idle timeout for routed session state.
func (h *Handler) SetSessionRouteIdleTimeout(timeout time.Duration) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	h.mu.Lock()
	h.sessionRouteIdleTimeout = timeout
	h.mu.Unlock()
}

// HandleStream implements the libp2p stream handler for incoming relay requests.
// It performs zero-knowledge forwarding of the encrypted payload to the next hop.
// AC 7.1: Decrypt outermost layer
// AC 7.2: Extract next-hop from decrypted header
func (h *Handler) HandleStream(stream network.Stream) {
	baseCtx := context.Background()
	defer stream.Close()

	// Enforce compatibility circuit limits only when rcmgr integration is disabled.
	h.mu.Lock()
	if !h.useRCMgr && h.maxCircuits > 0 && len(h.activeRelays) >= h.maxCircuits {
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
	if h.reportUtilization != nil {
		h.reportUtilization(len(h.activeRelays))
	}
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.activeRelays, circuitID)
		if h.reportUtilization != nil {
			h.reportUtilization(len(h.activeRelays))
		}
		h.mu.Unlock()
	}()

	reader := bufio.NewReader(stream)
	var dst network.Stream
	var dstPeer peer.ID
	var dstIsFinal bool
	sessionRoutes := make(map[string]*sessionRouteEntry)

	defer func() {
		if dst != nil {
			_ = dst.Close()
		}
		for _, route := range sessionRoutes {
			if route != nil && route.dst != nil {
				_ = route.dst.Close()
			}
		}
	}()

	for {
		// Set a read deadline so the relay cannot be held open indefinitely (Req 6.3).
		deadline := time.Now().Add(ReadTimeout)
		_ = stream.SetDeadline(deadline)

		circuitID, frameVersion, payloadLen, err := readEncryptedFrameHeader(reader)
		if err != nil {
			return
		}
		frameCtx, cancel := context.WithDeadline(baseCtx, deadline)
		err = func(ctx context.Context) error {
			defer cancel()

			// Header-only frames are handled in a dedicated streaming path so the
			// relay only decrypts the onion header and forwards the remaining
			// payload bytes without rebuilding a full [header][payload] buffer.
			if frameVersion == frameVersionHeaderOnly {
				key := h.getCircuitKey(circuitID)
				if len(key) == 0 {
					return fmt.Errorf("missing circuit key")
				}
				return h.handleHeaderOnlyFrameStream(ctx, reader, circuitID, payloadLen, key, &dst, &dstPeer, &dstIsFinal, stream)
			}
			if frameVersion == frameVersionSessionSetupHeaderOnly || frameVersion == frameVersionSessionSetupFullOnion {
				key := h.getCircuitKey(circuitID)
				if len(key) == 0 {
					return fmt.Errorf("missing circuit key")
				}
				return h.handleSessionSetupFrame(ctx, reader, circuitID, frameVersion, payloadLen, key, sessionRoutes)
			}
			if frameVersion == frameVersionSessionDataHeaderOnly {
				return h.handleSessionDataFrameStream(ctx, reader, circuitID, frameVersion, payloadLen, sessionRoutes)
			}
			if frameVersion == frameVersionSessionDataFullOnion {
				return h.handleSessionDataFrame(ctx, reader, circuitID, frameVersion, payloadLen, sessionRoutes)
			}
			if frameVersion == frameVersionSessionClose {
				return h.handleSessionCloseFrame(ctx, reader, circuitID, payloadLen, sessionRoutes)
			}

			encPayload, releaseMem, err := readEncryptedFramePayload(reader, stream.Scope(), payloadLen)
			if err != nil {
				return err
			}
			if releaseMem != nil {
				defer releaseMem()
			}
			if h.recordBandwidth != nil {
				h.recordBandwidth("in", int64(len(encPayload)))
			}

			var (
				isFinal     bool
				nextHop     string
				innerHeader []byte
			)

			switch frameVersion {
			case frameVersionFullOnion:
				key := h.getCircuitKey(circuitID)
				if len(key) == 0 {
					return fmt.Errorf("missing circuit key")
				}
				plaintext, err := decryptHopPayload(key, encPayload)
				if err != nil {
					return err
				}
				parsedFinal, parsedHop, innerPayload, err := parseHopPayload(plaintext)
				if err != nil {
					return err
				}
				isFinal = parsedFinal
				nextHop = parsedHop
				innerHeader = innerPayload
			default:
				return fmt.Errorf("unknown frame version: %d", frameVersion)
			}

			// Determine protocol based on whether this is the final hop.
			nextProto := ProtocolID
			if isFinal {
				nextProto = FinalProtocolID
			}

			// Parse the next hop as a peer ID; fall back to multiaddr parsing.
			nextPeer, err := peer.Decode(nextHop)
			if err != nil {
				if dst != nil {
					_ = dst.Close()
					dst = nil
				}
				return h.forwardByAddressEncrypted(ctx, nextHop, circuitID, frameVersion, innerHeader, nextProto)
			}

			// Keep per-circuit streams open; rotate only when route target/mode changes.
			if dst == nil || dstPeer != nextPeer || dstIsFinal != isFinal {
				if dst != nil {
					_ = dst.Close()
				}
				s, err := h.openStream(ctx, nextPeer, nextProto)
				if err != nil {
					return err
				}
				dst = s
				dstPeer = nextPeer
				dstIsFinal = isFinal
			}

			// Apply bandwidth limit as a rate-limited writer if configured (Req 20.2, 20.4).
			var writer io.Writer = dst
			h.mu.RLock()
			maxBandwidth := h.maxBandwidth
			waitBandwidth := h.waitBandwidth
			recordBandwidth := h.recordBandwidth
			h.mu.RUnlock()
			if maxBandwidth > 0 {
				writer = &rateLimitedWriter{w: dst, bytesPerSec: maxBandwidth}
			}
			if isFinal {
				if _, err := writePayloadWithBandwidth(ctx, writer, innerHeader, writeChunkSize, waitBandwidth, recordBandwidth); err != nil {
					return err
				}
				if len(innerHeader) > 0 && innerHeader[0] == msgTypeCloseReq {
					if err := waitForCloseAck(dst); err != nil {
						return err
					}
					if _, err := stream.Write([]byte{msgTypeCloseAck}); err != nil {
						return err
					}
					_ = dst.Close()
					dst = nil
					return io.EOF
				}
				// The destination handler treats each final-delivery stream as a
				// single message and reads until EOF, so normal data delivery must
				// close the final-hop stream after each payload.
				if dst != nil {
					_ = dst.Close()
					dst = nil
				}
			} else {
				if _, err := writeEncryptedFrame(ctx, writer, circuitID, frameVersion, innerHeader, waitBandwidth, recordBandwidth); err != nil {
					return err
				}
			}

			return nil
		}(frameCtx)
		if err == io.EOF {
			return
		}
		if err != nil {
			return
		}
	}
}

// handleHeaderOnlyFrameStream implements the header-only fast path.
//
// It reads and decrypts only the encrypted onion header, learns the next hop,
// and then streams the remaining payload bytes onward. The payload itself is
// never reassembled into a new full-size buffer at intermediate relays.
func (h *Handler) handleHeaderOnlyFrameStream(ctx context.Context, reader *bufio.Reader, circuitID string, payloadLen int, key []byte, dst *network.Stream, dstPeer *peer.ID, dstIsFinal *bool, src network.Stream) error {
	h.mu.RLock()
	recordBandwidth := h.recordBandwidth
	waitBandwidth := h.waitBandwidth
	maxBandwidth := h.maxBandwidth
	h.mu.RUnlock()

	if payloadLen < 4 {
		return fmt.Errorf("header-only payload too short")
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(reader, lenBuf[:]); err != nil {
		return err
	}
	if recordBandwidth != nil {
		recordBandwidth("in", 4)
	}
	headerLen := int(binary.LittleEndian.Uint32(lenBuf[:]))
	if headerLen <= 0 || payloadLen < 4+headerLen {
		return fmt.Errorf("invalid header length")
	}
	encryptedHeader := make([]byte, headerLen)
	if _, err := io.ReadFull(reader, encryptedHeader); err != nil {
		return err
	}
	if recordBandwidth != nil {
		recordBandwidth("in", int64(headerLen))
	}
	plaintext, err := decryptHopPayload(key, encryptedHeader)
	if err != nil {
		return err
	}
	isFinal, nextHop, innerHeader, err := parseHopPayload(plaintext)
	if err != nil {
		return err
	}
	dataPayloadLen := payloadLen - 4 - headerLen

	nextProto := ProtocolID
	if isFinal {
		nextProto = FinalProtocolID
	}

	nextPeerDecoded, err := peer.Decode(nextHop)
	if err != nil {
		if *dst != nil {
			_ = (*dst).Close()
			*dst = nil
		}
		return h.forwardByAddressHeaderOnlyStreaming(ctx, reader, nextHop, circuitID, innerHeader, dataPayloadLen, nextProto, waitBandwidth, recordBandwidth, maxBandwidth)
	}

	if *dst == nil || *dstPeer != nextPeerDecoded || *dstIsFinal != isFinal {
		if *dst != nil {
			_ = (*dst).Close()
		}
		s, err := h.openStream(ctx, nextPeerDecoded, nextProto)
		if err != nil {
			return err
		}
		*dst = s
		*dstPeer = nextPeerDecoded
		*dstIsFinal = isFinal
	}

	var writer io.Writer = *dst
	if maxBandwidth > 0 {
		writer = &rateLimitedWriter{w: *dst, bytesPerSec: maxBandwidth}
	}
	if isFinal {
		// At the destination-facing hop we still prepend the control header, but
		// the data payload is streamed from the inbound relay stream directly into
		// the final stream instead of being copied into a new combined buffer.
		if _, err := writePayloadWithBandwidth(ctx, writer, []byte{msgTypeData}, 1, waitBandwidth, recordBandwidth); err != nil {
			return err
		}
		if _, err := writePayloadWithBandwidth(ctx, writer, innerHeader, writeChunkSize, waitBandwidth, recordBandwidth); err != nil {
			return err
		}
		if _, err := pipePayloadWithBandwidth(ctx, reader, writer, dataPayloadLen, waitBandwidth, recordBandwidth); err != nil {
			return err
		}
		if len(innerHeader) > 0 && innerHeader[0] == msgTypeCloseReq {
			if err := waitForCloseAck(*dst); err != nil {
				return err
			}
			if _, err := src.Write([]byte{msgTypeCloseAck}); err != nil {
				return err
			}
			_ = (*dst).Close()
			*dst = nil
			return io.EOF
		}
		if *dst != nil {
			_ = (*dst).Close()
			*dst = nil
		}
		return nil
	}

	// For non-final hops write the updated frame prefix and then pipe the raw
	// payload bytes through without re-encoding or copying the full shard.
	if _, err := writeHeaderOnlyFramePrefix(ctx, writer, circuitID, innerHeader, dataPayloadLen, waitBandwidth, recordBandwidth); err != nil {
		return err
	}
	_, err = pipePayloadWithBandwidth(ctx, reader, writer, dataPayloadLen, waitBandwidth, recordBandwidth)
	return err
}

func (h *Handler) handleSessionSetupFrame(ctx context.Context, reader *bufio.Reader, circuitID string, frameVersion byte, payloadLen int, key []byte, sessionRoutes map[string]*sessionRouteEntry) error {
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
	h.mu.RLock()
	recordBandwidth := h.recordBandwidth
	waitBandwidth := h.waitBandwidth
	maxBandwidth := h.maxBandwidth
	h.mu.RUnlock()
	if recordBandwidth != nil {
		recordBandwidth("in", int64(len(payload)))
	}

	baseID, mode, encryptedHeader, keyData, err := decodeSessionSetupFramePayload(payload)
	if err != nil {
		return err
	}
	if expected := sessionSetupFrameVersionForMode(mode); expected != frameVersion {
		return fmt.Errorf("session setup mode/version mismatch: mode=%d version=%d", mode, frameVersion)
	}
	plaintext, err := decryptHopPayload(key, encryptedHeader)
	if err != nil {
		return err
	}
	isFinal, nextHop, innerPayload, err := parseHopPayload(plaintext)
	if err != nil {
		return err
	}
	nextPeer, err := peer.Decode(nextHop)
	if err != nil {
		return fmt.Errorf("session routing requires peer-id next hop, got %q", nextHop)
	}
	route := &sessionRouteEntry{
		baseSessionID: baseID,
		nextHop:       nextHop,
		nextPeer:      nextPeer,
		isFinal:       isFinal,
		mode:          mode,
		finalTemplate: []byte{msgTypeSessionData},
		lastActivity:  time.Now(),
	}
	if existing := sessionRoutes[baseID]; existing != nil && existing.dst != nil {
		_ = existing.dst.Close()
	}
	sessionRoutes[baseID] = route
	dst, err := h.sessionRouteStream(ctx, route)
	if err != nil {
		delete(sessionRoutes, baseID)
		return err
	}
	var writer io.Writer = dst
	if maxBandwidth > 0 {
		writer = &rateLimitedWriter{w: dst, bytesPerSec: maxBandwidth}
	}
	if isFinal {
		finalPayload := append([]byte{msgTypeSessionSetup}, innerPayload...)
		if _, err := writePayloadWithBandwidth(ctx, writer, finalPayload, writeChunkSize, waitBandwidth, recordBandwidth); err != nil {
			_ = dst.Close()
			return err
		}
		_ = dst.Close()
		return nil
	}
	forwardPayload, err := encodeSessionSetupFramePayload(baseID, mode, innerPayload, keyData)
	if err != nil {
		return err
	}
	if _, err := writeEncryptedFrame(ctx, writer, circuitID, frameVersion, forwardPayload, waitBandwidth, recordBandwidth); err != nil {
		if route.dst != nil {
			_ = route.dst.Close()
			route.dst = nil
		}
		return err
	}
	return nil
}

func (h *Handler) handleSessionDataFrame(ctx context.Context, reader *bufio.Reader, circuitID string, frameVersion byte, payloadLen int, sessionRoutes map[string]*sessionRouteEntry) error {
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
	h.mu.RLock()
	recordBandwidth := h.recordBandwidth
	waitBandwidth := h.waitBandwidth
	maxBandwidth := h.maxBandwidth
	h.mu.RUnlock()
	if recordBandwidth != nil {
		recordBandwidth("in", int64(len(payload)))
	}
	baseID, err := sessionFrameBaseID(payload)
	if err != nil {
		return err
	}
	route, ok := h.sessionRoute(sessionRoutes, baseID)
	if !ok {
		return fmt.Errorf("missing session route for %s", baseID)
	}
	if expected := sessionDataFrameVersionForMode(route.mode); expected != frameVersion {
		return fmt.Errorf("session data mode/version mismatch: mode=%d version=%d", route.mode, frameVersion)
	}
	dst, err := h.sessionRouteStream(ctx, route)
	if err != nil {
		return err
	}
	var writer io.Writer = dst
	if maxBandwidth > 0 {
		writer = &rateLimitedWriter{w: dst, bytesPerSec: maxBandwidth}
	}
	if route.isFinal {
		finalPayload := make([]byte, 1+len(payload))
		finalPayload[0] = msgTypeSessionData
		copy(finalPayload[1:], payload)
		if _, err := writePayloadWithBandwidth(ctx, writer, finalPayload, writeChunkSize, waitBandwidth, recordBandwidth); err != nil {
			_ = dst.Close()
			return err
		}
		_ = dst.Close()
		return nil
	}
	if _, err := writeEncryptedFrame(ctx, writer, circuitID, frameVersion, payload, waitBandwidth, recordBandwidth); err != nil {
		if route.dst != nil {
			_ = route.dst.Close()
			route.dst = nil
		}
		return err
	}
	return nil
}

func (h *Handler) handleSessionDataFrameStream(ctx context.Context, reader *bufio.Reader, circuitID string, frameVersion byte, payloadLen int, sessionRoutes map[string]*sessionRouteEntry) error {
	h.mu.RLock()
	recordBandwidth := h.recordBandwidth
	waitBandwidth := h.waitBandwidth
	maxBandwidth := h.maxBandwidth
	h.mu.RUnlock()

	baseID, controlPrefix, dataPayloadLen, err := readSessionDataControlPrefix(reader, payloadLen, recordBandwidth)
	if err != nil {
		return err
	}
	route, ok := h.sessionRoute(sessionRoutes, baseID)
	if !ok {
		return fmt.Errorf("missing session route for %s", baseID)
	}
	if expected := sessionDataFrameVersionForMode(route.mode); expected != frameVersion {
		return fmt.Errorf("session data mode/version mismatch: mode=%d version=%d", route.mode, frameVersion)
	}
	dst, err := h.sessionRouteStream(ctx, route)
	if err != nil {
		return err
	}
	var writer io.Writer = dst
	if maxBandwidth > 0 {
		writer = &rateLimitedWriter{w: dst, bytesPerSec: maxBandwidth}
	}
	if route.isFinal {
		if _, err := writePayloadWithBandwidth(ctx, writer, append(route.finalTemplate, controlPrefix...), writeChunkSize, waitBandwidth, recordBandwidth); err != nil {
			_ = dst.Close()
			return err
		}
		if _, err := pipePayloadWithBandwidth(ctx, reader, writer, dataPayloadLen, waitBandwidth, recordBandwidth); err != nil {
			_ = dst.Close()
			return err
		}
		_ = dst.Close()
		return nil
	}
	if _, err := writeEncryptedFrameHeaderOnlyPayloadPrefix(ctx, writer, circuitID, frameVersion, payloadLen, controlPrefix, waitBandwidth, recordBandwidth); err != nil {
		if route.dst != nil {
			_ = route.dst.Close()
			route.dst = nil
		}
		return err
	}
	_, err = pipePayloadWithBandwidth(ctx, reader, writer, dataPayloadLen, waitBandwidth, recordBandwidth)
	return err
}

func (h *Handler) handleSessionCloseFrame(ctx context.Context, reader *bufio.Reader, circuitID string, payloadLen int, sessionRoutes map[string]*sessionRouteEntry) error {
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
	h.mu.RLock()
	recordBandwidth := h.recordBandwidth
	waitBandwidth := h.waitBandwidth
	maxBandwidth := h.maxBandwidth
	h.mu.RUnlock()
	if recordBandwidth != nil {
		recordBandwidth("in", int64(len(payload)))
	}
	baseID, err := decodeSessionCloseFramePayload(payload)
	if err != nil {
		return err
	}
	route, ok := h.sessionRoute(sessionRoutes, baseID)
	if !ok {
		return nil
	}
	delete(sessionRoutes, baseID)
	dst, err := h.sessionRouteStream(ctx, route)
	if err != nil {
		h.closeSessionRoute(route)
		return err
	}
	var writer io.Writer = dst
	if maxBandwidth > 0 {
		writer = &rateLimitedWriter{w: dst, bytesPerSec: maxBandwidth}
	}
	if route.isFinal {
		finalPayload := make([]byte, 1+len(payload))
		finalPayload[0] = msgTypeSessionClose
		copy(finalPayload[1:], payload)
		if _, err := writePayloadWithBandwidth(ctx, writer, finalPayload, writeChunkSize, waitBandwidth, recordBandwidth); err != nil {
			_ = dst.Close()
			return err
		}
		_ = dst.Close()
		return nil
	}
	if _, err := writeEncryptedFrame(ctx, writer, circuitID, frameVersionSessionClose, payload, waitBandwidth, recordBandwidth); err != nil {
		h.closeSessionRoute(route)
		return err
	}
	h.closeSessionRoute(route)
	return nil
}

func (h *Handler) sessionRouteTimeout() time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.sessionRouteIdleTimeout > 0 {
		return h.sessionRouteIdleTimeout
	}
	return 30 * time.Second
}

func sessionSetupFrameVersionForMode(mode byte) byte {
	if mode == sessionRouteModeHeaderOnly {
		return frameVersionSessionSetupHeaderOnly
	}
	return frameVersionSessionSetupFullOnion
}

func sessionDataFrameVersionForMode(mode byte) byte {
	if mode == sessionRouteModeHeaderOnly {
		return frameVersionSessionDataHeaderOnly
	}
	return frameVersionSessionDataFullOnion
}

func (h *Handler) sessionRoute(sessionRoutes map[string]*sessionRouteEntry, baseID string) (*sessionRouteEntry, bool) {
	route := sessionRoutes[baseID]
	if route == nil {
		return nil, false
	}
	timeout := h.sessionRouteTimeout()
	if timeout > 0 && !route.lastActivity.IsZero() && time.Since(route.lastActivity) > timeout {
		h.closeSessionRoute(route)
		delete(sessionRoutes, baseID)
		return nil, false
	}
	route.lastActivity = time.Now()
	return route, true
}

func (h *Handler) sessionRouteStream(ctx context.Context, route *sessionRouteEntry) (network.Stream, error) {
	protoID := ProtocolID
	if route.isFinal {
		protoID = FinalProtocolID
		return h.openStream(ctx, route.nextPeer, protoID)
	}
	if route.dst != nil {
		return route.dst, nil
	}
	dst, err := h.openStream(ctx, route.nextPeer, protoID)
	if err != nil {
		return nil, err
	}
	route.dst = dst
	return dst, nil
}

func (h *Handler) closeSessionRoute(route *sessionRouteEntry) {
	if route == nil || route.dst == nil {
		return
	}
	_ = route.dst.Close()
	route.dst = nil
}

func writeEncryptedFrameHeaderOnlyPayloadPrefix(ctx context.Context, w io.Writer, circuitID string, version byte, payloadLen int, controlPrefix []byte, waitBandwidth func(context.Context, int64) error, recordBandwidth func(string, int64)) (int, error) {
	if len(circuitID) == 0 || len(circuitID) > 255 {
		return 0, fmt.Errorf("invalid circuit id")
	}
	frameHeader := make([]byte, 1+len(circuitID)+1+4)
	frameHeader[0] = byte(len(circuitID))
	copy(frameHeader[1:], []byte(circuitID))
	frameHeader[1+len(circuitID)] = version
	binary.LittleEndian.PutUint32(frameHeader[1+len(circuitID)+1:], uint32(payloadLen))

	total, err := writePayloadWithBandwidth(ctx, w, frameHeader, len(frameHeader), waitBandwidth, recordBandwidth)
	if err != nil {
		return total, err
	}
	n, err := writePayloadWithBandwidth(ctx, w, controlPrefix, writeChunkSize, waitBandwidth, recordBandwidth)
	return total + n, err
}

func readSessionDataControlPrefix(reader *bufio.Reader, payloadLen int, recordBandwidth func(string, int64)) (string, []byte, int, error) {
	readTracked := func(buf []byte) error {
		if _, err := io.ReadFull(reader, buf); err != nil {
			return err
		}
		if recordBandwidth != nil {
			recordBandwidth("in", int64(len(buf)))
		}
		return nil
	}

	if payloadLen < 1 {
		return "", nil, 0, fmt.Errorf("session data payload too short")
	}
	baseLenBuf := make([]byte, 1)
	if err := readTracked(baseLenBuf); err != nil {
		return "", nil, 0, err
	}
	baseLen := int(baseLenBuf[0])
	if payloadLen < 1+baseLen+1+4+4+2 {
		return "", nil, 0, fmt.Errorf("session data payload truncated")
	}
	prefix := append([]byte(nil), baseLenBuf...)
	baseAndFlags := make([]byte, baseLen+1)
	if err := readTracked(baseAndFlags); err != nil {
		return "", nil, 0, err
	}
	prefix = append(prefix, baseAndFlags...)
	baseID := string(baseAndFlags[:baseLen])
	flags := baseAndFlags[baseLen]
	if flags&sessionDataFlagSequenced != 0 {
		seqBuf := make([]byte, 8)
		if err := readTracked(seqBuf); err != nil {
			return "", nil, 0, err
		}
		prefix = append(prefix, seqBuf...)
	}
	metaBuf := make([]byte, 10)
	if err := readTracked(metaBuf); err != nil {
		return "", nil, 0, err
	}
	prefix = append(prefix, metaBuf...)
	authLen := int(binary.LittleEndian.Uint16(metaBuf[8:10]))
	if payloadLen < len(prefix)+authLen {
		return "", nil, 0, fmt.Errorf("invalid session data auth length")
	}
	if authLen > 0 {
		authBuf := make([]byte, authLen)
		if err := readTracked(authBuf); err != nil {
			return "", nil, 0, err
		}
		prefix = append(prefix, authBuf...)
	}
	dataPayloadLen := payloadLen - len(prefix)
	if dataPayloadLen < 0 {
		return "", nil, 0, fmt.Errorf("invalid session data payload length")
	}
	return baseID, prefix, dataPayloadLen, nil
}

func (h *Handler) openStream(ctx context.Context, nextPeer peer.ID, protoID string) (network.Stream, error) {
	h.mu.RLock()
	host := h.host
	useRCMgr := h.useRCMgr
	serviceName := h.serviceName
	h.mu.RUnlock()

	if host == nil {
		return nil, fmt.Errorf("no host configured")
	}
	if host.Network().Connectedness(nextPeer) != network.Connected {
		connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := host.Connect(connectCtx, peer.AddrInfo{ID: nextPeer}); err != nil {
			return nil, fmt.Errorf("failed to connect to next hop: %w", err)
		}
	}

	// Pre-admit outbound stream with rcmgr so resource policies are enforced centrally.
	if useRCMgr {
		rm := host.Network().ResourceManager()
		scope, err := rm.OpenStream(nextPeer, network.DirOutbound)
		if err != nil {
			return nil, fmt.Errorf("rcmgr rejected outbound stream: %w", err)
		}
		if err := scope.SetProtocol(protocol.ID(protoID)); err != nil {
			scope.Done()
			return nil, fmt.Errorf("rcmgr protocol scope setup failed: %w", err)
		}
		// Best effort. Service names are optional in rcmgr.
		_ = scope.SetService(serviceName)
		defer scope.Done()
	}

	s, err := host.NewStream(ctx, nextPeer, protocol.ID(protoID))
	if err != nil {
		return nil, err
	}
	if flusher, ok := s.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			_ = s.Reset()
			return nil, fmt.Errorf("failed to negotiate stream: %w", err)
		}
	}
	// Tag the stream's own scope with service so resource policies are enforced correctly.
	if useRCMgr {
		_ = s.Scope().SetService(serviceName)
	}
	return s, nil
}

func (h *Handler) forwardByAddressEncrypted(ctx context.Context, addr string, circuitID string, version byte, payload []byte, protoID string) error {
	h.mu.RLock()
	host := h.host
	maxBandwidth := h.maxBandwidth
	waitBandwidth := h.waitBandwidth
	recordBandwidth := h.recordBandwidth
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

	dst, err := host.NewStream(ctx, addrInfo.ID, protocol.ID(protoID))
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer dst.Close()
	if flusher, ok := dst.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			_ = dst.Reset()
			return fmt.Errorf("failed to negotiate stream: %w", err)
		}
	}

	var writer io.Writer = dst
	if maxBandwidth > 0 {
		writer = &rateLimitedWriter{w: dst, bytesPerSec: maxBandwidth}
	}
	if waitBandwidth != nil {
		if err := waitBandwidth(ctx, int64(len(payload))); err != nil {
			return err
		}
	}

	_, err = writeEncryptedFrame(ctx, writer, circuitID, version, payload, waitBandwidth, recordBandwidth)
	return err
}

func (h *Handler) forwardByAddressHeaderOnlyEncrypted(ctx context.Context, addr string, circuitID string, encryptedHeader []byte, dataPayload []byte, protoID string) error {
	h.mu.RLock()
	host := h.host
	maxBandwidth := h.maxBandwidth
	waitBandwidth := h.waitBandwidth
	recordBandwidth := h.recordBandwidth
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

	dst, err := host.NewStream(ctx, addrInfo.ID, protocol.ID(protoID))
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer dst.Close()
	if flusher, ok := dst.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			_ = dst.Reset()
			return fmt.Errorf("failed to negotiate stream: %w", err)
		}
	}

	var writer io.Writer = dst
	if maxBandwidth > 0 {
		writer = &rateLimitedWriter{w: dst, bytesPerSec: maxBandwidth}
	}

	_, err = writeHeaderOnlyFrame(ctx, writer, circuitID, encryptedHeader, dataPayload, waitBandwidth, recordBandwidth)
	return err
}

func (h *Handler) forwardByAddressHeaderOnlyStreaming(ctx context.Context, reader *bufio.Reader, addr string, circuitID string, encryptedHeader []byte, dataPayloadLen int, protoID string, waitBandwidth func(context.Context, int64) error, recordBandwidth func(string, int64), maxBandwidth int64) error {
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

	dst, err := host.NewStream(ctx, addrInfo.ID, protocol.ID(protoID))
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer dst.Close()
	if flusher, ok := dst.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			_ = dst.Reset()
			return fmt.Errorf("failed to negotiate stream: %w", err)
		}
	}

	var writer io.Writer = dst
	if maxBandwidth > 0 {
		writer = &rateLimitedWriter{w: dst, bytesPerSec: maxBandwidth}
	}
	if _, err := writeHeaderOnlyFramePrefix(ctx, writer, circuitID, encryptedHeader, dataPayloadLen, waitBandwidth, recordBandwidth); err != nil {
		return err
	}
	_, err = pipePayloadWithBandwidth(ctx, reader, writer, dataPayloadLen, waitBandwidth, recordBandwidth)
	return err
}

func decodeSessionSetupFramePayload(data []byte) (string, byte, []byte, []byte, error) {
	if len(data) < 1 {
		return "", 0, nil, nil, fmt.Errorf("session setup payload too short")
	}
	baseLen := int(data[0])
	offset := 1
	if len(data) < offset+baseLen+1+4 {
		return "", 0, nil, nil, fmt.Errorf("session setup payload truncated")
	}
	baseID := string(data[offset : offset+baseLen])
	offset += baseLen
	mode := data[offset]
	offset++
	headerLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if headerLen < 0 || len(data) < offset+headerLen+4 {
		return "", 0, nil, nil, fmt.Errorf("invalid session setup header length")
	}
	encryptedHeader := append([]byte(nil), data[offset:offset+headerLen]...)
	offset += headerLen
	keyLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	if keyLen < 0 || len(data) < offset+keyLen {
		return "", 0, nil, nil, fmt.Errorf("invalid session setup key length")
	}
	keyData := append([]byte(nil), data[offset:offset+keyLen]...)
	return baseID, mode, encryptedHeader, keyData, nil
}

func encodeSessionSetupFramePayload(baseSessionID string, mode byte, encryptedHeader []byte, keyData []byte) ([]byte, error) {
	if len(baseSessionID) > 0xff {
		return nil, fmt.Errorf("base session id too long: %d", len(baseSessionID))
	}
	buf := make([]byte, 1+len(baseSessionID)+1+4+len(encryptedHeader)+4+len(keyData))
	pos := 0
	buf[pos] = byte(len(baseSessionID))
	pos++
	pos += copy(buf[pos:], baseSessionID)
	buf[pos] = mode
	pos++
	binary.LittleEndian.PutUint32(buf[pos:], uint32(len(encryptedHeader)))
	pos += 4
	pos += copy(buf[pos:], encryptedHeader)
	binary.LittleEndian.PutUint32(buf[pos:], uint32(len(keyData)))
	pos += 4
	copy(buf[pos:], keyData)
	return buf, nil
}

func decodeSessionCloseFramePayload(data []byte) (string, error) {
	if len(data) < 1 {
		return "", fmt.Errorf("session payload too short")
	}
	baseLen := int(data[0])
	if len(data) < 1+baseLen+4 {
		return "", fmt.Errorf("session payload truncated")
	}
	return string(data[1 : 1+baseLen]), nil
}

func sessionFrameBaseID(data []byte) (string, error) {
	if len(data) < 1 {
		return "", fmt.Errorf("session payload too short")
	}
	baseLen := int(data[0])
	if len(data) < 1+baseLen {
		return "", fmt.Errorf("session payload truncated")
	}
	return string(data[1 : 1+baseLen]), nil
}

func waitForCloseAck(stream network.Stream) error {
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(stream, buf); err != nil {
		return err
	}
	if buf[0] != msgTypeCloseAck {
		return fmt.Errorf("unexpected close ack: %x", buf[0])
	}
	return nil
}

func readEncryptedFrameHeader(r *bufio.Reader) (string, byte, int, error) {
	cidLen, err := r.ReadByte()
	if err != nil {
		return "", 0, 0, err
	}
	if cidLen == 0 {
		return "", 0, 0, fmt.Errorf("empty circuit id")
	}
	cid := make([]byte, int(cidLen))
	if _, err := io.ReadFull(r, cid); err != nil {
		return "", 0, 0, err
	}
	version, err := r.ReadByte()
	if err != nil {
		return "", 0, 0, err
	}
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return "", 0, 0, err
	}
	payloadLen := int(binary.LittleEndian.Uint32(lenBuf))
	maxPayloadSize := MaxEncryptedPayloadSize()
	if payloadLen <= 0 || payloadLen > maxPayloadSize {
		return "", 0, 0, fmt.Errorf("invalid encrypted payload length")
	}
	return string(cid), version, payloadLen, nil
}

func readEncryptedFramePayload(r *bufio.Reader, scope network.StreamScope, payloadLen int) ([]byte, func(), error) {
	release := func() {}
	if scope != nil {
		if err := scope.ReserveMemory(payloadLen, network.ReservationPriorityMedium); err != nil {
			return nil, nil, fmt.Errorf("rcmgr inbound memory reservation failed: %w", err)
		}
		release = func() { scope.ReleaseMemory(payloadLen) }
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		release()
		return nil, nil, err
	}
	return payload, release, nil
}

func writeEncryptedFrame(ctx context.Context, w io.Writer, circuitID string, version byte, payload []byte, waitBandwidth func(context.Context, int64) error, recordBandwidth func(string, int64)) (int, error) {
	if len(circuitID) == 0 || len(circuitID) > 255 {
		return 0, fmt.Errorf("invalid circuit id")
	}
	maxPayloadSize := MaxEncryptedPayloadSize()
	if len(payload) > maxPayloadSize {
		return 0, fmt.Errorf("payload too large: %d bytes exceeds limit of %d", len(payload), maxPayloadSize)
	}
	header := make([]byte, 1+len(circuitID)+1+4)
	header[0] = byte(len(circuitID))
	copy(header[1:], []byte(circuitID))
	header[1+len(circuitID)] = version
	binary.LittleEndian.PutUint32(header[1+len(circuitID)+1:], uint32(len(payload)))
	hn, err := writePayloadWithBandwidth(ctx, w, header, len(header), waitBandwidth, recordBandwidth)
	if err != nil {
		return hn, err
	}
	pn, err := writePayloadWithBandwidth(ctx, w, payload, writeChunkSize, waitBandwidth, recordBandwidth)
	return hn + pn, err
}

func writeHeaderOnlyFrame(ctx context.Context, w io.Writer, circuitID string, encryptedHeader []byte, dataPayload []byte, waitBandwidth func(context.Context, int64) error, recordBandwidth func(string, int64)) (int, error) {
	if len(circuitID) == 0 || len(circuitID) > 255 {
		return 0, fmt.Errorf("invalid circuit id")
	}
	if len(encryptedHeader) == 0 {
		return 0, fmt.Errorf("missing header-only header")
	}
	payloadLen := 4 + len(encryptedHeader) + len(dataPayload)
	maxPayloadSize := MaxEncryptedPayloadSize()
	if payloadLen > maxPayloadSize {
		return 0, fmt.Errorf("payload too large: %d bytes exceeds limit of %d", payloadLen, maxPayloadSize)
	}

	total, err := writeHeaderOnlyFramePrefix(ctx, w, circuitID, encryptedHeader, len(dataPayload), waitBandwidth, recordBandwidth)
	if err != nil {
		return total, err
	}
	n, err := writePayloadWithBandwidth(ctx, w, dataPayload, writeChunkSize, waitBandwidth, recordBandwidth)
	total += n
	return total, err
}

func writeHeaderOnlyFramePrefix(ctx context.Context, w io.Writer, circuitID string, encryptedHeader []byte, dataPayloadLen int, waitBandwidth func(context.Context, int64) error, recordBandwidth func(string, int64)) (int, error) {
	if len(circuitID) == 0 || len(circuitID) > 255 {
		return 0, fmt.Errorf("invalid circuit id")
	}
	if len(encryptedHeader) == 0 {
		return 0, fmt.Errorf("missing header-only header")
	}
	payloadLen := 4 + len(encryptedHeader) + dataPayloadLen
	maxPayloadSize := MaxEncryptedPayloadSize()
	if payloadLen > maxPayloadSize {
		return 0, fmt.Errorf("payload too large: %d bytes exceeds limit of %d", payloadLen, maxPayloadSize)
	}

	frameHeader := make([]byte, 1+len(circuitID)+1+4)
	frameHeader[0] = byte(len(circuitID))
	copy(frameHeader[1:], []byte(circuitID))
	frameHeader[1+len(circuitID)] = frameVersionHeaderOnly
	binary.LittleEndian.PutUint32(frameHeader[1+len(circuitID)+1:], uint32(payloadLen))

	headerOnlyPrefix := make([]byte, 4)
	binary.LittleEndian.PutUint32(headerOnlyPrefix, uint32(len(encryptedHeader)))

	total, err := writePayloadWithBandwidth(ctx, w, frameHeader, len(frameHeader), waitBandwidth, recordBandwidth)
	if err != nil {
		return total, err
	}
	n, err := writePayloadWithBandwidth(ctx, w, headerOnlyPrefix, len(headerOnlyPrefix), waitBandwidth, recordBandwidth)
	total += n
	if err != nil {
		return total, err
	}
	n, err = writePayloadWithBandwidth(ctx, w, encryptedHeader, writeChunkSize, waitBandwidth, recordBandwidth)
	total += n
	return total, err
}

func writeHeaderOnlyFinalPayload(ctx context.Context, w io.Writer, controlHeader []byte, dataPayload []byte, waitBandwidth func(context.Context, int64) error, recordBandwidth func(string, int64)) (int, error) {
	total, err := writePayloadWithBandwidth(ctx, w, []byte{msgTypeData}, 1, waitBandwidth, recordBandwidth)
	if err != nil {
		return total, err
	}
	n, err := writePayloadWithBandwidth(ctx, w, controlHeader, writeChunkSize, waitBandwidth, recordBandwidth)
	total += n
	if err != nil {
		return total, err
	}
	n, err = writePayloadWithBandwidth(ctx, w, dataPayload, writeChunkSize, waitBandwidth, recordBandwidth)
	total += n
	return total, err
}

// pipePayloadWithBandwidth copies payload bytes from the inbound relay stream
// to the outbound stream in fixed-size chunks. It exists specifically to avoid
// allocating or rebuilding a second full payload buffer when header-only onion
// forwarding only needs to change the routing header.
func pipePayloadWithBandwidth(ctx context.Context, r *bufio.Reader, w io.Writer, remaining int, waitBandwidth func(context.Context, int64) error, recordBandwidth func(string, int64)) (int, error) {
	if remaining < 0 {
		return 0, fmt.Errorf("invalid payload length")
	}
	bufPtr := relayChunkPool.Get().(*[]byte)
	buf := *bufPtr
	defer relayChunkPool.Put(bufPtr)
	total := 0
	for remaining > 0 {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
		chunkLen := remaining
		if chunkLen > len(buf) {
			chunkLen = len(buf)
		}
		n, err := io.ReadFull(r, buf[:chunkLen])
		if n > 0 && recordBandwidth != nil {
			recordBandwidth("in", int64(n))
		}
		if err != nil {
			return total, err
		}
		written, err := writePayloadWithBandwidth(ctx, w, buf[:n], n, waitBandwidth, recordBandwidth)
		total += written
		if err != nil {
			return total, err
		}
		remaining -= n
	}
	return total, nil
}

func writePayloadWithBandwidth(ctx context.Context, w io.Writer, payload []byte, chunkSize int, waitBandwidth func(context.Context, int64) error, recordBandwidth func(string, int64)) (int, error) {
	total := 0
	for len(payload) > 0 {
		chunk := payload
		if chunkSize > 0 && len(chunk) > chunkSize {
			chunk = chunk[:chunkSize]
		}
		if waitBandwidth != nil {
			if err := waitBandwidth(ctx, int64(len(chunk))); err != nil {
				return total, err
			}
		}
		n, err := w.Write(chunk)
		total += n
		if n > 0 && recordBandwidth != nil {
			recordBandwidth("out", int64(n))
		}
		if err != nil {
			return total, err
		}
		if n <= 0 {
			return total, fmt.Errorf("short write")
		}
		payload = payload[n:]
	}
	return total, nil
}

func writeAllChunked(w io.Writer, payload []byte, chunkSize int) (int, error) {
	if chunkSize <= 0 {
		chunkSize = len(payload)
	}
	total := 0
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > chunkSize {
			chunk = chunk[:chunkSize]
		}
		n, err := w.Write(chunk)
		total += n
		if err != nil {
			return total, err
		}
		if n <= 0 {
			return total, fmt.Errorf("short write")
		}
		payload = payload[n:]
	}
	return total, nil
}

func decryptHopPayload(key []byte, payload []byte) ([]byte, error) {
	if len(payload) < nonceSize {
		return nil, fmt.Errorf("payload too short")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := payload[:nonceSize]
	ciphertext := payload[nonceSize:]
	return aead.Open(nil, nonce, ciphertext, nil)
}

func parseHopPayload(plaintext []byte) (bool, string, []byte, error) {
	if len(plaintext) < 1+2 {
		return false, "", nil, fmt.Errorf("plaintext too short")
	}
	isFinal := plaintext[0] == 1
	nextLen := int(binary.LittleEndian.Uint16(plaintext[1:3]))
	if len(plaintext) < 3+nextLen {
		return false, "", nil, fmt.Errorf("invalid next hop length")
	}
	nextHop := string(plaintext[3 : 3+nextLen])
	inner := plaintext[3+nextLen:]
	return isFinal, nextHop, inner, nil
}

func parseHeaderOnlyPayload(payload []byte) ([]byte, []byte, error) {
	if len(payload) < 4 {
		return nil, nil, fmt.Errorf("header-only payload too short")
	}
	headerLen := int(binary.LittleEndian.Uint32(payload[:4]))
	if headerLen <= 0 || len(payload) < 4+headerLen {
		return nil, nil, fmt.Errorf("invalid header length")
	}
	encryptedHeader := payload[4 : 4+headerLen]
	data := payload[4+headerLen:]
	return encryptedHeader, data, nil
}

func buildHeaderOnlyPayload(encryptedHeader []byte, payload []byte) []byte {
	buf := make([]byte, 4+len(encryptedHeader)+len(payload))
	binary.LittleEndian.PutUint32(buf[:4], uint32(len(encryptedHeader)))
	copy(buf[4:], encryptedHeader)
	copy(buf[4+len(encryptedHeader):], payload)
	return buf
}

// HandleKeyExchange registers hop keys for a circuit using a Noise XX handshake.
func (h *Handler) HandleKeyExchange(stream network.Stream) {
	defer stream.Close()
	payload, err := runNoiseXXResponder(context.Background(), stream)
	if err != nil {
		return
	}
	circuitID, key, err := decodeKeyExchangePayload(payload)
	if err != nil {
		return
	}
	h.setCircuitKey(circuitID, key)
	_ = writeFrame(stream, []byte{0x01})
}

func (h *Handler) setCircuitKey(circuitID string, key []byte) {
	h.muKeys.Lock()
	defer h.muKeys.Unlock()
	h.circuitKeys[circuitID] = key
}

func (h *Handler) getCircuitKey(circuitID string) []byte {
	h.muKeys.RLock()
	defer h.muKeys.RUnlock()
	return h.circuitKeys[circuitID]
}

type rateLimitedWriter struct {
	w           io.Writer
	bytesPerSec int64
}

func (r *rateLimitedWriter) Write(p []byte) (int, error) {
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

// SetMaxBandwidth updates the per-circuit bandwidth limit used by the relay handler.
func (h *Handler) SetMaxBandwidth(maxBandwidth int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.maxBandwidth = maxBandwidth
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

// EnableLibp2pResourceManager toggles rcmgr-based admission and accounting.
func (h *Handler) EnableLibp2pResourceManager(enabled bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.useRCMgr = enabled
}

// SetResourceServiceName sets the rcmgr service name for stream scopes.
func (h *Handler) SetResourceServiceName(name string) {
	if name == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.serviceName = name
}

// SetBandwidthBackpressure sets a callback used to enforce bandwidth backpressure.
func (h *Handler) SetBandwidthBackpressure(fn func(context.Context, int64) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.waitBandwidth = fn
}

// SetBandwidthRecorder sets a callback used to record inbound/outbound bandwidth.
func (h *Handler) SetBandwidthRecorder(fn func(direction string, bytes int64)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recordBandwidth = fn
}

// SetUtilizationReporter sets a callback to publish active relay circuit utilization.
func (h *Handler) SetUtilizationReporter(fn func(activeCircuits int)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reportUtilization = fn
}
