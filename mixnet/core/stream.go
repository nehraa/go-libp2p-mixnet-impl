package mixnet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// MixStream exposes a stream-style API on top of the mixnet session machinery.
//
// An outbound MixStream is created by OpenStream and remembers the destination
// peer and caller context. An inbound MixStream is created by AcceptStream and
// only supports reading until the remote side closes or the context is
// cancelled.
type MixStream struct {
	mixnet    *Mixnet
	dest      peer.ID
	proto     string
	sessionID string
	ctx       context.Context
	ch        <-chan []byte
	mu        sync.Mutex
	closed    bool
	readBuf   []byte
	writeSeq  uint64
}

const (
	streamSessionIDBytes = 20
	streamWriteDelimiter = "~"
	streamWriteSeqWidth  = 16
)

// OpenStream establishes mixnet circuits to dest and returns an outbound stream
// wrapper bound to a fresh session ID.
//
// The returned stream reuses the supplied context for reads and writes so that
// callers can cancel a long-running session using standard context semantics.
func (m *Mixnet) OpenStream(ctx context.Context, dest peer.ID) (*MixStream, error) {
	if _, err := m.EstablishConnection(ctx, dest); err != nil {
		return nil, err
	}
	sessionID := newStreamSessionID()
	if err := m.registerStreamSession(sessionID); err != nil {
		return nil, err
	}
	ch := m.destHandler.registerSession(sessionID)
	return &MixStream{
		mixnet:    m,
		dest:      dest,
		sessionID: sessionID,
		ctx:       ctx,
		ch:        ch,
	}, nil
}

// Read copies reconstructed payload bytes into p.
//
// If a previous read left buffered data behind, Read drains that buffer first.
// Otherwise it waits for the destination handler to deliver the next
// reconstructed message fragment for this session.
func (s *MixStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.EOF
	}
	if len(s.readBuf) > 0 {
		n := copy(p, s.readBuf)
		s.readBuf = s.readBuf[n:]
		s.mu.Unlock()
		return n, nil
	}
	s.mu.Unlock()

	var (
		data []byte
		ok   bool
	)
	if s.ctx != nil {
		select {
		case <-s.ctx.Done():
			return 0, s.ctx.Err()
		case data, ok = <-s.ch:
		}
	} else {
		data, ok = <-s.ch
	}
	if !ok {
		return 0, io.EOF
	}
	if len(data) <= len(p) {
		copy(p, data)
		return len(data), nil
	}
	n := copy(p, data[:len(p)])
	s.mu.Lock()
	s.readBuf = append(s.readBuf, data[n:]...)
	s.mu.Unlock()
	return n, nil
}

// Write sends p to the remote destination using the stream session ID.
//
// Inbound-only streams do not have a destination peer and therefore reject
// writes. For outbound streams, Write delegates to Mixnet.SendWithSession so
// that successive writes stay associated with the same logical session.
func (s *MixStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	if s.dest == "" {
		s.mu.Unlock()
		return 0, fmt.Errorf("cannot write to inbound-only stream")
	}
	wireSessionID := streamWriteSessionID(s.sessionID, s.writeSeq)
	s.writeSeq++
	s.mu.Unlock()

	if err := s.mixnet.SendWithSession(s.ctx, s.dest, p, wireSessionID); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close marks the stream closed and unregisters its session from the
// destination handler.
//
// Close is idempotent. It does not tear down the underlying mixnet runtime, but
// it stops future reads and writes for this session wrapper.
func (s *MixStream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	if s.dest != "" && s.mixnet != nil && sessionRoutingEnabled(s.mixnet.config) {
		_ = s.mixnet.closeSessionRouting(s.ctx, s.dest, s.sessionID)
	}
	s.mixnet.clearStreamSession(s.sessionID)
	s.mixnet.destHandler.unregisterSession(s.sessionID)
	return nil
}

// AcceptStream waits for the next inbound mixnet session and returns a stream
// wrapper that reads reconstructed payloads for that session.
//
// The method blocks until a remote peer starts sending on a new session or the
// supplied context is cancelled.
func (m *Mixnet) AcceptStream(ctx context.Context) (*MixStream, error) {
	if m.destHandler == nil {
		return nil, fmt.Errorf("no destination handler")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case sessionID := <-m.destHandler.inboundCh:
		ch := m.destHandler.registerSession(sessionID)
		return &MixStream{
			mixnet:    m,
			dest:      "",
			sessionID: sessionID,
			ctx:       ctx,
			ch:        ch,
		}, nil
	}
}

func newStreamSessionID() string {
	buf := make([]byte, streamSessionIDBytes)
	if _, err := rand.Read(buf); err == nil {
		return hex.EncodeToString(buf)
	}
	return normalizeSessionID(fmt.Sprintf("stream-%d", time.Now().UnixNano()))
}

func streamWriteSessionID(base string, seq uint64) string {
	return fmt.Sprintf("%s%s%0*x", base, streamWriteDelimiter, streamWriteSeqWidth, seq)
}

func parseStreamWriteSequence(sessionID string) (string, uint64, bool) {
	idx := strings.LastIndex(sessionID, streamWriteDelimiter)
	if idx <= 0 || len(sessionID)-idx-1 != streamWriteSeqWidth {
		return sessionID, 0, false
	}
	seq, err := strconv.ParseUint(sessionID[idx+1:], 16, 64)
	if err != nil {
		return sessionID, 0, false
	}
	return sessionID[:idx], seq, true
}

func baseSessionID(sessionID string) string {
	base, _, ok := parseStreamWriteSequence(sessionID)
	if !ok {
		return sessionID
	}
	return base
}
