package mixnet

// This file exports internal functions for use by the benchmarks package.
// These are NOT part of the public API.

import (
	"context"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/mixnet/circuit"
)

// SessionKeyExported is an exported alias for the internal sessionKey type.
type SessionKeyExported = sessionKey

// EncryptSessionPayload exports encryptSessionPayload for benchmarks.
func EncryptSessionPayload(plaintext []byte) ([]byte, []byte, error) {
	return encryptSessionPayload(plaintext)
}

// DecryptSessionPayload exports decryptSessionPayload for benchmarks.
func DecryptSessionPayload(ciphertext []byte, key sessionKey) ([]byte, error) {
	return decryptSessionPayload(ciphertext, key)
}

// DecodeSessionKeyData exports decodeSessionKeyData for benchmarks.
func DecodeSessionKeyData(data []byte) (sessionKey, error) {
	return decodeSessionKeyData(data)
}

// ComputeAuthTag exports computeAuthTag for benchmarks.
func ComputeAuthTag(key sessionKey, sessionID []byte, shardIndex uint32, totalShards uint32, shardData []byte, hasKeys bool, keyData []byte, tagSize int) []byte {
	return computeAuthTag(key, sessionID, shardIndex, totalShards, shardData, hasKeys, keyData, tagSize)
}

// ApplyPayloadPadding exports applyPayloadPadding for benchmarks.
func ApplyPayloadPadding(payload []byte, cfg *MixnetConfig) ([]byte, bool, error) {
	return applyPayloadPadding(payload, cfg)
}

// DataChannel returns the reconstructed data channel from the destination handler.
func (m *Mixnet) DataChannel() <-chan []byte {
	if m.destHandler == nil {
		return nil
	}
	return m.destHandler.DataChan()
}

// ExchangeHopKey exports exchangeHopKey for benchmarks.
func (m *Mixnet) ExchangeHopKey(ctx context.Context, relayPeer peer.ID, circuitID string) ([]byte, error) {
	return m.exchangeHopKey(ctx, relayPeer, circuitID)
}

// EnsureCircuitKeysForBenchmark precomputes and caches hop keys for the given circuits.
func (m *Mixnet) EnsureCircuitKeysForBenchmark(ctx context.Context, circuits []*circuit.Circuit) error {
	return m.ensureCircuitKeys(ctx, circuits)
}

// DisableBandwidthLimitsForBenchmark removes internal bandwidth throttling for local benchmark runs.
func (m *Mixnet) DisableBandwidthLimitsForBenchmark() {
	if m == nil || m.resourceMgr == nil {
		return
	}
	m.resourceMgr.SetBackpressureEnabled(false)
	m.resourceMgr.SetBandwidthLimit(0)
}

// ForceCloseForTest performs a forced shutdown suitable for test cleanup.
func (m *Mixnet) ForceCloseForTest() {
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
	m.clearAllStreamSessions()
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
