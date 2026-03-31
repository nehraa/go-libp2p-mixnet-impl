package mixnet

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/mixnet/ces"
)

func TestSessionRoutingEnabledOnlyForHeaderOnly(t *testing.T) {
	tests := []struct {
		name string
		cfg  *MixnetConfig
		want bool
	}{
		{name: "nil config", cfg: nil, want: false},
		{name: "disabled", cfg: &MixnetConfig{EnableSessionRouting: false, EncryptionMode: EncryptionModeHeaderOnly}, want: false},
		{name: "header only enabled", cfg: &MixnetConfig{EnableSessionRouting: true, EncryptionMode: EncryptionModeHeaderOnly}, want: true},
		{name: "full onion enabled", cfg: &MixnetConfig{EnableSessionRouting: true, EncryptionMode: EncryptionModeFull}, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sessionRoutingEnabled(tc.cfg); got != tc.want {
				t.Fatalf("sessionRoutingEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSessionSetupFrameControlPrefixMatchesEncodedPayload(t *testing.T) {
	baseID := "session-setup"
	encryptedHeader := []byte("header-bytes")
	keyData := []byte("key-material")

	encoded, err := encodeSessionSetupFramePayload(baseID, sessionRouteModeHeaderOnly, encryptedHeader, keyData)
	if err != nil {
		t.Fatalf("encodeSessionSetupFramePayload() error = %v", err)
	}

	prefix, keyPrefix, err := buildSessionSetupFrameControlParts(baseID, sessionRouteModeHeaderOnly, len(encryptedHeader), len(keyData))
	if err != nil {
		t.Fatalf("buildSessionSetupFrameControlParts() error = %v", err)
	}

	var assembled bytes.Buffer
	assembled.Write(prefix)
	assembled.Write(encryptedHeader)
	assembled.Write(keyPrefix)
	assembled.Write(keyData)

	if !bytes.Equal(encoded, assembled.Bytes()) {
		t.Fatalf("assembled setup payload mismatch")
	}
}

func TestSessionDataFrameControlPrefixMatchesEncodedPayload(t *testing.T) {
	shard := &ces.Shard{Index: 3, Data: []byte("payload-bytes")}
	authTag := []byte("auth")
	baseID := "session-data"
	seq := uint64(42)

	encoded, err := encodeSessionDataFramePayload(baseID, true, seq, shard, 7, authTag)
	if err != nil {
		t.Fatalf("encodeSessionDataFramePayload() error = %v", err)
	}

	prefix, err := buildSessionDataFrameControlPrefix(baseID, true, seq, shard.Index, 7, len(authTag))
	if err != nil {
		t.Fatalf("buildSessionDataFrameControlPrefix() error = %v", err)
	}

	var assembled bytes.Buffer
	assembled.Write(prefix)
	assembled.Write(authTag)
	assembled.Write(shard.Data)

	if !bytes.Equal(encoded, assembled.Bytes()) {
		t.Fatalf("assembled session data payload mismatch")
	}
}

func TestSessionDataFrameControlPrefixRejectsInvalidInputs(t *testing.T) {
	if _, err := buildSessionDataFrameControlPrefix("session", false, 0, -1, 2, 0); err == nil {
		t.Fatal("expected invalid shard index to fail")
	}
	if _, err := buildSessionDataFrameControlPrefix("session", false, 0, 0, 2, 1<<16); err == nil {
		t.Fatal("expected oversized auth tag to fail")
	}
}

func TestDecodeSessionDataFramePayloadViewAvoidsCloning(t *testing.T) {
	shard := &ces.Shard{Index: 1, Data: []byte("payload-bytes")}
	authTag := []byte("auth-tag")
	encoded, err := encodeSessionDataFramePayload("session-data", true, 7, shard, 3, authTag)
	if err != nil {
		t.Fatalf("encodeSessionDataFramePayload() error = %v", err)
	}

	prefix, err := buildSessionDataFrameControlPrefix("session-data", true, 7, shard.Index, 3, len(authTag))
	if err != nil {
		t.Fatalf("buildSessionDataFrameControlPrefix() error = %v", err)
	}
	authOffset := len(prefix)
	payloadOffset := authOffset + len(authTag)

	_, _, _, viewShard, _, viewAuth, err := decodeSessionDataFramePayloadView(encoded)
	if err != nil {
		t.Fatalf("decodeSessionDataFramePayloadView() error = %v", err)
	}
	_, _, _, clonedShard, _, clonedAuth, err := decodeSessionDataFramePayload(encoded)
	if err != nil {
		t.Fatalf("decodeSessionDataFramePayload() error = %v", err)
	}

	encoded[authOffset] ^= 0x01
	encoded[payloadOffset] ^= 0x01

	if bytes.Equal(viewAuth, authTag) {
		t.Fatal("view auth tag should reflect backing-buffer mutation")
	}
	if bytes.Equal(viewShard.Data, shard.Data) {
		t.Fatal("view shard data should reflect backing-buffer mutation")
	}
	if !bytes.Equal(clonedAuth, authTag) {
		t.Fatal("cloned auth tag should remain unchanged")
	}
	if !bytes.Equal(clonedShard.Data, shard.Data) {
		t.Fatal("cloned shard data should remain unchanged")
	}
}

func TestDecodeSessionSetupDeliveryPayloadViewAvoidsCloning(t *testing.T) {
	baseID := "session-setup"
	keyData := []byte("setup-key-data")

	encoded, err := encodeSessionSetupDeliveryPayload(baseID, keyData)
	if err != nil {
		t.Fatalf("encodeSessionSetupDeliveryPayload() error = %v", err)
	}

	keyOffset := 1 + len(baseID) + 4

	_, viewKeyData, err := decodeSessionSetupDeliveryPayloadView(encoded)
	if err != nil {
		t.Fatalf("decodeSessionSetupDeliveryPayloadView() error = %v", err)
	}
	_, clonedKeyData, err := decodeSessionSetupDeliveryPayload(encoded)
	if err != nil {
		t.Fatalf("decodeSessionSetupDeliveryPayload() error = %v", err)
	}

	encoded[keyOffset] ^= 0x01

	if bytes.Equal(viewKeyData, keyData) {
		t.Fatal("view key data should reflect backing-buffer mutation")
	}
	if !bytes.Equal(clonedKeyData, keyData) {
		t.Fatal("cloned key data should remain unchanged")
	}
}
