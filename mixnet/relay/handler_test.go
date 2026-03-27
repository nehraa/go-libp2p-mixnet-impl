package relay

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

func TestReadEncryptedFrameHeaderAndPayload(t *testing.T) {
	const circuitID = "cid-1"
	const version = frameVersionFullOnion
	payload := []byte("hello relay")

	var frame bytes.Buffer
	frame.WriteByte(byte(len(circuitID)))
	frame.WriteString(circuitID)
	frame.WriteByte(version)
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	frame.Write(lenBuf[:])
	frame.Write(payload)

	reader := bufio.NewReader(bytes.NewReader(frame.Bytes()))
	gotCircuitID, gotVersion, gotLen, err := readEncryptedFrameHeader(reader)
	if err != nil {
		t.Fatalf("readEncryptedFrameHeader() error = %v", err)
	}
	if gotCircuitID != circuitID {
		t.Fatalf("circuitID = %q, want %q", gotCircuitID, circuitID)
	}
	if gotVersion != version {
		t.Fatalf("version = %d, want %d", gotVersion, version)
	}
	if gotLen != len(payload) {
		t.Fatalf("payloadLen = %d, want %d", gotLen, len(payload))
	}

	gotPayload, release, err := readEncryptedFramePayload(reader, nil, gotLen)
	if err != nil {
		t.Fatalf("readEncryptedFramePayload() error = %v", err)
	}
	defer release()

	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload = %q, want %q", gotPayload, payload)
	}
}

func TestReadSessionDataControlPrefix(t *testing.T) {
	baseID := "session-123"
	auth := []byte("auth")
	data := []byte("payload")
	seq := uint64(42)

	var encoded bytes.Buffer
	encoded.WriteByte(byte(len(baseID)))
	encoded.WriteString(baseID)
	encoded.WriteByte(sessionDataFlagSequenced)
	var seqBuf [8]byte
	binary.LittleEndian.PutUint64(seqBuf[:], seq)
	encoded.Write(seqBuf[:])
	var metaBuf [10]byte
	binary.LittleEndian.PutUint16(metaBuf[8:], uint16(len(auth)))
	encoded.Write(metaBuf[:])
	encoded.Write(auth)
	encoded.Write(data)

	reader := bufio.NewReader(bytes.NewReader(encoded.Bytes()))
	gotBaseID, prefix, gotDataLen, err := readSessionDataControlPrefix(reader, encoded.Len(), nil)
	if err != nil {
		t.Fatalf("readSessionDataControlPrefix() error = %v", err)
	}
	if gotBaseID != baseID {
		t.Fatalf("baseID = %q, want %q", gotBaseID, baseID)
	}
	if gotDataLen != len(data) {
		t.Fatalf("dataLen = %d, want %d", gotDataLen, len(data))
	}
	if !bytes.Equal(prefix, encoded.Bytes()[:len(encoded.Bytes())-len(data)]) {
		t.Fatalf("prefix mismatch")
	}
}

func TestAssembleRelayPayload(t *testing.T) {
	payload, release := assembleRelayPayload([]byte("a"), []byte("bc"), []byte("def"))
	defer release()

	if got, want := string(payload), "abcdef"; got != want {
		t.Fatalf("assembled payload = %q, want %q", got, want)
	}
}

func TestDecodeSessionSetupFramePayloadViewAvoidsCloning(t *testing.T) {
	baseID := "session-setup"
	encryptedHeader := []byte("encrypted-header")
	keyData := []byte("key-material")

	encoded, err := encodeSessionSetupFramePayload(baseID, sessionRouteModeHeaderOnly, encryptedHeader, keyData)
	if err != nil {
		t.Fatalf("encodeSessionSetupFramePayload() error = %v", err)
	}

	headerOffset := 1 + len(baseID) + 1 + 4
	keyOffset := headerOffset + len(encryptedHeader) + 4

	_, _, viewHeader, viewKeyData, err := decodeSessionSetupFramePayloadView(encoded)
	if err != nil {
		t.Fatalf("decodeSessionSetupFramePayloadView() error = %v", err)
	}
	_, _, clonedHeader, clonedKeyData, err := decodeSessionSetupFramePayload(encoded)
	if err != nil {
		t.Fatalf("decodeSessionSetupFramePayload() error = %v", err)
	}

	encoded[headerOffset] ^= 0x01
	encoded[keyOffset] ^= 0x01

	if bytes.Equal(viewHeader, encryptedHeader) {
		t.Fatal("view encrypted header should reflect backing-buffer mutation")
	}
	if bytes.Equal(viewKeyData, keyData) {
		t.Fatal("view key data should reflect backing-buffer mutation")
	}
	if !bytes.Equal(clonedHeader, encryptedHeader) {
		t.Fatal("cloned encrypted header should remain unchanged")
	}
	if !bytes.Equal(clonedKeyData, keyData) {
		t.Fatal("cloned key data should remain unchanged")
	}
}
