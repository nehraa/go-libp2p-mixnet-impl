package relay

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func BenchmarkDecryptHopPayload(b *testing.B) {
	key := bytes.Repeat([]byte{0x55}, 32)
	plaintext := bytes.Repeat([]byte("mixnet-relay-hop-payload-"), 96)
	ciphertext, err := encryptHopPayloadForBenchmark(key, plaintext)
	if err != nil {
		b.Fatalf("encryptHopPayloadForBenchmark() setup error = %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		buf := append([]byte(nil), ciphertext...)
		if _, err := decryptHopPayload(key, buf, true); err != nil {
			b.Fatalf("decryptHopPayload() error = %v", err)
		}
	}
}

func encryptHopPayloadForBenchmark(key []byte, payload []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, payload, nil), nil
}

func BenchmarkWriteHeaderOnlyFinalPayload(b *testing.B) {
	control := bytes.Repeat([]byte{0x33}, 32)
	payload := bytes.Repeat([]byte("mixnet-relay-final-payload-"), 128)
	var sink bytes.Buffer

	b.ReportAllocs()
	b.SetBytes(int64(len(control) + len(payload) + 1))
	for i := 0; i < b.N; i++ {
		sink.Reset()
		if _, err := writeHeaderOnlyFinalPayload(b.Context(), &sink, control, payload, nil, nil); err != nil {
			b.Fatalf("writeHeaderOnlyFinalPayload() error = %v", err)
		}
	}
}

func BenchmarkReadSessionDataControlPrefix(b *testing.B) {
	baseID := "bench-session"
	auth := bytes.Repeat([]byte{0x44}, 16)
	data := bytes.Repeat([]byte("mixnet-relay-stream-data-"), 128)

	var encoded bytes.Buffer
	encoded.WriteByte(byte(len(baseID)))
	encoded.WriteString(baseID)
	encoded.WriteByte(sessionDataFlagSequenced)
	var seqBuf [8]byte
	binary.LittleEndian.PutUint64(seqBuf[:], 42)
	encoded.Write(seqBuf[:])
	var metaBuf [10]byte
	binary.LittleEndian.PutUint16(metaBuf[8:], uint16(len(auth)))
	encoded.Write(metaBuf[:])
	encoded.Write(auth)
	encoded.Write(data)
	frame := encoded.Bytes()

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		reader := bufio.NewReader(bytes.NewReader(frame))
		baseID, prefix, dataLen, err := readSessionDataControlPrefix(reader, len(frame), nil)
		if err != nil {
			b.Fatalf("readSessionDataControlPrefix() error = %v", err)
		}
		if baseID == "" || len(prefix) == 0 || dataLen != len(data) {
			b.Fatal("unexpected parsed control prefix result")
		}
	}
}

func BenchmarkDecodeSessionSetupFramePayload(b *testing.B) {
	baseID := "bench-session-setup"
	encryptedHeader := bytes.Repeat([]byte{0x55}, 96)
	keyData := bytes.Repeat([]byte{0x66}, 64)
	payload, err := encodeSessionSetupFramePayload(baseID, sessionRouteModeHeaderOnly, encryptedHeader, keyData)
	if err != nil {
		b.Fatalf("encodeSessionSetupFramePayload() setup error = %v", err)
	}

	b.Run("copy", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		for i := 0; i < b.N; i++ {
			gotBaseID, gotMode, gotHeader, gotKeyData, err := decodeSessionSetupFramePayload(payload)
			if err != nil {
				b.Fatalf("decodeSessionSetupFramePayload() error = %v", err)
			}
			if gotBaseID != baseID || gotMode != sessionRouteModeHeaderOnly || len(gotHeader) != len(encryptedHeader) || len(gotKeyData) != len(keyData) {
				b.Fatal("unexpected session setup decode result")
			}
		}
	})

	b.Run("view", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		for i := 0; i < b.N; i++ {
			gotBaseID, gotMode, gotHeader, gotKeyData, err := decodeSessionSetupFramePayloadView(payload)
			if err != nil {
				b.Fatalf("decodeSessionSetupFramePayloadView() error = %v", err)
			}
			if gotBaseID != baseID || gotMode != sessionRouteModeHeaderOnly || len(gotHeader) != len(encryptedHeader) || len(gotKeyData) != len(keyData) {
				b.Fatal("unexpected session setup decode result")
			}
		}
	})
}
