package relay

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/libp2p/go-libp2p/mixnet/noiseframe"
)

func runNoiseXXResponder(ctx context.Context, stream network.Stream) ([]byte, error) {
	return noiseframe.RunXXResponder(ctx, stream)
}

func decodeKeyExchangePayload(data []byte) (string, []byte, error) {
	if len(data) < 1+2 {
		return "", nil, fmt.Errorf("payload too short")
	}
	pos := 0
	idLen := int(data[pos])
	pos++
	if len(data) < pos+idLen+2 {
		return "", nil, fmt.Errorf("payload truncated")
	}
	circuitID := string(data[pos : pos+idLen])
	pos += idLen
	keyLen := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if len(data) < pos+keyLen {
		return "", nil, fmt.Errorf("payload truncated (key)")
	}
	key := make([]byte, keyLen)
	copy(key, data[pos:pos+keyLen])
	return circuitID, key, nil
}

