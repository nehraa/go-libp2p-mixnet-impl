package hub

import (
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	ma "github.com/multiformats/go-multiaddr"
)

// Snapshot is the current receptor state exposed to managers and tests.
type Snapshot struct {
	ReceptorID            ReceptorID
	PeerID                peer.ID
	ProtocolID            protocol.ID
	PeerAddrs             []ma.Multiaddr
	Connectedness         network.Connectedness
	HasActiveStream       bool
	ActiveStreamID        string
	ActiveStreamDirection network.Direction
	Transport             string
	SecurityProtocol      protocol.ID
	StreamMultiplexer     protocol.ID
	ConnectionID          string
	ConnectionCount       int
	ConnectionStreamCount int
	ConnectionDirection   network.Direction
	ConnectionOpenedAt    time.Time
	ConnectionLimited     bool
	LocalMultiaddr        ma.Multiaddr
	RemoteMultiaddr       ma.Multiaddr
	LastRTT               time.Duration
	LatencyEWMA           time.Duration
	BytesSent             uint64
	BytesReceived         uint64
	ConnectAttemptCount   uint64
	ConnectFailureCount   uint64
	StreamOpenCount       uint64
	StreamCloseCount      uint64
	ReconnectCount        uint64
	SendOperationCount    uint64
	ReceiveOperationCount uint64
	PingSuccessCount      uint64
	PingFailureCount      uint64
	ReadErrorCount        uint64
	WriteErrorCount       uint64
	EventDropCount        uint64
	MetricsDropCount      uint64
	BackpressureResets    uint64
	StreamOpenedAt        time.Time
	FirstPacketAt         time.Time
	LastActivityAt        time.Time
	LastSendAt            time.Time
	LastReceiveAt         time.Time
	LastPingSuccessAt     time.Time
	LastPingFailureAt     time.Time
	LastErrorAt           time.Time
	LastError             string
	TransportDetails      TransportDetails
}
