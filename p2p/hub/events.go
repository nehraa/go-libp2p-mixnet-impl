package hub

import (
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// ReceptorID uniquely identifies a receptor within a hub.
type ReceptorID string

// EventKind identifies a hub lifecycle or data event.
type EventKind string

const (
	EventKindReceptorCreated EventKind = "receptor_created"
	EventKindReceptorRemoved EventKind = "receptor_removed"
	EventKindStreamOpened    EventKind = "stream_opened"
	EventKindStreamClosed    EventKind = "stream_closed"
	EventKindDataReceived    EventKind = "data_received"
	EventKindMetricsUpdated  EventKind = "metrics_updated"
	EventKindPeerOffline     EventKind = "peer_offline"
	EventKindError           EventKind = "error"
)

// Event reports receptor lifecycle, stream, and data changes.
type Event struct {
	Kind          EventKind
	ReceptorID    ReceptorID
	PeerID        peer.ID
	StreamID      string
	Data          []byte
	Snapshot      Snapshot
	Err           error
	IsFirstPacket bool
	OccurredAt    time.Time
}

// MetricKind identifies a metrics update published by the hub.
type MetricKind string

const (
	MetricKindReceptorCreated  MetricKind = "receptor_created"
	MetricKindReceptorRemoved  MetricKind = "receptor_removed"
	MetricKindStreamOpened     MetricKind = "stream_opened"
	MetricKindStreamClosed     MetricKind = "stream_closed"
	MetricKindFirstPacket      MetricKind = "first_packet"
	MetricKindPeerOffline      MetricKind = "peer_offline"
	MetricKindPingSucceeded    MetricKind = "ping_succeeded"
	MetricKindPingFailed       MetricKind = "ping_failed"
	MetricKindConnectFailed    MetricKind = "connect_failed"
	MetricKindStreamOpenFailed MetricKind = "stream_open_failed"
	MetricKindReadFailed       MetricKind = "read_failed"
	MetricKindWriteFailed      MetricKind = "write_failed"
	MetricKindEventDropped     MetricKind = "event_dropped"
	MetricKindBackpressure     MetricKind = "backpressure_reset"
)

// MetricUpdate reports receptor snapshots on the dedicated observability path.
type MetricUpdate struct {
	Kind       MetricKind
	ReceptorID ReceptorID
	PeerID     peer.ID
	StreamID   string
	Snapshot   Snapshot
	Err        error
	OccurredAt time.Time
}
