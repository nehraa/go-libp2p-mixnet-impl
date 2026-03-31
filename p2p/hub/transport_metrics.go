package hub

import (
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/pion/webrtc/v4"
	"github.com/quic-go/quic-go"
	webtransport "github.com/quic-go/webtransport-go"
)

// TransportDetails describes transport-specific state exposed by a connection.
type TransportDetails struct {
	AddressFamily            string
	ProtocolStack            []string
	DetailedMetricsAvailable bool
	TCP                      TCPTransportDetails
	QUIC                     *QUICTransportDetails
	WebTransport             *WebTransportTransportDetails
	WebRTC                   *WebRTCTransportDetails
	WebSocket                *WebSocketTransportDetails
}

// TCPTransportDetails describes TCP-specific capability signals.
type TCPTransportDetails struct {
	KernelMetricsAvailable bool
}

// QUICTransportDetails describes QUIC connection state.
type QUICTransportDetails struct {
	Version                        string
	HandshakeComplete              bool
	DidResume                      bool
	Used0RTT                       bool
	SupportsDatagramsLocal         bool
	SupportsDatagramsRemote        bool
	SupportsPartialDeliveryLocal   bool
	SupportsPartialDeliveryRemote  bool
	GenericSegmentationOffloadUsed bool
}

// WebTransportTransportDetails describes WebTransport session state.
type WebTransportTransportDetails struct {
	ApplicationProtocol            string
	HandshakeComplete              bool
	DidResume                      bool
	Used0RTT                       bool
	SupportsDatagramsLocal         bool
	SupportsDatagramsRemote        bool
	SupportsPartialDeliveryLocal   bool
	SupportsPartialDeliveryRemote  bool
	GenericSegmentationOffloadUsed bool
}

// WebRTCTransportDetails describes WebRTC connection and candidate-pair state.
type WebRTCTransportDetails struct {
	PeerConnectionState             string
	ICEConnectionState              string
	ICEGatheringState               string
	SignalingState                  string
	SCTPTransportState              string
	SelectedCandidatePairAvailable  bool
	SelectedLocalCandidateType      string
	SelectedRemoteCandidateType     string
	SelectedLocalCandidateProtocol  string
	SelectedRemoteCandidateProtocol string
	SelectedLocalCandidateAddress   string
	SelectedRemoteCandidateAddress  string
	CandidatePairCurrentRTT         time.Duration
	CandidatePairBytesSent          uint64
	CandidatePairBytesReceived      uint64
	CandidatePairOutgoingBitrate    float64
	CandidatePairIncomingBitrate    float64
	SCTPBytesSent                   uint64
	SCTPBytesReceived               uint64
}

// WebSocketTransportDetails describes websocket connection state.
type WebSocketTransportDetails struct {
	Secure bool
}

func buildTransportDetails(conn network.Conn) TransportDetails {
	if conn == nil {
		return TransportDetails{}
	}

	remoteAddr := conn.RemoteMultiaddr()
	details := TransportDetails{
		AddressFamily: addressFamilyFromMultiaddr(remoteAddr),
		ProtocolStack: protocolStack(remoteAddr),
		TCP: TCPTransportDetails{
			KernelMetricsAvailable: false,
		},
	}

	switch conn.ConnState().Transport {
	case "tcp":
		return details
	case "websocket":
		details.WebSocket = &WebSocketTransportDetails{
			Secure: multiaddrHasProtocol(remoteAddr, ma.P_TLS),
		}
		return details
	case "quic", "quic-v1":
		if quicDetails, ok := extractQUICDetails(conn); ok {
			details.DetailedMetricsAvailable = true
			details.QUIC = quicDetails
		}
		return details
	case "webtransport":
		if transportDetails, ok := extractWebTransportDetails(conn); ok {
			details.DetailedMetricsAvailable = true
			details.WebTransport = transportDetails
		}
		return details
	case "webrtc-direct":
		if webRTCDetails, ok := extractWebRTCDetails(conn); ok {
			details.DetailedMetricsAvailable = true
			details.WebRTC = webRTCDetails
		}
		return details
	default:
		return details
	}
}

func extractQUICDetails(conn network.Conn) (*QUICTransportDetails, bool) {
	var qconn *quic.Conn
	if !conn.As(&qconn) || qconn == nil {
		return nil, false
	}

	state := qconn.ConnectionState()
	return &QUICTransportDetails{
		Version:                        state.Version.String(),
		HandshakeComplete:              state.TLS.HandshakeComplete,
		DidResume:                      state.TLS.DidResume,
		Used0RTT:                       state.Used0RTT,
		SupportsDatagramsLocal:         state.SupportsDatagrams.Local,
		SupportsDatagramsRemote:        state.SupportsDatagrams.Remote,
		SupportsPartialDeliveryLocal:   state.SupportsStreamResetPartialDelivery.Local,
		SupportsPartialDeliveryRemote:  state.SupportsStreamResetPartialDelivery.Remote,
		GenericSegmentationOffloadUsed: state.GSO,
	}, true
}

func extractWebTransportDetails(conn network.Conn) (*WebTransportTransportDetails, bool) {
	var session *webtransport.Session
	if !conn.As(&session) || session == nil {
		return nil, false
	}

	state := session.SessionState()
	return &WebTransportTransportDetails{
		ApplicationProtocol:            state.ApplicationProtocol,
		HandshakeComplete:              state.ConnectionState.TLS.HandshakeComplete,
		DidResume:                      state.ConnectionState.TLS.DidResume,
		Used0RTT:                       state.ConnectionState.Used0RTT,
		SupportsDatagramsLocal:         state.ConnectionState.SupportsDatagrams.Local,
		SupportsDatagramsRemote:        state.ConnectionState.SupportsDatagrams.Remote,
		SupportsPartialDeliveryLocal:   state.ConnectionState.SupportsStreamResetPartialDelivery.Local,
		SupportsPartialDeliveryRemote:  state.ConnectionState.SupportsStreamResetPartialDelivery.Remote,
		GenericSegmentationOffloadUsed: state.ConnectionState.GSO,
	}, true
}

func extractWebRTCDetails(conn network.Conn) (*WebRTCTransportDetails, bool) {
	var pc *webrtc.PeerConnection
	if !conn.As(&pc) || pc == nil {
		return nil, false
	}

	details := &WebRTCTransportDetails{
		PeerConnectionState: pc.ConnectionState().String(),
		ICEConnectionState:  pc.ICEConnectionState().String(),
		ICEGatheringState:   pc.ICEGatheringState().String(),
		SignalingState:      pc.SignalingState().String(),
	}

	if sctp := pc.SCTP(); sctp != nil {
		details.SCTPTransportState = sctp.State().String()
		if dtls := sctp.Transport(); dtls != nil {
			if iceTransport := dtls.ICETransport(); iceTransport != nil {
				pair, err := iceTransport.GetSelectedCandidatePair()
				if err == nil && pair != nil {
					details.SelectedCandidatePairAvailable = true
					details.SelectedLocalCandidateType = pair.Local.Typ.String()
					details.SelectedRemoteCandidateType = pair.Remote.Typ.String()
					details.SelectedLocalCandidateProtocol = pair.Local.Protocol.String()
					details.SelectedRemoteCandidateProtocol = pair.Remote.Protocol.String()
					details.SelectedLocalCandidateAddress = pair.Local.Address
					details.SelectedRemoteCandidateAddress = pair.Remote.Address
				}
			}
		}
	}

	for _, stat := range pc.GetStats() {
		switch typed := stat.(type) {
		case webrtc.ICECandidatePairStats:
			if !typed.Nominated && !details.SelectedCandidatePairAvailable {
				continue
			}
			if !typed.Nominated && typed.BytesSent+typed.BytesReceived == 0 {
				continue
			}
			details.CandidatePairCurrentRTT = time.Duration(typed.CurrentRoundTripTime * float64(time.Second))
			details.CandidatePairBytesSent = typed.BytesSent
			details.CandidatePairBytesReceived = typed.BytesReceived
			details.CandidatePairOutgoingBitrate = typed.AvailableOutgoingBitrate
			details.CandidatePairIncomingBitrate = typed.AvailableIncomingBitrate
		case webrtc.SCTPTransportStats:
			details.SCTPBytesSent = typed.BytesSent
			details.SCTPBytesReceived = typed.BytesReceived
		}
	}

	return details, true
}

func addressFamilyFromMultiaddr(addr ma.Multiaddr) string {
	switch {
	case multiaddrHasProtocol(addr, ma.P_IP4):
		return "ip4"
	case multiaddrHasProtocol(addr, ma.P_IP6):
		return "ip6"
	default:
		return ""
	}
}

func protocolStack(addr ma.Multiaddr) []string {
	protocols := addr.Protocols()
	stack := make([]string, 0, len(protocols))
	for _, protocol := range protocols {
		stack = append(stack, protocol.Name)
	}
	return stack
}

func multiaddrHasProtocol(addr ma.Multiaddr, code int) bool {
	if addr == nil {
		return false
	}
	_, err := addr.ValueForProtocol(code)
	return err == nil
}
