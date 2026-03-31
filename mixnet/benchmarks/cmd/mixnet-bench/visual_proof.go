package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	mixnet "github.com/libp2p/go-libp2p/mixnet/core"
	"github.com/libp2p/go-libp2p/mixnet/relay"
)

const visualProofPayloadSize = 64 * 1024

type visualProofScenario struct {
	ID                 string             `json:"id"`
	Title              string             `json:"title"`
	Message            string             `json:"message"`
	PayloadSizeBytes   int                `json:"payload_size_bytes"`
	PayloadPreviewText string             `json:"payload_preview_text"`
	EnableSessionRoute bool               `json:"enable_session_routing"`
	Path               []visualProofPeer  `json:"path"`
	Events             []visualProofEvent `json:"events"`
}

type visualProofPeer struct {
	Role   string `json:"role"`
	PeerID string `json:"peer_id"`
}

type visualProofEvent struct {
	Order            int    `json:"order"`
	Role             string `json:"role"`
	NodePeer         string `json:"node_peer"`
	Stage            string `json:"stage"`
	ObservedFrom     string `json:"observed_from"`
	ObservedTo       string `json:"observed_to"`
	Frame            string `json:"frame"`
	BaseSessionID    string `json:"base_session_id,omitempty"`
	PayloadLength    int    `json:"payload_length"`
	WirePreviewHex   string `json:"wire_preview_hex,omitempty"`
	WirePreviewText  string `json:"wire_preview_text,omitempty"`
	KnowsSource      string `json:"knows_source"`
	KnowsDestination string `json:"knows_destination"`
	Notes            string `json:"notes,omitempty"`
}

type visualProofCollector struct {
	mu       sync.Mutex
	next     int
	roleByID map[string]string
	destID   string
	events   []visualProofEvent
}

func runQuickVisualProof(opts suiteOptions) ([]visualProofScenario, error) {
	payload := makeVisualProofPayload(visualProofPayloadSize)
	proofs := make([]visualProofScenario, 0, 2)
	cases := []struct {
		id    string
		title string
		sc    scenario
	}{
		{
			id:    "header-only-routed",
			title: "Visual proof: header-only routed stream (64KB live message)",
			sc:    newRoutedStreamMixnetScenario("proof-header-routed", groupFocusedOnion, "proof", "header-only", 2, 1, false),
		},
		{
			id:    "full-onion-legacy",
			title: "Visual proof: full onion legacy stream (64KB live message)",
			sc:    newStreamMixnetScenario("proof-full-legacy", groupFocusedOnion, "proof", "full", 2, 1, false),
		},
	}

	for _, item := range cases {
		proof, err := captureVisualProof(item.id, item.title, item.sc, payload, opts.Timeout)
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, proof)
	}
	return proofs, nil
}

func captureVisualProof(id, title string, sc scenario, payload []byte, timeout time.Duration) (visualProofScenario, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cfg, err := sc.config()
	if err != nil {
		return visualProofScenario{}, err
	}
	network, err := setupBenchmarkNetwork(ctx, cfg, cfg.HopCount*cfg.CircuitCount*3)
	if err != nil {
		return visualProofScenario{}, err
	}
	defer network.cleanup()

	circuits, err := network.origin.EstablishConnection(ctx, network.dest.Host().ID())
	if err != nil {
		return visualProofScenario{}, fmt.Errorf("visual proof establish connection: %w", err)
	}
	if err := network.origin.EnsureCircuitKeysForBenchmark(ctx, circuits); err != nil {
		return visualProofScenario{}, fmt.Errorf("visual proof ensure circuit keys: %w", err)
	}
	if len(circuits) == 0 {
		return visualProofScenario{}, fmt.Errorf("visual proof missing circuit")
	}

	path := make([]visualProofPeer, 0, len(circuits[0].Peers)+2)
	path = append(path, visualProofPeer{Role: "origin", PeerID: network.origin.Host().ID().String()})
	for idx, relayPeer := range circuits[0].Peers {
		path = append(path, visualProofPeer{Role: fmt.Sprintf("relay %d", idx+1), PeerID: relayPeer.String()})
	}
	path = append(path, visualProofPeer{Role: "destination", PeerID: network.dest.Host().ID().String()})

	collector := newVisualProofCollector(path, network.dest.Host().ID())
	for _, relayMix := range network.relays {
		relayMix.RelayHandler().SetObservationHandler(collector.addRelayObservation)
	}
	network.dest.SetDeliveryObservationHandler(collector.addDeliveryObservation)

	readDone := make(chan error, 1)
	go func() {
		stream, err := network.dest.AcceptStream(ctx)
		if err != nil {
			readDone <- err
			return
		}
		defer stream.Close()
		data, err := readMixnetPayload(stream, len(payload))
		if err != nil {
			readDone <- err
			return
		}
		collector.addAppObservation(data)
		readDone <- nil
	}()

	collector.addOriginObservation(network.dest.Host().ID(), payload, sc.EnableSessionRouting)
	stream, err := network.origin.OpenStream(ctx, network.dest.Host().ID())
	if err != nil {
		return visualProofScenario{}, fmt.Errorf("visual proof open stream: %w", err)
	}
	if _, err := stream.Write(payload); err != nil {
		_ = stream.Close()
		return visualProofScenario{}, fmt.Errorf("visual proof write: %w", err)
	}
	if err := stream.Close(); err != nil {
		return visualProofScenario{}, fmt.Errorf("visual proof close: %w", err)
	}

	select {
	case err := <-readDone:
		if err != nil {
			return visualProofScenario{}, fmt.Errorf("visual proof receive: %w", err)
		}
	case <-ctx.Done():
		return visualProofScenario{}, ctx.Err()
	}

	time.Sleep(150 * time.Millisecond)

	return visualProofScenario{
		ID:                 id,
		Title:              title,
		Message:            string(payload[:minInt(96, len(payload))]),
		PayloadSizeBytes:   len(payload),
		PayloadPreviewText: sanitizePreviewText(payload),
		EnableSessionRoute: sc.EnableSessionRouting,
		Path:               path,
		Events:             collector.snapshot(),
	}, nil
}

func newVisualProofCollector(path []visualProofPeer, dest peer.ID) *visualProofCollector {
	roleByID := make(map[string]string, len(path))
	for _, hop := range path {
		roleByID[hop.PeerID] = hop.Role
	}
	return &visualProofCollector{
		roleByID: roleByID,
		destID:   dest.String(),
	}
}

func (c *visualProofCollector) snapshot() []visualProofEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := append([]visualProofEvent(nil), c.events...)
	sort.Slice(out, func(i, j int) bool { return out[i].Order < out[j].Order })
	return out
}

func (c *visualProofCollector) addOriginObservation(dest peer.ID, payload []byte, routed bool) {
	frame := "mixnet stream write"
	notes := "origin knows the final destination peer and the cleartext application payload"
	if routed {
		notes = "origin will trigger one routed setup frame and then one routed data frame for this 64KB write"
	}
	c.appendEvent(visualProofEvent{
		Role:             "origin",
		NodePeer:         c.nodeForRole("origin"),
		Stage:            "origin send",
		ObservedFrom:     c.nodeForRole("origin"),
		ObservedTo:       dest.String(),
		Frame:            frame,
		PayloadLength:    len(payload),
		WirePreviewHex:   previewHexBytes(payload),
		WirePreviewText:  sanitizePreviewText(payload),
		KnowsSource:      "self",
		KnowsDestination: fmt.Sprintf("final destination %s", dest),
		Notes:            notes,
	})
}

func (c *visualProofCollector) addRelayObservation(obs relay.FrameObservation) {
	role, ok := c.roleByID[obs.NodePeer]
	if !ok {
		return
	}
	destKnowledge := "none"
	if obs.OutboundPeer != "" {
		if obs.IsFinal {
			destKnowledge = fmt.Sprintf("final destination %s", obs.OutboundPeer)
		} else {
			destKnowledge = fmt.Sprintf("next hop only %s", obs.OutboundPeer)
		}
	}
	sourceKnowledge := "none"
	if obs.InboundPeer != "" {
		sourceKnowledge = fmt.Sprintf("immediate upstream only %s", obs.InboundPeer)
	}
	notes := fmt.Sprintf("payload=%dB", obs.PayloadLength)
	if obs.RouteMode != "" {
		notes = fmt.Sprintf("%s, payload=%dB", obs.RouteMode, obs.PayloadLength)
	}
	c.appendEvent(visualProofEvent{
		Role:             role,
		NodePeer:         obs.NodePeer,
		Stage:            "relay forward",
		ObservedFrom:     obs.InboundPeer,
		ObservedTo:       obs.OutboundPeer,
		Frame:            obs.FrameLabel,
		BaseSessionID:    obs.BaseSessionID,
		PayloadLength:    obs.PayloadLength,
		WirePreviewHex:   obs.WirePreviewHex,
		WirePreviewText:  obs.WirePreviewText,
		KnowsSource:      sourceKnowledge,
		KnowsDestination: destKnowledge,
		Notes:            notes,
	})
}

func (c *visualProofCollector) addDeliveryObservation(obs mixnet.FinalDeliveryObservation) {
	role, ok := c.roleByID[obs.NodePeer]
	if !ok {
		return
	}
	sessionNotes := fmt.Sprintf("payload=%dB", obs.PayloadLength)
	if obs.BaseSessionID != "" {
		sessionNotes = fmt.Sprintf("baseSession=%s, payload=%dB", obs.BaseSessionID, obs.PayloadLength)
	}
	c.appendEvent(visualProofEvent{
		Role:             role,
		NodePeer:         obs.NodePeer,
		Stage:            "destination inbound",
		ObservedFrom:     obs.InboundPeer,
		ObservedTo:       obs.NodePeer,
		Frame:            obs.MessageType,
		BaseSessionID:    obs.BaseSessionID,
		PayloadLength:    obs.PayloadLength,
		WirePreviewHex:   obs.WirePreviewHex,
		WirePreviewText:  obs.WirePreviewText,
		KnowsSource:      fmt.Sprintf("immediate upstream only %s", obs.InboundPeer),
		KnowsDestination: fmt.Sprintf("self %s", obs.NodePeer),
		Notes:            sessionNotes,
	})
}

func (c *visualProofCollector) addAppObservation(payload []byte) {
	c.appendEvent(visualProofEvent{
		Role:             "destination app",
		NodePeer:         c.destID,
		Stage:            "application receive",
		ObservedFrom:     c.destID,
		ObservedTo:       c.destID,
		Frame:            "delivered cleartext stream chunk",
		PayloadLength:    len(payload),
		WirePreviewHex:   previewHexBytes(payload),
		WirePreviewText:  sanitizePreviewText(payload),
		KnowsSource:      "app gets payload only, not the origin transport peer",
		KnowsDestination: fmt.Sprintf("self %s", c.destID),
		Notes:            "this is the first point where the 64KB message is readable as application text",
	})
}

func (c *visualProofCollector) appendEvent(event visualProofEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next++
	event.Order = c.next
	c.events = append(c.events, event)
}

func (c *visualProofCollector) nodeForRole(role string) string {
	for id, current := range c.roleByID {
		if current == role {
			return id
		}
	}
	return ""
}

func makeVisualProofPayload(size int) []byte {
	base := []byte("hello world this is what each node sees in the live mixnet proof. ")
	out := make([]byte, 0, size)
	for len(out) < size {
		out = append(out, base...)
	}
	return out[:size]
}

func sanitizePreviewText(data []byte) string {
	text := previewTextBytes(data)
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	return text
}

func writeVisualProofFiles(outputDir string, proofs []visualProofScenario) error {
	if len(proofs) == 0 {
		return nil
	}
	jsonData, err := json.MarshalIndent(proofs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "visual_proof.json"), jsonData, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "visual_proof.txt"), renderVisualProofText(proofs), 0o644)
}

func renderVisualProofText(proofs []visualProofScenario) []byte {
	var out bytes.Buffer
	for _, proof := range proofs {
		fmt.Fprintf(&out, "%s\n", proof.Title)
		fmt.Fprintf(&out, "payload: %s\n", formatBytes(proof.PayloadSizeBytes))
		fmt.Fprintf(&out, "payload preview: %q\n", proof.PayloadPreviewText)
		fmt.Fprintf(&out, "path: %s\n", renderProofPath(proof.Path))
		for _, event := range proof.Events {
			fmt.Fprintf(&out, "%d. %s [%s]\n", event.Order, event.Role, event.Frame)
			fmt.Fprintf(&out, "   from: %s\n", fallbackString(event.ObservedFrom))
			fmt.Fprintf(&out, "   to: %s\n", fallbackString(event.ObservedTo))
			if event.BaseSessionID != "" {
				fmt.Fprintf(&out, "   base session: %s\n", event.BaseSessionID)
			}
			fmt.Fprintf(&out, "   wire hex: %s\n", fallbackString(event.WirePreviewHex))
			fmt.Fprintf(&out, "   wire text: %s\n", fallbackString(event.WirePreviewText))
			fmt.Fprintf(&out, "   knows source: %s\n", event.KnowsSource)
			fmt.Fprintf(&out, "   knows destination: %s\n", event.KnowsDestination)
			if event.Notes != "" {
				fmt.Fprintf(&out, "   notes: %s\n", event.Notes)
			}
		}
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func renderProofPath(path []visualProofPeer) string {
	parts := make([]string, 0, len(path))
	for _, hop := range path {
		parts = append(parts, fmt.Sprintf("%s=%s", hop.Role, hop.PeerID))
	}
	return strings.Join(parts, " -> ")
}

func fallbackString(value string) string {
	if strings.TrimSpace(value) == "" {
		return "(none)"
	}
	return value
}

func previewHexBytes(data []byte) string {
	const previewLimit = 24
	if len(data) == 0 {
		return ""
	}
	if len(data) > previewLimit {
		data = data[:previewLimit]
	}
	out := make([]byte, 0, len(data)*3)
	for i, b := range data {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, "0123456789abcdef"[b>>4], "0123456789abcdef"[b&0x0f])
	}
	return string(out)
}

func previewTextBytes(data []byte) string {
	const previewLimit = 24
	if len(data) == 0 {
		return ""
	}
	if len(data) > previewLimit {
		data = data[:previewLimit]
	}
	out := make([]byte, len(data))
	for i, b := range data {
		if b >= 32 && b <= 126 {
			out[i] = b
			continue
		}
		out[i] = '.'
	}
	return string(out)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
