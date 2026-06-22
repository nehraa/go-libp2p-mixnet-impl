// Package upload provides a configurable shard upload mechanism on top of
// libp2p streams.
//
// The sender side uses p2p/hub receptors for one-peer-per-shard fan-out.
// The receiver side uses a plain stream handler for the upload protocol and
// persists received shards directly to storage.
package upload
