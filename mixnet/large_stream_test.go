package mixnet

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"
)

func TestLargeHeaderOnlyStream1MB(t *testing.T) {
	cfg := &MixnetConfig{
		HopCount:               1,
		CircuitCount:           1,
		Compression:            "gzip",
		UseCESPipeline:         false,
		EncryptionMode:         EncryptionModeHeaderOnly,
		HeaderPaddingEnabled:   false,
		PayloadPaddingStrategy: PaddingStrategyNone,
		EnableAuthTag:          false,
		SelectionMode:          SelectionModeRandom,
		SamplingSize:           3,
		RandomnessFactor:       0.3,
		MaxJitter:              0,
	}

	t.Setenv("MIXNET_MAX_ENCRYPTED_PAYLOAD", "134217728")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	origin, dest, _, cleanup := setupMixnetNetwork(t, ctx, cfg, 3)
	defer cleanup()

	originStream, err := origin.OpenStream(ctx, dest.Host().ID())
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer originStream.Close()

	acceptCh := make(chan *MixStream, 1)
	errCh := make(chan error, 1)
	go func() {
		s, err := dest.AcceptStream(ctx)
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- s
	}()

	payload := bytes.Repeat([]byte("a"), 1024*1024)
	const chunkSize = 256 * 1024

	for offset := 0; offset < len(payload); offset += chunkSize {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		if _, err := originStream.Write(payload[offset:end]); err != nil {
			t.Fatalf("write chunk %d-%d: %v", offset, end, err)
		}
	}

	var destStream *MixStream
	select {
	case err := <-errCh:
		t.Fatalf("accept stream: %v", err)
	case destStream = <-acceptCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for accept stream")
	}
	defer destStream.Close()

	readDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, chunkSize)
		out := make([]byte, 0, len(payload))
		for len(out) < len(payload) {
			n, err := destStream.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			out = append(out, buf[:n]...)
		}
		readDone <- out[:len(payload)]
	}()

	select {
	case err := <-errCh:
		t.Fatalf("large stream read failed: %v", err)
	case out := <-readDone:
		if !bytes.Equal(out, payload) {
			t.Fatal("payload mismatch")
		}
	case <-time.After(15 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("timeout reading 1MB payload\n%s", string(buf[:n]))
	}
}

func TestMultiWriteStreamAcrossCircuits(t *testing.T) {
	modes := []struct {
		name           string
		mode           EncryptionMode
		useCSE         bool
		sessionRouting bool
	}{
		{name: "header-only", mode: EncryptionModeHeaderOnly},
		{name: "full", mode: EncryptionModeFull},
		{name: "header-only-cse", mode: EncryptionModeHeaderOnly, useCSE: true},
		{name: "full-cse", mode: EncryptionModeFull, useCSE: true},
		{name: "header-only-routed", mode: EncryptionModeHeaderOnly, sessionRouting: true},
		{name: "full-routed", mode: EncryptionModeFull, sessionRouting: true},
		{name: "header-only-cse-routed", mode: EncryptionModeHeaderOnly, useCSE: true, sessionRouting: true},
		{name: "full-cse-routed", mode: EncryptionModeFull, useCSE: true, sessionRouting: true},
	}
	circuitCounts := []int{2, 3}

	for _, tc := range modes {
		for _, circuitCount := range circuitCounts {
			t.Run(fmt.Sprintf("%s-c%d", tc.name, circuitCount), func(t *testing.T) {
				cfg := &MixnetConfig{
					HopCount:                2,
					CircuitCount:            circuitCount,
					Compression:             "gzip",
					UseCESPipeline:          false,
					UseCSE:                  tc.useCSE,
					EnableSessionRouting:    tc.sessionRouting,
					SessionRouteIdleTimeout: 2 * time.Second,
					EncryptionMode:          tc.mode,
					HeaderPaddingEnabled:    false,
					PayloadPaddingStrategy:  PaddingStrategyNone,
					EnableAuthTag:           false,
					SelectionMode:           SelectionModeRandom,
					SamplingSize:            6,
					RandomnessFactor:        0.3,
					MaxJitter:               0,
				}

				t.Setenv("MIXNET_MAX_ENCRYPTED_PAYLOAD", "134217728")

				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()

				origin, dest, _, cleanup := setupMixnetNetwork(t, ctx, cfg, cfg.HopCount*cfg.CircuitCount*3)
				defer cleanup()

				originStream, err := origin.OpenStream(ctx, dest.Host().ID())
				if err != nil {
					t.Fatalf("open stream: %v", err)
				}
				defer originStream.Close()

				acceptCh := make(chan *MixStream, 1)
				errCh := make(chan error, 1)
				go func() {
					s, err := dest.AcceptStream(ctx)
					if err != nil {
						errCh <- err
						return
					}
					acceptCh <- s
				}()

				pattern := []byte(fmt.Sprintf("%s-c%d|", tc.name, circuitCount))
				payload := bytes.Repeat(pattern, (1024*1024/len(pattern))+1)
				payload = payload[:1024*1024]
				const chunkSize = 256 * 1024

				for offset := 0; offset < len(payload); offset += chunkSize {
					end := offset + chunkSize
					if end > len(payload) {
						end = len(payload)
					}
					if _, err := originStream.Write(payload[offset:end]); err != nil {
						t.Fatalf("write chunk %d-%d: %v", offset, end, err)
					}
				}

				var destStream *MixStream
				select {
				case err := <-errCh:
					t.Fatalf("accept stream: %v", err)
				case destStream = <-acceptCh:
				case <-time.After(5 * time.Second):
					t.Fatal("timeout waiting for accept stream")
				}
				defer destStream.Close()

				readDone := make(chan []byte, 1)
				go func() {
					buf := make([]byte, chunkSize)
					out := make([]byte, 0, len(payload))
					for len(out) < len(payload) {
						n, err := destStream.Read(buf)
						if err != nil {
							errCh <- err
							return
						}
						out = append(out, buf[:n]...)
					}
					readDone <- out[:len(payload)]
				}()

				select {
				case err := <-errCh:
					t.Fatalf("multi-write read failed: %v", err)
				case out := <-readDone:
					if !bytes.Equal(out, payload) {
						t.Fatal("payload mismatch")
					}
				case <-time.After(15 * time.Second):
					t.Fatal("timeout reading multi-write payload")
				}
			})
		}
	}
}

func TestLargeMultiWriteHeaderOnlyCSE16MB(t *testing.T) {
	cfg := &MixnetConfig{
		HopCount:               2,
		CircuitCount:           3,
		Compression:            "gzip",
		UseCESPipeline:         false,
		UseCSE:                 true,
		EncryptionMode:         EncryptionModeHeaderOnly,
		HeaderPaddingEnabled:   false,
		PayloadPaddingStrategy: PaddingStrategyNone,
		EnableAuthTag:          false,
		SelectionMode:          SelectionModeRandom,
		SamplingSize:           6,
		RandomnessFactor:       0.3,
		MaxJitter:              0,
	}

	t.Setenv("MIXNET_MAX_ENCRYPTED_PAYLOAD", "1073741824")

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	origin, dest, _, cleanup := setupMixnetNetwork(t, ctx, cfg, cfg.HopCount*cfg.CircuitCount*3)
	defer cleanup()

	originStream, err := origin.OpenStream(ctx, dest.Host().ID())
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer originStream.Close()

	acceptCh := make(chan *MixStream, 1)
	errCh := make(chan error, 1)
	go func() {
		s, err := dest.AcceptStream(ctx)
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- s
	}()

	pattern := []byte("header-only-cse-c3-")
	payload := bytes.Repeat(pattern, (16*1024*1024/len(pattern))+1)
	payload = payload[:16*1024*1024]
	const chunkSize = 256 * 1024

	for offset := 0; offset < len(payload); offset += chunkSize {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		if _, err := originStream.Write(payload[offset:end]); err != nil {
			t.Fatalf("write chunk %d-%d: %v", offset, end, err)
		}
	}

	var destStream *MixStream
	select {
	case err := <-errCh:
		t.Fatalf("accept stream: %v", err)
	case destStream = <-acceptCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for accept stream")
	}
	defer destStream.Close()

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, chunkSize)
		received := 0
		for received < len(payload) {
			n, err := destStream.Read(buf)
			if err != nil {
				readDone <- err
				return
			}
			end := received + n
			if end > len(payload) {
				readDone <- fmt.Errorf("payload overflow: got=%d want=%d", end, len(payload))
				return
			}
			if !bytes.Equal(buf[:n], payload[received:end]) {
				readDone <- fmt.Errorf("payload mismatch at offset %d", received)
				return
			}
			received = end
		}
		readDone <- nil
	}()

	select {
	case err := <-errCh:
		t.Fatalf("large multi-write read failed: %v", err)
	case err := <-readDone:
		if err != nil {
			t.Fatalf("large multi-write verification failed: %v", err)
		}
	case <-time.After(30 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("timeout reading large multi-write payload\n%s", string(buf[:n]))
	}
}
