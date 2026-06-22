package download

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/p2p/hub"
)

type frameSender interface {
	Send(ctx context.Context, payload []byte) (int, error)
	ID() hub.ReceptorID
}

type streamReopener interface {
	ResetStream(id hub.ReceptorID) error
	OpenStream(ctx context.Context, id hub.ReceptorID) error
}

func sendFrameWithReconnect(
	ctx context.Context,
	sender frameSender,
	ops streamReopener,
	sendTimeout time.Duration,
	parts ...[]byte,
) error {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		var sendErr error
		for _, part := range parts {
			if len(part) == 0 {
				continue
			}
			sendCtx, cancel := context.WithTimeout(ctx, sendTimeout)
			_, err := sender.Send(sendCtx, part)
			cancel()
			if err != nil {
				sendErr = err
				break
			}
		}
		if sendErr == nil {
			return nil
		}
		lastErr = sendErr
		_ = ops.ResetStream(sender.ID())
		openCtx, openCancel := context.WithTimeout(ctx, sendTimeout)
		openErr := ops.OpenStream(openCtx, sender.ID())
		openCancel()
		if openErr != nil {
			lastErr = fmt.Errorf("send error: %v; open stream error: %w", sendErr, openErr)
			break
		}
	}
	return lastErr
}

func writeAll(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	written := 0
	for written < len(payload) {
		n, err := w.Write(payload[written:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		written += n
	}
	return nil
}
