package download

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/p2p/hub"
)

func TestSendFrameWithReconnectSucceedsAfterRetry(t *testing.T) {
	sender := &stubFrameSender{failFirst: true}
	ops := &stubStreamOps{}

	err := sendFrameWithReconnect(context.Background(), sender, ops, time.Second, []byte("frame"))
	if err != nil {
		t.Fatalf("send frame with reconnect: %v", err)
	}
	if sender.calls != 2 {
		t.Fatalf("expected two send attempts, got %d", sender.calls)
	}
	if ops.resetCalls != 1 || ops.openCalls != 1 {
		t.Fatalf("unexpected reconnect counts reset=%d open=%d", ops.resetCalls, ops.openCalls)
	}
}

func TestSendFrameWithReconnectFailsWhenOpenFails(t *testing.T) {
	sender := &stubFrameSender{failAlways: true}
	ops := &stubStreamOps{openErr: errors.New("open failed")}

	err := sendFrameWithReconnect(context.Background(), sender, ops, time.Second, []byte("frame"))
	if err == nil {
		t.Fatal("expected reconnect error")
	}
	if ops.resetCalls != 1 || ops.openCalls != 1 {
		t.Fatalf("unexpected reconnect counts reset=%d open=%d", ops.resetCalls, ops.openCalls)
	}
}

func TestHolderSendFrameDelegatesToReconnectHelper(t *testing.T) {
	holder := &HolderService{
		cfg:       Config{MaxFrameSize: 1024, SendTimeout: time.Second},
		streamOps: &noopStreamOps{},
	}
	sender := &stubFrameSender{}
	err := holder.sendFrame(context.Background(), sender, frameKindShardEnd, []byte("payload"))
	if err != nil {
		t.Fatalf("holder send frame: %v", err)
	}
	if sender.calls != 1 {
		t.Fatalf("expected one send attempt, got %d", sender.calls)
	}
}

func TestManagerSendPullRequestDelegatesToReconnectHelper(t *testing.T) {
	manager := &Manager{
		cfg:       Config{MaxFrameSize: 1024, SendTimeout: time.Second},
		streamOps: &noopStreamOps{},
	}
	sender := &stubFrameSender{}
	err := manager.sendPullRequest(context.Background(), sender, pullRequestFrame{
		UploadID:   "upload-1",
		RequestID:  "req-1",
		ShardIndex: 0,
	})
	if err != nil {
		t.Fatalf("manager send pull request: %v", err)
	}
	if sender.calls != 1 {
		t.Fatalf("expected one send attempt, got %d", sender.calls)
	}
}

func TestManagerSendPullRequestRejectsBadRequestID(t *testing.T) {
	manager := &Manager{cfg: Config{MaxFrameSize: 1024, SendTimeout: time.Second}}
	sender := &stubFrameSender{}
	err := manager.sendPullRequest(context.Background(), sender, pullRequestFrame{
		UploadID:   "upload-1",
		RequestID:  "",
		ShardIndex: 0,
	})
	if err == nil {
		t.Fatal("expected invalid request id error")
	}
}

type stubFrameSender struct {
	calls      int
	failFirst  bool
	failAlways bool
}

func (s *stubFrameSender) Send(context.Context, []byte) (int, error) {
	s.calls++
	if s.failAlways {
		return 0, errors.New("send failed")
	}
	if s.failFirst && s.calls == 1 {
		return 0, errors.New("send failed")
	}
	return 1, nil
}

func (s *stubFrameSender) ID() hub.ReceptorID { return hub.ReceptorID("receptor-1") }

type stubStreamOps struct {
	resetCalls int
	openCalls  int
	openErr    error
}

func (s *stubStreamOps) ResetStream(hub.ReceptorID) error {
	s.resetCalls++
	return nil
}

func (s *stubStreamOps) OpenStream(context.Context, hub.ReceptorID) error {
	s.openCalls++
	return s.openErr
}

func (s *stubStreamOps) ID() hub.ReceptorID { return hub.ReceptorID("receptor-1") }

type noopStreamOps struct{}

func (n *noopStreamOps) ResetStream(hub.ReceptorID) error { return nil }

func (n *noopStreamOps) OpenStream(context.Context, hub.ReceptorID) error { return nil }

func (n *noopStreamOps) ID() hub.ReceptorID { return hub.ReceptorID("noop") }
