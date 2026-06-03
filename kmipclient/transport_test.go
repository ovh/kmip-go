package kmipclient_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"

	"github.com/stretchr/testify/require"
)

// TestStreamTransport_ResponseTooLarge confirms the stream transport surfaces
// oversized responses as ErrResponseTooLarge, matching the HTTP transport.
func TestStreamTransport_ResponseTooLarge(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(
		func(_ context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
			// Pad the UID so the encoded response exceeds the client's cap.
			return &payloads.ActivateResponsePayload{
				UniqueIdentifier: strings.Repeat("a", 4096),
			}, nil
		}))

	addr, ca := kmiptest.NewServer(t, mux)
	client, err := kmipclient.Dial(addr,
		kmipclient.WithRootCAPem([]byte(ca)),
		// EnforceVersion skips DiscoverVersions, whose response size is
		// independent of the test and could exceed the cap on its own.
		kmipclient.EnforceVersion(kmip.V1_4),
		kmipclient.WithMaxMessageSize(512),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Activate("uid").Exec()
	require.ErrorIs(t, err, kmipclient.ErrResponseTooLarge)
}

// TestStreamTransport_CloseBlocksDuringInFlight pins down the documented
// behavior of streamTransport.Close: it blocks until the in-flight RoundTrip
// releases the per-transport mutex, and the way to abort sooner is to cancel
// the RoundTrip context.
func TestStreamTransport_CloseBlocksDuringInFlight(t *testing.T) {
	started := make(chan struct{})

	mux := kmipserver.NewBatchExecutor()
	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(
		func(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}))

	addr, ca := kmiptest.NewServer(t, mux)
	client, err := kmipclient.Dial(addr, kmipclient.WithRootCAPem([]byte(ca)))
	require.NoError(t, err)

	rtCtx, rtCancel := context.WithCancel(context.Background())
	defer rtCancel()

	rtDone := make(chan struct{})
	go func() {
		_, _ = client.Activate("inflight").ExecContext(rtCtx)
		close(rtDone)
	}()

	// Wait for the handler to start, proving the RoundTrip is in flight and
	// holds the streamTransport mutex.
	<-started

	closeReturned := make(chan error, 1)
	var closeStarted atomic.Bool
	go func() {
		closeStarted.Store(true)
		closeReturned <- client.Close()
	}()

	// Spin until the Close goroutine has at least entered Close.
	require.Eventually(t, closeStarted.Load, time.Second, time.Millisecond)

	// Close must remain blocked on the in-flight RoundTrip's mutex.
	select {
	case err := <-closeReturned:
		t.Fatalf("Close returned while RoundTrip in flight: err=%v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Cancelling the RoundTrip context releases the mutex; Close can now finish.
	rtCancel()
	<-rtDone

	select {
	case err := <-closeReturned:
		// Close may surface the underlying read error from the cancelled
		// RoundTrip; the contract we care about is that it eventually returns.
		_ = err
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after RoundTrip completed")
	}
}

// TestStreamTransport_DoubleClose pins down Close idempotency: a second Close
// must not panic or error, and a RoundTrip after Close must return
// net.ErrClosed without dialing.
func TestStreamTransport_DoubleClose(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(
		func(_ context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
			return &payloads.ActivateResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
		}))

	addr, ca := kmiptest.NewServer(t, mux)
	client, err := kmipclient.Dial(addr, kmipclient.WithRootCAPem([]byte(ca)))
	require.NoError(t, err)

	require.NoError(t, client.Close())
	require.NoError(t, client.Close(), "second Close must be idempotent")

	_, err = client.Activate("after-close").Exec()
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestStreamTransport_CloneAfterClose(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(
		func(_ context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
			return &payloads.ActivateResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
		}))

	addr, ca := kmiptest.NewServer(t, mux)
	client, err := kmipclient.Dial(addr, kmipclient.WithRootCAPem([]byte(ca)))
	require.NoError(t, err)

	require.NoError(t, client.Close())

	clone, err := client.Clone()
	require.NoError(t, err, "Clone must succeed after Close")
	t.Cleanup(func() { _ = clone.Close() })

	resp, err := clone.Activate("after-close-clone").Exec()
	require.NoError(t, err)
	require.Equal(t, "after-close-clone", resp.UniqueIdentifier)

	_, err = client.Activate("still-closed").Exec()
	require.ErrorIs(t, err, net.ErrClosed)
}

// TestStreamTransport_RecoversAfterResponseTooLarge verifies that a RoundTrip
// returning ErrResponseTooLarge leaves the transport in a usable state: a
// subsequent request that fits within the cap must succeed instead of
// inheriting the previous run's cached terminate cause.
func TestStreamTransport_RecoversAfterResponseTooLarge(t *testing.T) {
	var big atomic.Bool
	mux := kmipserver.NewBatchExecutor()
	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(
		func(_ context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
			if big.Load() {
				return &payloads.ActivateResponsePayload{
					UniqueIdentifier: strings.Repeat("a", 4096),
				}, nil
			}
			return &payloads.ActivateResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
		}))

	addr, ca := kmiptest.NewServer(t, mux)
	client, err := kmipclient.Dial(addr,
		kmipclient.WithRootCAPem([]byte(ca)),
		kmipclient.EnforceVersion(kmip.V1_4),
		kmipclient.WithMaxMessageSize(512),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// First call trips the cap.
	big.Store(true)
	_, err = client.Activate("uid").Exec()
	require.ErrorIs(t, err, kmipclient.ErrResponseTooLarge)

	// Second call with a small response must succeed — not surface a cached
	// ErrResponseTooLarge from the poisoned previous conn.
	big.Store(false)
	resp, err := client.Activate("ok").Exec()
	require.NoError(t, err)
	require.Equal(t, "ok", resp.UniqueIdentifier)
	require.False(t, errors.Is(err, kmipclient.ErrResponseTooLarge))
}

func TestWithTransportBuilder_NilRejected(t *testing.T) {
	_, err := kmipclient.Dial("127.0.0.1:1", kmipclient.WithTransportBuilder(nil))
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil TransportBuilder")
}

// TestDialContext_AggregatesOptionErrors: a caller with multiple bad options
// sees them all at once via errors.Join instead of fixing one per Dial.
func TestDialContext_AggregatesOptionErrors(t *testing.T) {
	_, err := kmipclient.Dial("127.0.0.1:1",
		kmipclient.WithRootCAFile("/__kmipclient_test/__missing_a"),
		kmipclient.WithRootCAFile("/__kmipclient_test/__missing_b"),
		kmipclient.WithTransportBuilder(nil),
	)
	require.Error(t, err)
	msg := err.Error()
	require.Contains(t, msg, "__missing_a")
	require.Contains(t, msg, "__missing_b")
	require.Contains(t, msg, "nil TransportBuilder")
}

func TestDialClusterContext_AggregatesOptionErrors(t *testing.T) {
	_, err := kmipclient.DialCluster([]string{"127.0.0.1:1", "127.0.0.1:2"},
		kmipclient.WithRootCAFile("/__kmipclient_test/__missing_a"),
		kmipclient.WithRootCAFile("/__kmipclient_test/__missing_b"),
	)
	require.Error(t, err)
	msg := err.Error()
	require.Contains(t, msg, "__missing_a")
	require.Contains(t, msg, "__missing_b")
}

// TestWithTransportBuilder_ErrorPropagates: builder errors surface verbatim
// from Dial — sub-packages rely on this to defer validation to dial time.
func TestWithTransportBuilder_ErrorPropagates(t *testing.T) {
	sentinel := errors.New("custom transport refused to build")
	_, err := kmipclient.Dial("127.0.0.1:1",
		kmipclient.WithTransportBuilder(func(context.Context, kmipclient.DialInfo) (kmipclient.Transport, error) {
			return nil, sentinel
		}),
	)
	require.ErrorIs(t, err, sentinel)
}

// TestWithTransportBuilder_ReceivesContext pins the DialInfo fields builder
// authors depend on — if any stops being filled in, custom transports silently
// break.
func TestWithTransportBuilder_ReceivesContext(t *testing.T) {
	var captured kmipclient.DialInfo
	sentinel := errors.New("captured")
	_, err := kmipclient.Dial("kms.example.com:5696",
		kmipclient.WithMaxMessageSize(1234),
		kmipclient.WithRootCAPem([]byte("---not a real ca---")),
		kmipclient.WithTransportBuilder(func(_ context.Context, info kmipclient.DialInfo) (kmipclient.Transport, error) {
			captured = info
			return nil, sentinel
		}),
	)
	require.ErrorIs(t, err, sentinel)
	require.Equal(t, "kms.example.com:5696", captured.Addr)
	require.Equal(t, 1234, captured.MaxMessageSize)
	require.True(t, captured.TLSConfigured, "TLSConfigured must be true when a TLS option was set")
	require.NotNil(t, captured.TLSConfig, "TLSConfig must be populated when no custom dialer is set")
}

// TestWithTransportBuilder_RejectedByDialCluster: any custom transport — not
// just the kmiphttp adapter — must be rejected by DialCluster.
func TestWithTransportBuilder_RejectedByDialCluster(t *testing.T) {
	builderInvoked := false
	_, err := kmipclient.DialCluster([]string{"127.0.0.1:1", "127.0.0.1:2"},
		kmipclient.WithTransportBuilder(func(context.Context, kmipclient.DialInfo) (kmipclient.Transport, error) {
			builderInvoked = true
			return nil, errors.New("builder must not be invoked")
		}),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "DialCluster")
	require.False(t, builderInvoked, "DialCluster must reject the option without invoking the builder")
}

// TestDialInfo_TLSConfiguredCoversAllSetters guards the invariant on
// opts.hasTLSOptions: every standard TLS setter must trip TLSConfigured, or
// transports gating on it (e.g. kmiphttp.WithClient mutual-exclusivity)
// silently miss the new option. One case per field consulted by hasTLSOptions
// — setters that share a field don't all need their own row. Slice (not map)
// so a missing entry shows up as a deterministic gap in code review rather
// than as a nondeterministic CI flake.
func TestDialInfo_TLSConfiguredCoversAllSetters(t *testing.T) {
	cases := []struct {
		name string
		opt  kmipclient.Option
	}{
		{"WithTlsConfig", kmipclient.WithTlsConfig(&tls.Config{MinVersion: tls.VersionTLS12})},
		{"WithRootCAPem", kmipclient.WithRootCAPem([]byte("---not a real ca---"))},
		{"WithClientCert", kmipclient.WithClientCert(tls.Certificate{})},
		{"WithServerName", kmipclient.WithServerName("kms.example.com")},
		{"WithTlsCipherSuites", kmipclient.WithTlsCipherSuites(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured kmipclient.DialInfo
			sentinel := errors.New("captured")
			_, err := kmipclient.Dial("kms.example.com:5696",
				tc.opt,
				kmipclient.WithTransportBuilder(func(_ context.Context, info kmipclient.DialInfo) (kmipclient.Transport, error) {
					captured = info
					return nil, sentinel
				}),
			)
			require.ErrorIs(t, err, sentinel)
			require.True(t, captured.TLSConfigured, "%s must trip TLSConfigured", tc.name)
		})
	}
}

// recordingTransport is a fake Transport whose RoundTrip returns a canned
// response and records every call.
type recordingTransport struct {
	mu       sync.Mutex
	calls    int
	closed   bool
	response func(*kmip.RequestMessage) (*kmip.ResponseMessage, error)
}

func (r *recordingTransport) RoundTrip(_ context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return r.response(msg)
}

func (r *recordingTransport) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

// Clone returns an independent fake so a future test using Client.Clone can't
// accidentally depend on shared state (e.g. Close affecting both transports).
// The response closure is shared by design — it's the caller's canned behavior.
func (r *recordingTransport) Clone(context.Context) (kmipclient.Transport, error) {
	return &recordingTransport{response: r.response}, nil
}

// TestWithTransportBuilder_Wires: a builder-supplied Transport is actually
// wired into the Client — RoundTrip flows through it and Close delegates back.
// End-to-end coverage of the bare kmipclient.WithTransportBuilder contract,
// without going through the kmiphttp sub-package.
func TestWithTransportBuilder_Wires(t *testing.T) {
	rt := &recordingTransport{
		response: func(req *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
			switch p := req.BatchItem[0].RequestPayload.(type) {
			case *payloads.DiscoverVersionsRequestPayload:
				return &kmip.ResponseMessage{
					Header: kmip.ResponseHeader{
						ProtocolVersion: kmip.V1_4,
						BatchCount:      1,
					},
					BatchItem: []kmip.ResponseBatchItem{{
						Operation:    kmip.OperationDiscoverVersions,
						ResultStatus: kmip.ResultStatusSuccess,
						ResponsePayload: &payloads.DiscoverVersionsResponsePayload{
							ProtocolVersion: []kmip.ProtocolVersion{kmip.V1_4},
						},
					}},
				}, nil
			case *payloads.ActivateRequestPayload:
				return &kmip.ResponseMessage{
					Header: kmip.ResponseHeader{
						ProtocolVersion: kmip.V1_4,
						BatchCount:      1,
					},
					BatchItem: []kmip.ResponseBatchItem{{
						Operation:    kmip.OperationActivate,
						ResultStatus: kmip.ResultStatusSuccess,
						ResponsePayload: &payloads.ActivateResponsePayload{
							UniqueIdentifier: p.UniqueIdentifier,
						},
					}},
				}, nil
			default:
				return nil, fmt.Errorf("recordingTransport: unexpected payload %T", p)
			}
		},
	}

	client, err := kmipclient.Dial("test:1",
		kmipclient.WithTransportBuilder(func(context.Context, kmipclient.DialInfo) (kmipclient.Transport, error) {
			return rt, nil
		}),
	)
	require.NoError(t, err)
	rt.mu.Lock()
	require.GreaterOrEqual(t, rt.calls, 1, "DiscoverVersions must flow through the builder-supplied transport")
	rt.mu.Unlock()

	resp, err := client.Activate("uid").Exec()
	require.NoError(t, err)
	require.Equal(t, "uid", resp.UniqueIdentifier)

	require.NoError(t, client.Close())
	rt.mu.Lock()
	require.True(t, rt.closed, "Client.Close must delegate to the builder-supplied transport")
	rt.mu.Unlock()
}

// TestDialInfo_TLSConfigNilWhenDialerSet: when a custom dialer is configured
// it takes full responsibility for TLS, so TLSConfig must be dropped from the
// info — even if the caller also set a TLS option.
func TestDialInfo_TLSConfigNilWhenDialerSet(t *testing.T) {
	var captured kmipclient.DialInfo
	sentinel := errors.New("captured")
	_, err := kmipclient.Dial("kms.example.com:5696",
		kmipclient.WithServerName("kms.example.com"),
		kmipclient.WithDialerUnsafe(func(context.Context, string) (net.Conn, error) {
			return nil, errors.New("not invoked")
		}),
		kmipclient.WithTransportBuilder(func(_ context.Context, info kmipclient.DialInfo) (kmipclient.Transport, error) {
			captured = info
			return nil, sentinel
		}),
	)
	require.ErrorIs(t, err, sentinel)
	require.NotNil(t, captured.Dialer, "Dialer must be threaded through")
	require.Nil(t, captured.TLSConfig, "TLSConfig must be nil when Dialer is set")
}
