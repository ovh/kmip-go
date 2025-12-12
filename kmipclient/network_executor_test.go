package kmipclient_test

import (
	"context"
	"testing"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"

	"github.com/stretchr/testify/require"
)

type simpleHandler struct {
	id string
}

func (h *simpleHandler) HandleRequest(ctx context.Context, req *kmip.RequestMessage) *kmip.ResponseMessage {
	header := kmip.ResponseHeader{
		ProtocolVersion:        req.Header.ProtocolVersion,
		TimeStamp:              time.Now(),
		BatchCount:             1,
		ClientCorrelationValue: req.Header.ClientCorrelationValue,
	}
	bi := kmip.ResponseBatchItem{
		Operation:         req.BatchItem[0].Operation,
		UniqueBatchItemID: req.BatchItem[0].UniqueBatchItemID,
		ResultStatus:      kmip.ResultStatusSuccess,
		ResultMessage:     h.id,
	}
	return &kmip.ResponseMessage{Header: header, BatchItem: []kmip.ResponseBatchItem{bi}}
}

// TestClientNetworkConnection_Fallback starts three servers and verifies the client falls back
// to the next available server when the first one is shut down.
func TestClientNetworkConnection_Fallback(t *testing.T) {
	// start 3 servers using kmiptest helpers
	addrs := make([]string, 0, 3)
	var combinedCA []byte
	servers := make([]*kmipserver.Server, 3)

	for i := 0; i < 3; i++ {
		h := &simpleHandler{}
		addr, ca, srv := kmiptest.NewServerWithHandle(t, h)
		h.id = addr
		addrs = append(addrs, addr)
		combinedCA = append(combinedCA, []byte(ca)...)
		servers[i] = srv
	}

	// create a client network connection with the three server addresses
	exec, err := kmipclient.DialWithFallbackContext(context.Background(), addrs, 5*time.Second, kmipclient.WithRootCAPem(combinedCA))
	require.NoError(t, err)
	require.NotNil(t, exec)

	// build a simple request
	req := kmip.NewRequestMessage(kmip.V1_4, &payloads.DiscoverVersionsRequestPayload{})

	// first call should hit the first server
	resp, err := exec.Roundtrip(context.Background(), &req)
	require.NoError(t, err)
	require.Equal(t, addrs[0], resp.BatchItem[0].ResultMessage)

	// stop the first server
	require.NoError(t, servers[0].Shutdown())

	// allow some time for the listener to close and lastError to be recorded
	time.Sleep(20 * time.Millisecond)

	// next call should fallback to one of the remaining servers (addr[1] most likely)
	resp2, err := exec.Roundtrip(context.Background(), &req)
	require.NoError(t, err)
	require.Equal(t, addrs[1], resp2.BatchItem[0].ResultMessage)

	// stop the first server
	require.NoError(t, servers[1].Shutdown())
	// allow some time for the listener to close and lastError to be recorded
	time.Sleep(20 * time.Millisecond)

	// next call should fallback to one of the remaining servers (addr[1] most likely)
	resp3, err := exec.Roundtrip(context.Background(), &req)
	require.NoError(t, err)
	require.Equal(t, addrs[2], resp3.BatchItem[0].ResultMessage)
}

func TestClientConnectionPool_PrimaryUpNoFallback(t *testing.T) {
	addrs := make([]string, 0, 1)
	var combinedCA []byte
	h := &simpleHandler{}
	addr, ca := kmiptest.NewServer(t, h)
	h.id = addr
	addrs = append(addrs, addr)
	combinedCA = append(combinedCA, []byte(ca)...)

	exec, err := kmipclient.DialWithFallbackContext(context.Background(), addrs, 50*time.Millisecond, kmipclient.WithRootCAPem(combinedCA))
	require.NoError(t, err)

	req := kmip.NewRequestMessage(kmip.V1_4, &payloads.DiscoverVersionsRequestPayload{})
	resp, err := exec.Roundtrip(context.Background(), &req)
	require.NoError(t, err)
	require.Equal(t, addrs[0], resp.BatchItem[0].ResultMessage)
}

func TestClientConnectionPool_AllDownError(t *testing.T) {
	// Start one server then stop it to ensure all endpoints are down
	h := &simpleHandler{}
	addr, ca, srv := kmiptest.NewServerWithHandle(t, h)
	h.id = addr
	// stop immediately
	require.NoError(t, srv.Shutdown())

	exec, err := kmipclient.DialWithFallbackContext(context.Background(), []string{addr}, 10*time.Millisecond, kmipclient.WithRootCAPem([]byte(ca)))
	require.NoError(t, err)

	req := kmip.NewRequestMessage(kmip.V1_4, &payloads.DiscoverVersionsRequestPayload{})
	_, err = exec.Roundtrip(context.Background(), &req)
	require.Error(t, err)
}

func TestClientConnectionPool_IntermittentRecovery(t *testing.T) {
	// Start server with a reusable TLS listener (generate cert here so we can restart on same addr)
	// generate cert
	certPEM, keyPEM, err := kmiptest.GenerateSelfSignedCertPEM()
	require.NoError(t, err)

	addr := ""
	// start listener and server
	l, a := kmiptest.ListenWithCert(t, certPEM, keyPEM)
	addr = a
	h := &simpleHandler{id: addr}
	srv := kmipserver.NewServer(l, h)
	go func() { _ = srv.Serve() }()

	exec, err := kmipclient.DialWithFallbackContext(context.Background(), []string{addr}, 40*time.Millisecond, kmipclient.WithRootCAPem(certPEM))
	require.NoError(t, err)

	req := kmip.NewRequestMessage(kmip.V1_4, &payloads.DiscoverVersionsRequestPayload{})
	// initial call should work
	resp, err := exec.Roundtrip(context.Background(), &req)
	require.NoError(t, err)
	require.Equal(t, addr, resp.BatchItem[0].ResultMessage)

	// stop server
	require.NoError(t, srv.Shutdown())
	time.Sleep(20 * time.Millisecond)

	// attempt should fail (single endpoint)
	_, err = exec.Roundtrip(context.Background(), &req)
	require.Error(t, err)

	// restart server on same addr using same cert
	l2, _ := kmiptest.ListenWithExistingAddr(t, addr, certPEM, keyPEM)
	h2 := &simpleHandler{id: addr}
	srv2 := kmipserver.NewServer(l2, h2)
	go func() { _ = srv2.Serve() }()
	// give some time for client to consider endpoint retriable
	time.Sleep(60 * time.Millisecond)

	resp2, err := exec.Roundtrip(context.Background(), &req)
	require.NoError(t, err)
	require.Equal(t, addr, resp2.BatchItem[0].ResultMessage)
	_ = srv2.Shutdown()
}
