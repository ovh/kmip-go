package kmipclient_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"
	"github.com/stretchr/testify/require"
)

func TestWithDialerPool(t *testing.T) {
	keyid := "8d857fd6-61c0-434a-bd53-f478bd72360b"
	router1 := kmipserver.NewBatchExecutor()
	router1.Route(kmip.OperationLocate, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.LocateRequestPayload) (*payloads.LocateResponsePayload, error) {
		slog.Info("server locate")
		var nbItem int32 = 1
		return &payloads.LocateResponsePayload{
			LocatedItems:     &nbItem,
			UniqueIdentifier: []string{keyid},
		}, nil
	}))

	addr1, ca1 := kmiptest.NewServer(t, router1)

	router2 := kmipserver.NewBatchExecutor()
	addr2, ca2 := kmiptest.NewServer(t, router2)

	client, err := kmipclient.DialCluster([]string{addr1, addr2},
		kmipclient.WithRetryTimeout(1*time.Second),
		kmipclient.WithRootCAPem([]byte(ca1)),
		kmipclient.WithRootCAPem([]byte(ca2)),
	)

	_, err = client.Request(context.Background(), &payloads.DiscoverVersionsRequestPayload{})
	require.NoError(t, err)
	resp, err := client.Locate().Exec()
	require.NoError(t, err)
	require.Equal(t, int32(1), *resp.LocatedItems)
	require.Equal(t, keyid, resp.UniqueIdentifier[0])
	// assert.True(t, false)
}

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

	// Handle DiscoverVersions operation for protocol version negotiation
	if len(req.BatchItem) > 0 && req.BatchItem[0].Operation == kmip.OperationDiscoverVersions {
		bi := kmip.ResponseBatchItem{
			Operation:         kmip.OperationDiscoverVersions,
			UniqueBatchItemID: req.BatchItem[0].UniqueBatchItemID,
			ResultStatus:      kmip.ResultStatusSuccess,
			ResponsePayload: &payloads.DiscoverVersionsResponsePayload{
				ProtocolVersion: []kmip.ProtocolVersion{kmip.V1_4, kmip.V1_3, kmip.V1_2, kmip.V1_1, kmip.V1_0},
			},
		}
		return &kmip.ResponseMessage{Header: header, BatchItem: []kmip.ResponseBatchItem{bi}}
	}

	// For Query operations, return response with VendorIdentification set to the handler ID
	if len(req.BatchItem) > 0 && req.BatchItem[0].Operation == kmip.OperationQuery {
		bi := kmip.ResponseBatchItem{
			Operation:         kmip.OperationQuery,
			UniqueBatchItemID: req.BatchItem[0].UniqueBatchItemID,
			ResultStatus:      kmip.ResultStatusSuccess,
			ResponsePayload: &payloads.QueryResponsePayload{
				VendorIdentification: h.id,
			},
		}
		return &kmip.ResponseMessage{Header: header, BatchItem: []kmip.ResponseBatchItem{bi}}
	}

	// Default fallback for unhandled operations
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
	client, err := kmipclient.DialCluster(addrs,
		kmipclient.WithRootCAPem(combinedCA),
		kmipclient.WithRetryTimeout(5*time.Second))
	require.NoError(t, err)
	require.NotNil(t, client)

	// build a simple request
	req := kmip.NewRequestMessage(kmip.V1_4, &payloads.QueryRequestPayload{})

	// first call should hit the first server
	resp, err := client.Roundtrip(context.Background(), &req)
	require.NoError(t, err)
	require.Equal(t, addrs[0], resp.BatchItem[0].ResponsePayload.(*payloads.QueryResponsePayload).VendorIdentification)

	// stop the first server
	require.NoError(t, servers[0].Shutdown())

	// allow some time for the listener to close and lastError to be recorded
	time.Sleep(20 * time.Millisecond)

	// next call should fallback to one of the remaining servers (addr[1] most likely)
	resp2, err := client.Roundtrip(context.Background(), &req)
	require.NoError(t, err)
	require.Equal(t, addrs[1], resp2.BatchItem[0].ResponsePayload.(*payloads.QueryResponsePayload).VendorIdentification)

	// stop the second server
	require.NoError(t, servers[1].Shutdown())
	// allow some time for the listener to close and lastError to be recorded
	time.Sleep(20 * time.Millisecond)

	// next call should fallback to the last remaining server (addrs[2])
	resp3, err := client.Roundtrip(context.Background(), &req)
	require.NoError(t, err)
	require.Equal(t, addrs[2], resp3.BatchItem[0].ResponsePayload.(*payloads.QueryResponsePayload).VendorIdentification)
}

func TestClientConnectionPool_PrimaryUpNoFallback(t *testing.T) {
	addrs := make([]string, 0, 1)
	var combinedCA []byte
	h := &simpleHandler{}
	addr, ca := kmiptest.NewServer(t, h)
	h.id = addr
	addrs = append(addrs, addr)
	combinedCA = append(combinedCA, []byte(ca)...)

	exec, err := kmipclient.DialCluster(addrs,
		kmipclient.WithRootCAPem(combinedCA),
		kmipclient.WithRetryTimeout(50*time.Millisecond))
	require.NoError(t, err)

	req := kmip.NewRequestMessage(kmip.V1_4, &payloads.QueryRequestPayload{})
	resp, err := exec.Roundtrip(context.Background(), &req)
	require.NoError(t, err)
	require.Equal(t, addrs[0], resp.BatchItem[0].ResponsePayload.(*payloads.QueryResponsePayload).VendorIdentification)
}

func TestClientConnectionPool_AllDownError(t *testing.T) {
	// Start one server then stop it to ensure all endpoints are down
	h := &simpleHandler{}
	addr, ca, srv := kmiptest.NewServerWithHandle(t, h)
	h.id = addr
	// stop immediately
	require.NoError(t, srv.Shutdown())

	// Now that the client does version negotiation on dial, we expect the DialCluster to fail
	// since the server is already shut down
	_, err := kmipclient.DialCluster([]string{addr},
		kmipclient.WithRootCAPem([]byte(ca)),
		kmipclient.WithRetryTimeout(10*time.Millisecond))
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
	go srv.Serve()

	exec, err := kmipclient.DialCluster([]string{addr},
		kmipclient.WithRootCAPem(certPEM),
		kmipclient.WithRetryTimeout(40*time.Millisecond))
	require.NoError(t, err)

	req := kmip.NewRequestMessage(kmip.V1_4, &payloads.QueryRequestPayload{})
	// initial call should work
	resp, err := exec.Roundtrip(context.Background(), &req)
	require.NoError(t, err)
	require.Equal(t, addr, resp.BatchItem[0].ResponsePayload.(*payloads.QueryResponsePayload).VendorIdentification)

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
	go srv2.Serve()
	// give some time for client to consider endpoint retriable
	time.Sleep(60 * time.Millisecond)

	resp2, err := exec.Roundtrip(context.Background(), &req)
	require.NoError(t, err)
	require.Equal(t, addr, resp2.BatchItem[0].ResponsePayload.(*payloads.QueryResponsePayload).VendorIdentification)
	_ = srv2.Shutdown()
}
