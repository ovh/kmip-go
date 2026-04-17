package kmipserver_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"

	"github.com/stretchr/testify/require"
)

func TestServerConnection(t *testing.T) {
	client := kmiptest.NewClientAndServer(t, kmipserver.NewBatchExecutor())
	require.Equal(t, kmip.V1_4, client.Version())
}

func TestServerRequest(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		return &payloads.ActivateResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
	}))

	resp, err := client.Activate("foobar").Exec()
	require.NoError(t, err)
	require.Equal(t, "foobar", resp.UniqueIdentifier)
}

func TestServerRequest_Error(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		return nil, kmipserver.ErrItemNotFound
	}))

	resp, err := client.Activate("foobar").Exec()
	require.Nil(t, resp)
	require.ErrorContains(t, err, ttlv.EnumStr(kmip.ResultReasonItemNotFound))
}

func TestServerRequest_Panic(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		panic("FAILURE")
	}))

	resp, err := client.Activate("foobar").Exec()
	require.Nil(t, resp)
	require.ErrorContains(t, err, ttlv.EnumStr(kmip.ResultReasonGeneralFailure))
}

func TestServerRequest_UnsupportedOperation(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	resp, err := client.Activate("foobar").Exec()
	require.Nil(t, resp)
	require.ErrorContains(t, err, ttlv.EnumStr(kmip.ResultReasonOperationNotSupported))
}

func TestServerRequest_ContextCancelled(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	canceled := false

	wg := new(sync.WaitGroup)
	wg.Add(1)

	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		defer wg.Done()
		tm := time.NewTimer(10 * time.Second)
		defer tm.Stop()
		select {
		case <-tm.C:
			t.Fatal("Timer expired before context")
		case <-ctx.Done():
			canceled = true
			return nil, ctx.Err()
		}
		panic("unreachable")
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	resp, err := client.Activate("foobar").ExecContext(ctx)
	wg.Wait()
	require.True(t, canceled)
	require.Nil(t, resp)
	require.Error(t, err)
}

func TestServerRequest_BadRequest(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	addr, ca := kmiptest.NewServer(t, mux)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM([]byte(ca))
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs: caPool,
	})
	require.NoError(t, err)
	defer conn.Close()

	enc := ttlv.NewTTLVEncoder()
	enc.TextString(0x01, "foobar")
	_, err = conn.Write(enc.Bytes())
	require.NoError(t, err)

	stream := ttlv.NewStream(conn, -1)
	resp := &kmip.ResponseMessage{}
	err = stream.Recv(&resp)
	require.NoError(t, err)
	require.Len(t, resp.BatchItem, 1)
	require.Equal(t, kmip.ResultStatusOperationFailed, resp.BatchItem[0].ResultStatus)
	require.Equal(t, kmip.ResultReasonInvalidMessage, resp.BatchItem[0].ResultReason)
}

func TestServerWithMaxMessageSize(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		return &payloads.ActivateResponsePayload{UniqueIdentifier: pl.UniqueIdentifier}, nil
	}))

	t.Run("rejects request exceeding max size", func(t *testing.T) {
		certPEM, keyPEM, err := kmiptest.GenerateSelfSignedCertPEM()
		require.NoError(t, err)

		ln, srvAddr := kmiptest.ListenWithCert(t, certPEM, keyPEM)
		srv := kmipserver.NewServer(ln, mux).
			WithMaxMessageSize(16) // too small for any real request

		go func() { _ = srv.Serve() }()
		t.Cleanup(func() { _ = srv.Shutdown() })

		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(certPEM)
		conn, err := tls.Dial("tcp", srvAddr, &tls.Config{RootCAs: caPool})
		require.NoError(t, err)
		defer conn.Close()

		// Send a valid KMIP request that exceeds 16 bytes
		stream := ttlv.NewStream(conn, -1)
		msg := kmip.NewRequestMessage(kmip.V1_4, &payloads.ActivateRequestPayload{UniqueIdentifier: "foobar"})
		err = stream.Send(&msg)
		require.NoError(t, err)

		// Server rejects the oversized message and returns an error response
		resp := &kmip.ResponseMessage{}
		err = stream.Recv(resp)
		require.NoError(t, err)
		require.Len(t, resp.BatchItem, 1)
		require.Equal(t, kmip.ResultStatusOperationFailed, resp.BatchItem[0].ResultStatus)
		require.Contains(t, resp.BatchItem[0].ResultMessage, "too big")
	})

	t.Run("accepts request within max size", func(t *testing.T) {
		addr, ca := kmiptest.NewServer(t, mux) // default 1 MB
		client, err := kmipclient.Dial(addr, kmipclient.WithRootCAPem([]byte(ca)))
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		resp, err := client.Activate("foobar").Exec()
		require.NoError(t, err)
		require.Equal(t, "foobar", resp.UniqueIdentifier)
	})
}

func TestServerRequest_BadRequestMessageContent(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	addr, ca := kmiptest.NewServer(t, mux)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM([]byte(ca))
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs: caPool,
	})
	require.NoError(t, err)
	defer conn.Close()

	enc := ttlv.NewTTLVEncoder()
	enc.Struct(kmip.TagRequestMessage, func(e *ttlv.Encoder) {
		e.TextString(kmip.TagRequestHeader, "foobar")
	})
	_, err = conn.Write(enc.Bytes())
	require.NoError(t, err)

	stream := ttlv.NewStream(conn, -1)
	resp := &kmip.ResponseMessage{}
	err = stream.Recv(&resp)
	require.NoError(t, err)
	require.Len(t, resp.BatchItem, 1)
	require.Equal(t, kmip.ResultStatusOperationFailed, resp.BatchItem[0].ResultStatus)
	require.Equal(t, kmip.ResultReasonInvalidMessage, resp.BatchItem[0].ResultReason)
}
