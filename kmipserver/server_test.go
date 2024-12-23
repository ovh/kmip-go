package kmipserver_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/ovh/kmip-go"
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
		return &payloads.ActivateResponsePayload{UniqueIdentifier: *req.UniqueIdentifier}, nil
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
	require.ErrorContains(t, err, ttlv.EnumStr(kmip.ReasonItemNotFound))
}

func TestServerRequest_Panic(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		panic("FAILURE")
	}))

	resp, err := client.Activate("foobar").Exec()
	require.Nil(t, resp)
	require.ErrorContains(t, err, ttlv.EnumStr(kmip.ReasonGeneralFailure))
}

func TestServerRequest_UnsupportedOperation(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	resp, err := client.Activate("foobar").Exec()
	require.Nil(t, resp)
	require.ErrorContains(t, err, ttlv.EnumStr(kmip.ReasonOperationNotSupported))
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
	require.Equal(t, kmip.StatusOperationFailed, resp.BatchItem[0].ResultStatus)
	require.Equal(t, kmip.ReasonInvalidMessage, resp.BatchItem[0].ResultReason)
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
	require.Equal(t, kmip.StatusOperationFailed, resp.BatchItem[0].ResultStatus)
	require.Equal(t, kmip.ReasonInvalidMessage, resp.BatchItem[0].ResultReason)
}
