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

func TestTimeoutMiddleware_Expire(t *testing.T) {
	router := kmipserver.NewBatchExecutor()
	router.Route(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
		t.Fatal("Timer should not have expired")
		return nil, nil
	}))

	addr, ca := kmiptest.NewServer(t, router)

	netExec, err := kmipclient.Dial(addr, kmipclient.WithRootCAPem([]byte(ca)), kmipclient.WithMiddlewares(
		kmipclient.TimeoutMiddleware(5*time.Second),
	))
	require.NoError(t, err)
	client, err := kmipclient.NewClient(
		kmipclient.WithClientNetworkExecutor(netExec),
	)
	require.NoError(t, err)

	_, err = client.Activate("foobar").Exec()
	require.Error(t, err)
}

func TestTimeoutMiddleware_NoExpire(t *testing.T) {
	router := kmipserver.NewBatchExecutor()
	router.Route(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		return &payloads.ActivateResponsePayload{}, nil
	}))

	addr, ca := kmiptest.NewServer(t, router)

	netExec, err := kmipclient.Dial(addr, kmipclient.WithRootCAPem([]byte(ca)), kmipclient.WithMiddlewares(
		kmipclient.TimeoutMiddleware(5*time.Second),
	))
	require.NoError(t, err)
	client, err := kmipclient.NewClient(
		kmipclient.WithClientNetworkExecutor(netExec),
	)
	require.NoError(t, err)
	_, err = client.Activate("foobar").Exec()
	require.NoError(t, err)
}

func TestTimeoutMiddleware_ZeroTimeout(t *testing.T) {
	router := kmipserver.NewBatchExecutor()
	router.Route(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		timer := time.NewTimer(1 * time.Second)
		defer timer.Stop()

		select {
		case <-ctx.Done():
			t.Fatal("Timeout should not have happened")
		case <-timer.C:
		}

		return &payloads.ActivateResponsePayload{}, nil
	}))

	addr, ca := kmiptest.NewServer(t, router)

	netExec, err := kmipclient.Dial(addr, kmipclient.WithRootCAPem([]byte(ca)), kmipclient.WithMiddlewares(
		kmipclient.TimeoutMiddleware(0),
	))
	require.NoError(t, err)
	client, err := kmipclient.NewClient(
		kmipclient.WithClientNetworkExecutor(netExec),
	)
	require.NoError(t, err)
	_, err = client.Activate("foobar").Exec()
	require.NoError(t, err)
}
