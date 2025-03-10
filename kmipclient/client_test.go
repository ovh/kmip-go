package kmipclient_test

import (
	"context"
	"os"
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

func TestRequest_ContextTimeout(t *testing.T) {
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

func TestActivate(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	req := client.Activate("foobar")
	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		require.EqualValues(t, req.RequestPayload(), pl)
		return &payloads.ActivateResponsePayload{UniqueIdentifier: pl.UniqueIdentifier}, nil
	}))
	resp, err := req.Exec()
	require.NoError(t, err)
	require.Equal(t, "foobar", resp.UniqueIdentifier)

	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		require.EqualValues(t, req.RequestPayload(), pl)
		return nil, kmipserver.ErrItemNotFound
	}))

	resp, err = req.Exec()
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestAddAttribute(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	req := client.AddAttribute("foobar", kmip.AttributeNameName, kmip.Name{NameValue: "foo", NameType: kmip.NameTypeUninterpretedTextString})
	mux.Route(kmip.OperationAddAttribute, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.AddAttributeRequestPayload) (*payloads.AddAttributeResponsePayload, error) {
		require.EqualValues(t, req.RequestPayload(), pl)
		return &payloads.AddAttributeResponsePayload{UniqueIdentifier: pl.UniqueIdentifier, Attribute: pl.Attribute}, nil
	}))
	resp, err := req.Exec()
	require.NoError(t, err)
	require.Equal(t, "foobar", resp.UniqueIdentifier)
	require.Equal(t, req.RequestPayload().Attribute, resp.Attribute)

	req = req.WithIndex(12)
	mux.Route(kmip.OperationAddAttribute, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.AddAttributeRequestPayload) (*payloads.AddAttributeResponsePayload, error) {
		require.EqualValues(t, req.RequestPayload(), pl)
		return &payloads.AddAttributeResponsePayload{UniqueIdentifier: pl.UniqueIdentifier, Attribute: pl.Attribute}, nil
	}))
	resp, err = req.Exec()
	require.NoError(t, err)
	require.Equal(t, "foobar", resp.UniqueIdentifier)
	require.Equal(t, req.RequestPayload().Attribute, resp.Attribute)
}

func TestArchive(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	req := client.Archive("foobar")
	mux.Route(kmip.OperationArchive, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.ArchiveRequestPayload) (*payloads.ArchiveResponsePayload, error) {
		require.EqualValues(t, req.RequestPayload(), pl)
		return &payloads.ArchiveResponsePayload{UniqueIdentifier: pl.UniqueIdentifier}, nil
	}))
	resp, err := req.Exec()
	require.NoError(t, err)
	require.Equal(t, "foobar", resp.UniqueIdentifier)
}

func TestRecover(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	req := client.Recover("foobar")
	mux.Route(kmip.OperationRecover, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.RecoverRequestPayload) (*payloads.RecoverResponsePayload, error) {
		require.EqualValues(t, req.RequestPayload(), pl)
		return &payloads.RecoverResponsePayload{UniqueIdentifier: pl.UniqueIdentifier}, nil
	}))
	resp, err := req.Exec()
	require.NoError(t, err)
	require.Equal(t, "foobar", resp.UniqueIdentifier)
}

func TestCreateKeyPair(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	t.Run("RSA", func(t *testing.T) {
		req := client.CreateKeyPair().RSA(2048, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).
			PrivateKey().WithName("privatekey").
			PublicKey().WithName("publickey")
		mux.Route(kmip.OperationCreateKeyPair, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.CreateKeyPairRequestPayload) (*payloads.CreateKeyPairResponsePayload, error) {
			require.EqualValues(t, req.RequestPayload(), pl)
			return &payloads.CreateKeyPairResponsePayload{PrivateKeyUniqueIdentifier: "foo", PublicKeyUniqueIdentifier: "bar"}, nil
		}))
		resp, err := req.Exec()
		require.NoError(t, err)
		require.Equal(t, "foo", resp.PrivateKeyUniqueIdentifier)
		require.Equal(t, "bar", resp.PublicKeyUniqueIdentifier)
	})

	t.Run("ECDSA", func(t *testing.T) {
		req := client.CreateKeyPair().ECDSA(kmip.RecommendedCurveP_256, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).
			PrivateKey().WithName("privatekey").
			PublicKey().WithName("publickey")
		mux.Route(kmip.OperationCreateKeyPair, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.CreateKeyPairRequestPayload) (*payloads.CreateKeyPairResponsePayload, error) {
			require.EqualValues(t, req.RequestPayload(), pl)
			return &payloads.CreateKeyPairResponsePayload{PrivateKeyUniqueIdentifier: "foo", PublicKeyUniqueIdentifier: "bar"}, nil
		}))
		resp, err := req.Exec()
		require.NoError(t, err)
		require.Equal(t, "foo", resp.PrivateKeyUniqueIdentifier)
		require.Equal(t, "bar", resp.PublicKeyUniqueIdentifier)
	})

}

func TestCreate(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	req := client.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt)
	mux.Route(kmip.OperationCreate, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.CreateRequestPayload) (*payloads.CreateResponsePayload, error) {
		require.EqualValues(t, req.RequestPayload(), pl)
		return &payloads.CreateResponsePayload{UniqueIdentifier: "foobar"}, nil
	}))

	resp, err := req.Exec()
	require.NoError(t, err)
	require.Equal(t, "foobar", resp.UniqueIdentifier)
}

func TestRekey(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	req := client.Rekey("foobar").
		WithOffset(10*time.Minute).
		WithAttribute(kmip.AttributeNameSensitive, true)

	mux.Route(kmip.OperationReKey, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.RekeyRequestPayload) (*payloads.RekeyResponsePayload, error) {
		require.EqualValues(t, req.RequestPayload(), pl)
		return &payloads.RekeyResponsePayload{UniqueIdentifier: pl.UniqueIdentifier}, nil
	}))

	resp := req.MustExec()
	require.EqualValues(t, req.RequestPayload().UniqueIdentifier, resp.UniqueIdentifier)
}

func TestClone(t *testing.T) {
	client1 := kmiptest.NewClientAndServer(t, kmipserver.NewBatchExecutor())
	client2, err := client1.Clone()
	require.NoError(t, err)
	require.NoError(t, client1.Close())

	_, err = client1.Request(context.Background(), &payloads.DiscoverVersionsRequestPayload{})
	require.Error(t, err)

	client3, err := client1.Clone()
	require.NoError(t, err)

	_, err = client2.Request(context.Background(), &payloads.DiscoverVersionsRequestPayload{})
	require.NoError(t, err)
	_, err = client3.Request(context.Background(), &payloads.DiscoverVersionsRequestPayload{})
	require.NoError(t, err)
}

func TestVersionNegociation(t *testing.T) {
	router := kmipserver.NewBatchExecutor()
	router.Route(kmip.OperationDiscoverVersions, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.DiscoverVersionsRequestPayload) (*payloads.DiscoverVersionsResponsePayload, error) {
		return &payloads.DiscoverVersionsResponsePayload{
			ProtocolVersion: []kmip.ProtocolVersion{
				kmip.V1_3, kmip.V1_2,
			},
		}, nil
	}))
	addr, ca := kmiptest.NewServer(t, router)
	client, err := kmipclient.Dial(
		addr,
		kmipclient.WithRootCAPem([]byte(ca)),
		kmipclient.WithMiddlewares(
			kmipclient.DebugMiddleware(os.Stderr, ttlv.MarshalXML),
		),
		kmipclient.WithKmipVersions(kmip.V1_2, kmip.V1_3),
	)
	require.NoError(t, err)
	require.NotNil(t, client)
	require.EqualValues(t, client.Version(), kmip.V1_3)
}

func TestVersionNegociation_NoCommon(t *testing.T) {
	router := kmipserver.NewBatchExecutor()
	router.Route(kmip.OperationDiscoverVersions, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.DiscoverVersionsRequestPayload) (*payloads.DiscoverVersionsResponsePayload, error) {
		return &payloads.DiscoverVersionsResponsePayload{
			ProtocolVersion: []kmip.ProtocolVersion{},
		}, nil
	}))
	addr, ca := kmiptest.NewServer(t, router)
	client, err := kmipclient.Dial(
		addr,
		kmipclient.WithRootCAPem([]byte(ca)),
		kmipclient.WithMiddlewares(
			kmipclient.DebugMiddleware(os.Stderr, ttlv.MarshalXML),
		),
		kmipclient.WithKmipVersions(kmip.V1_1, kmip.V1_2),
	)
	require.Error(t, err)
	require.Nil(t, client)
}

func TestVersionNegociation_v1_0_Fallback(t *testing.T) {
	router := kmipserver.NewBatchExecutor()
	router.Route(kmip.OperationDiscoverVersions, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.DiscoverVersionsRequestPayload) (*payloads.DiscoverVersionsResponsePayload, error) {
		return nil, kmipserver.ErrOperationNotSupported
	}))
	client := kmiptest.NewClientAndServer(t, router)
	require.EqualValues(t, client.Version(), kmip.V1_0)
}

func TestVersionNegociation_v1_0_Fallback_unsupported(t *testing.T) {
	router := kmipserver.NewBatchExecutor()
	router.Route(kmip.OperationDiscoverVersions, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.DiscoverVersionsRequestPayload) (*payloads.DiscoverVersionsResponsePayload, error) {
		return nil, kmipserver.ErrOperationNotSupported
	}))
	addr, ca := kmiptest.NewServer(t, router)
	client, err := kmipclient.Dial(
		addr,
		kmipclient.WithRootCAPem([]byte(ca)),
		kmipclient.WithMiddlewares(
			kmipclient.DebugMiddleware(os.Stderr, ttlv.MarshalXML),
		),
		kmipclient.WithKmipVersions(kmip.V1_3, kmip.V1_4),
	)
	require.Error(t, err)
	require.Nil(t, client)
}
