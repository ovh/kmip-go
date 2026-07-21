package kmipclient_test

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"
	"github.com/stretchr/testify/require"
)

func TestHash(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()

	mux.Route(kmip.OperationHash, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.HashRequestPayload) (*payloads.HashResponsePayload, error) {
		// Simple mock implementation that returns SHA-256 hash of the data
		hash := sha256.Sum256(pl.Data)
		return &payloads.HashResponsePayload{
			Data: hash[:],
		}, nil
	}))

	client := kmiptest.NewClientAndServer(t, mux)

	data := []byte("hello world")

	t.Run("BasicHash", func(t *testing.T) {
		resp, err := client.Hash().
			WithCryptographicParameters(kmip.CryptographicParameters{
				HashingAlgorithm: kmip.HashingAlgorithmSHA_256,
			}).
			Data(data).
			ExecContext(context.Background())
		require.NoError(t, err)
		require.NotNil(t, resp)

		// Verify the hash
		expected := sha256.Sum256(data)
		require.Equal(t, expected[:], resp.Data)
	})
}
