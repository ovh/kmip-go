package kmipclient_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"
	"github.com/stretchr/testify/require"
)

func TestMAC(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()

	// Secret key for HMAC
	secretKey := []byte("0123456789abcdef0123456789abcdef")

	mux.Route(kmip.OperationMAC, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.MACRequestPayload) (*payloads.MACResponsePayload, error) {
		// Simple mock implementation that returns HMAC-SHA256 of the data
		h := hmac.New(sha256.New, secretKey)
		h.Write(pl.Data)
		mac := h.Sum(nil)
		return &payloads.MACResponsePayload{
			UniqueIdentifier: pl.UniqueIdentifier,
			MACData:          mac,
		}, nil
	}))

	client := kmiptest.NewClientAndServer(t, mux)

	data := []byte("hello world")

	t.Run("BasicMAC", func(t *testing.T) {
		resp, err := client.MAC("test-key-id").
			WithCryptographicParameters(kmip.CryptographicParameters{
				CryptographicAlgorithm: kmip.CryptographicAlgorithmHMACSHA256,
			}).
			Data(data).
			ExecContext(context.Background())
		require.NoError(t, err)
		require.NotNil(t, resp)

		// Verify the MAC
		h := hmac.New(sha256.New, secretKey)
		h.Write(data)
		expectedMAC := h.Sum(nil)
		require.Equal(t, expectedMAC, resp.MACData)
	})

	t.Run("MACWithoutID", func(t *testing.T) {
		resp, err := client.MAC("").
			WithCryptographicParameters(kmip.CryptographicParameters{
				CryptographicAlgorithm: kmip.CryptographicAlgorithmHMACSHA256,
			}).
			Data(data).
			ExecContext(context.Background())
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.MACData)
	})
}

func TestMACVerify(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()

	// Secret key for HMAC
	secretKey := []byte("0123456789abcdef0123456789abcdef")

	mux.Route(kmip.OperationMACVerify, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.MACVerifyRequestPayload) (*payloads.MACVerifyResponsePayload, error) {
		// Calculate expected MAC
		h := hmac.New(sha256.New, secretKey)
		h.Write(pl.Data)
		expectedMAC := h.Sum(nil)

		// Compare with provided MAC
		valid := hmac.Equal(pl.MACData, expectedMAC)

		validityIndicator := kmip.ValidityIndicatorInvalid
		if valid {
			validityIndicator = kmip.ValidityIndicatorValid
		}

		return &payloads.MACVerifyResponsePayload{
			UniqueIdentifier:  pl.UniqueIdentifier,
			ValidityIndicator: validityIndicator,
		}, nil
	}))

	client := kmiptest.NewClientAndServer(t, mux)

	data := []byte("hello world")

	// Calculate valid MAC
	h := hmac.New(sha256.New, secretKey)
	h.Write(data)
	validMAC := h.Sum(nil)

	// Calculate invalid MAC
	invalidMAC := []byte("invalid-mac-data")

	t.Run("ValidMAC", func(t *testing.T) {
		resp, err := client.MACVerify("test-key-id").
			WithCryptographicParameters(kmip.CryptographicParameters{
				CryptographicAlgorithm: kmip.CryptographicAlgorithmHMACSHA256,
			}).
			Data(data).
			MACData(validMAC).
			ExecContext(context.Background())
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, kmip.ValidityIndicatorValid, resp.ValidityIndicator)
	})

	t.Run("InvalidMAC", func(t *testing.T) {
		resp, err := client.MACVerify("test-key-id").
			WithCryptographicParameters(kmip.CryptographicParameters{
				CryptographicAlgorithm: kmip.CryptographicAlgorithmHMACSHA256,
			}).
			Data(data).
			MACData(invalidMAC).
			ExecContext(context.Background())
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, kmip.ValidityIndicatorInvalid, resp.ValidityIndicator)
	})

	t.Run("MACVerifyWithData", func(t *testing.T) {
		// Test the alternative method chain: .MACVerify().MACData()
		resp, err := client.MACVerify("test-key-id").
			WithCryptographicParameters(kmip.CryptographicParameters{
				CryptographicAlgorithm: kmip.CryptographicAlgorithmHMACSHA256,
			}).
			MACData(validMAC).
			Data(data).
			ExecContext(context.Background())
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, kmip.ValidityIndicatorValid, resp.ValidityIndicator)
	})
}
