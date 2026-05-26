package kmipserver

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/ovh/kmip-go"

	"github.com/stretchr/testify/require"
)

func TestRemoteAddr(t *testing.T) {
	t.Run("missing context value returns empty string", func(t *testing.T) {
		require.Empty(t, RemoteAddr(t.Context()))
	})

	t.Run("returns stored remote address", func(t *testing.T) {
		ctx := newConnContext(t.Context(), "10.0.0.1:4242", nil)
		require.Equal(t, "10.0.0.1:4242", RemoteAddr(ctx))
	})
}

func TestTLSConnectionState(t *testing.T) {
	t.Run("missing context value returns nil", func(t *testing.T) {
		require.Nil(t, TLSConnectionState(t.Context()))
	})

	t.Run("nil tls state returns nil", func(t *testing.T) {
		ctx := newConnContext(t.Context(), "10.0.0.1:4242", nil)
		require.Nil(t, TLSConnectionState(ctx))
	})

	t.Run("returns stored tls connection state", func(t *testing.T) {
		state := &tls.ConnectionState{}
		ctx := newConnContext(t.Context(), "10.0.0.1:4242", state)
		require.Same(t, state, TLSConnectionState(ctx))
	})
}

func TestPeerCertificates(t *testing.T) {
	t.Run("missing context value returns nil", func(t *testing.T) {
		require.Nil(t, PeerCertificates(t.Context()))
	})

	t.Run("nil tls state returns nil", func(t *testing.T) {
		ctx := newConnContext(t.Context(), "10.0.0.1:4242", nil)
		require.Nil(t, PeerCertificates(ctx))
	})

	t.Run("returns peer certificates from tls state", func(t *testing.T) {
		certs := []*x509.Certificate{{Subject: pkix.Name{CommonName: "client"}}}
		state := &tls.ConnectionState{PeerCertificates: certs}
		ctx := newConnContext(t.Context(), "10.0.0.1:4242", state)
		require.Equal(t, certs, PeerCertificates(ctx))
	})
}

func TestIdPlaceholder(t *testing.T) {
	t.Run("outside batch context returns empty string", func(t *testing.T) {
		require.Empty(t, IdPlaceholder(t.Context()))
	})

	t.Run("unset placeholder returns empty string", func(t *testing.T) {
		ctx := newBatchContext(t.Context(), kmip.RequestHeader{})
		require.Empty(t, IdPlaceholder(ctx))
	})

	t.Run("returns stored placeholder", func(t *testing.T) {
		ctx := newBatchContext(t.Context(), kmip.RequestHeader{})
		SetIdPlaceholder(ctx, "abc-123")
		require.Equal(t, "abc-123", IdPlaceholder(ctx))
	})
}

func TestGetIdOrPlaceholder(t *testing.T) {
	t.Run("returns reqId when non-empty", func(t *testing.T) {
		id, err := GetIdOrPlaceholder(t.Context(), "explicit-id")
		require.NoError(t, err)
		require.Equal(t, "explicit-id", id)
	})

	t.Run("falls back to placeholder when reqId is empty", func(t *testing.T) {
		ctx := newBatchContext(t.Context(), kmip.RequestHeader{})
		SetIdPlaceholder(ctx, "placeholder-id")
		id, err := GetIdOrPlaceholder(ctx, "")
		require.NoError(t, err)
		require.Equal(t, "placeholder-id", id)
	})

	t.Run("returns error when both are empty", func(t *testing.T) {
		ctx := newBatchContext(t.Context(), kmip.RequestHeader{})
		id, err := GetIdOrPlaceholder(ctx, "")
		require.Error(t, err)
		require.Empty(t, id)
	})

	t.Run("returns error outside batch context when reqId empty", func(t *testing.T) {
		id, err := GetIdOrPlaceholder(t.Context(), "")
		require.Error(t, err)
		require.Empty(t, id)
	})
}

func TestSetIdPlaceholder(t *testing.T) {
	t.Run("panics outside batch context", func(t *testing.T) {
		require.PanicsWithValue(t, "not in a batch context", func() {
			SetIdPlaceholder(t.Context(), "id")
		})
	})

	t.Run("overwrites previous value", func(t *testing.T) {
		ctx := newBatchContext(t.Context(), kmip.RequestHeader{})
		SetIdPlaceholder(ctx, "first")
		SetIdPlaceholder(ctx, "second")
		require.Equal(t, "second", IdPlaceholder(ctx))
	})
}

func TestClearIdPlaceholder(t *testing.T) {
	t.Run("no-op outside batch context", func(t *testing.T) {
		require.NotPanics(t, func() {
			ClearIdPlaceholder(t.Context())
		})
	})

	t.Run("clears previously set placeholder", func(t *testing.T) {
		ctx := newBatchContext(t.Context(), kmip.RequestHeader{})
		SetIdPlaceholder(ctx, "to-be-cleared")
		ClearIdPlaceholder(ctx)
		require.Empty(t, IdPlaceholder(ctx))
	})
}

func TestGetRequestHeader(t *testing.T) {
	t.Run("panics outside batch context", func(t *testing.T) {
		require.PanicsWithValue(t, "not in a batch context", func() {
			GetRequestHeader(t.Context())
		})
	})

	t.Run("returns stored header", func(t *testing.T) {
		hdr := kmip.RequestHeader{
			ProtocolVersion: kmip.V1_4,
			BatchCount:      3,
		}
		ctx := newBatchContext(t.Context(), hdr)
		require.Equal(t, hdr, GetRequestHeader(ctx))
	})
}

func TestGetProtocolVersion(t *testing.T) {
	t.Run("panics outside batch context", func(t *testing.T) {
		require.PanicsWithValue(t, "not in a batch context", func() {
			GetProtocolVersion(t.Context())
		})
	})

	t.Run("returns protocol version from header", func(t *testing.T) {
		ctx := newBatchContext(t.Context(), kmip.RequestHeader{
			ProtocolVersion: kmip.V1_4,
		})
		require.Equal(t, kmip.V1_4, GetProtocolVersion(ctx))
	})
}
