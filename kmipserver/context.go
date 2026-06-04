package kmipserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/ovh/kmip-go"
)

type ctxConn struct{}

type connData struct {
	remoteAddr   string
	tlsConnState *tls.ConnectionState
}

func newConnContext(parent context.Context, remoteAddr string, tlsConnState *tls.ConnectionState) context.Context {
	data := connData{
		remoteAddr:   remoteAddr,
		tlsConnState: tlsConnState,
	}
	return context.WithValue(parent, ctxConn{}, data)
}

// RemoteAddr retrieves the remote address associated with the given context.
// If the value is not present or of the wrong type, it returns an empty string.
func RemoteAddr(ctx context.Context) string {
	v, _ := ctx.Value(ctxConn{}).(connData)
	return v.remoteAddr
}

// TLSConnectionState retrieves the TLS connection state associated with the given context.
// If no TLS connection state is present (e.g. the connection is not using TLS),
// it returns nil.
//
// The returned value is shared across all requests on the same connection and must be
// treated as read-only; callers must not mutate it.
func TLSConnectionState(ctx context.Context) *tls.ConnectionState {
	v, _ := ctx.Value(ctxConn{}).(connData)
	return v.tlsConnState
}

// PeerCertificates retrieves the peer certificates from the TLS connection state
// stored in the provided context. If no TLS connection state is present, it returns nil.
func PeerCertificates(ctx context.Context) []*x509.Certificate {
	tlsConnState := TLSConnectionState(ctx)
	if tlsConnState == nil {
		return nil
	}
	return tlsConnState.PeerCertificates
}

type ctxBatch struct{}
type batchData struct {
	idPlaceholder string
	header        kmip.RequestHeader
}

func newBatchContext(parent context.Context, hdr kmip.RequestHeader) context.Context {
	bdata := &batchData{
		header: hdr,
	}
	return context.WithValue(parent, ctxBatch{}, bdata)
}

// IdPlaceholder retrieves the idPlaceholder stored in the provided context.
// If no idPlaceholder is found in the context, it returns an empty string.
func IdPlaceholder(ctx context.Context) string {
	bd, _ := ctx.Value(ctxBatch{}).(*batchData)
	if bd == nil {
		return ""
	}
	return bd.idPlaceholder
}

// GetIdOrPlaceholder returns the provided reqId if it is not empty.
// If reqId is empty, it attempts to retrieve an ID placeholder from the context.
// If neither is available, it returns an error indicating that the ID placeholder is empty.
func GetIdOrPlaceholder(ctx context.Context, reqId string) (string, error) {
	if reqId != "" {
		return reqId, nil
	}
	if idp := IdPlaceholder(ctx); idp != "" {
		return idp, nil
	}
	//TODO: Proper error
	return "", errors.New("ID Placeholder is empty")
}

// SetIdPlaceholder sets the idPlaceholder in the given context.
// This function is intended to be used within a batch context to update the placeholder ID.
// It will panic if used outside the context of kmip request processing.
func SetIdPlaceholder(ctx context.Context, id string) {
	bd, _ := ctx.Value(ctxBatch{}).(*batchData)
	if bd == nil {
		panic("not in a batch context")
	}
	bd.idPlaceholder = id
}

// ClearIdPlaceholder resets the idPlaceholder in the given context.
// This is typically used to clear any temporary identifier placeholders within a batch operation context.
func ClearIdPlaceholder(ctx context.Context) {
	bd, _ := ctx.Value(ctxBatch{}).(*batchData)
	if bd == nil {
		// Silently ignore if not in a batch context
		return
	}
	bd.idPlaceholder = ""
}

// GetProtocolVersion retrieves the KMIP protocol version from the provided context.
// It panics if used outside the context of kmip request processing.
// Returns the ProtocolVersion from the batch header.
func GetProtocolVersion(ctx context.Context) kmip.ProtocolVersion {
	return GetRequestHeader(ctx).ProtocolVersion
}

// GetRequestHeader retrieves the KMIP request header from the provided context.
// It panics if used outside the context of kmip request processing.
// Returns the RequestHeader from the batch.
func GetRequestHeader(ctx context.Context) kmip.RequestHeader {
	bd, _ := ctx.Value(ctxBatch{}).(*batchData)
	if bd == nil {
		panic("not in a batch context")
	}
	return bd.header
}
