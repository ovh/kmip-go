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

func RemoteAddr(ctx context.Context) string {
	v, _ := ctx.Value(ctxConn{}).(connData)
	return v.remoteAddr
}

func PeerCertificates(ctx context.Context) []*x509.Certificate {
	v, _ := ctx.Value(ctxConn{}).(connData)
	if v.tlsConnState == nil {
		return nil
	}
	return v.tlsConnState.PeerCertificates
}

type ctxBatch struct{}
type batchData struct {
	idPlaceholder *string
	header        kmip.RequestHeader
}

func newBatchContext(parent context.Context, hdr kmip.RequestHeader) context.Context {
	bdata := &batchData{
		header: hdr,
	}
	return context.WithValue(parent, ctxBatch{}, bdata)
}

func IdPlaceholder(ctx context.Context) *string {
	bd, _ := ctx.Value(ctxBatch{}).(*batchData)
	if bd == nil {
		return nil
	}
	return bd.idPlaceholder
}

func GetIdOrPlaceholder(ctx context.Context, reqId *string) (string, error) {
	if reqId != nil {
		return *reqId, nil
	}
	if idp := IdPlaceholder(ctx); idp != nil {
		return *idp, nil
	}
	//TODO: Proper error
	return "", errors.New("ID Placeholder is empty")
}

func SetIdPlaceholder(ctx context.Context, id string) {
	bd, _ := ctx.Value(ctxBatch{}).(*batchData)
	if bd == nil {
		panic("not in a batch context")
	}
	bd.idPlaceholder = &id
}

func ClearIdPlaceholder(ctx context.Context) {
	bd, _ := ctx.Value(ctxBatch{}).(*batchData)
	if bd == nil {
		// Silently ignore if not in a batch context
		return
	}
	bd.idPlaceholder = nil
}

func GetProtocolVersion(ctx context.Context) kmip.ProtocolVersion {
	bd, _ := ctx.Value(ctxBatch{}).(*batchData)
	if bd == nil {
		panic("not in a batch context")
	}
	return bd.header.ProtocolVersion
}
