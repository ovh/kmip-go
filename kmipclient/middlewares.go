package kmipclient

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"
)

type Next func(context.Context, *kmip.RequestMessage) (*kmip.ResponseMessage, error)
type Middleware func(next Next, ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error)

func DebugMiddleware(out io.Writer, marshal func(data any) []byte) Middleware {
	if marshal == nil {
		marshal = ttlv.MarshalXML
	}
	return func(next Next, ctx context.Context, rm *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
		if flushable, ok := out.(interface{ Flush() error }); ok {
			defer flushable.Flush()
		}
		fmt.Fprintln(out, "Request:")
		fmt.Fprintln(out, string(marshal(rm)))
		now := time.Now()
		resp, err := next(ctx, rm)
		if err != nil {
			return resp, err
		}
		fmt.Fprintf(out, "\nResponse in %s:\n", time.Since(now))
		fmt.Fprintln(out, string(marshal(resp)))
		return resp, nil
	}
}

func CorrelationValueMiddleware(fn func() string) Middleware {
	if fn == nil {
		panic("correlation value generator function cannot be null")
	}
	return func(next Next, ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
		if msg.Header.ClientCorrelationValue == nil && ttlv.CompareVersions(msg.Header.ProtocolVersion, kmip.V1_4) >= 0 {
			corrVal := fn()
			msg.Header.ClientCorrelationValue = &corrVal
		}
		return next(ctx, msg)
	}
}
