package kmipclient

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"
)

// Next defines a middleware function signature that processes a KMIP RequestMessage within a given context,
// and returns a corresponding ResponseMessage or an error. It is typically used to chain middleware handlers
// in the KMIP client request pipeline.
type Next func(context.Context, *kmip.RequestMessage) (*kmip.ResponseMessage, error)

// Middleware defines a function type that wraps the processing of a KMIP request message.
// It takes the next handler in the chain, a context, and the request message as input,
// and returns a response message or an error. Middlewares can be used to implement
// cross-cutting concerns such as logging, authentication, or error handling.
type Middleware func(next Next, ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error)

// DebugMiddleware returns a Middleware that logs the KMIP request and response messages
// to the specified io.Writer. The messages are marshaled using the provided marshal
// function, or ttlv.MarshalXML if marshal is nil. The middleware also logs the duration
// taken to receive the response. If the writer supports a Flush() method, it is called
// after logging is complete.
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

// CorrelationValueMiddleware returns a Middleware that sets the ClientCorrelationValue
// in the KMIP request header if it is empty and the protocol version is 1.4 or higher.
// The provided fn function is used to generate the correlation value. If fn is nil,
// the middleware will panic. This is useful for ensuring that requests have a unique
// correlation value for tracking and debugging purposes in compliant KMIP versions.
func CorrelationValueMiddleware(fn func() string) Middleware {
	if fn == nil {
		panic("correlation value generator function cannot be null")
	}
	return func(next Next, ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
		if msg.Header.ClientCorrelationValue == "" && ttlv.CompareVersions(msg.Header.ProtocolVersion, kmip.V1_4) >= 0 {
			msg.Header.ClientCorrelationValue = fn()
		}
		return next(ctx, msg)
	}
}

// TimeoutMiddleware returns a Middleware that applies a timeout to the context of each request.
// If the provided timeout is zero, the middleware passes the context unchanged.
// Otherwise, it wraps the context with a timeout, ensuring that the request is canceled
// if it does not complete within the specified duration.
//
// Parameters:
//   - timeout: The duration to wait before timing out the request. If zero, no timeout is applied.
//
// Returns:
//   - Middleware: A middleware function that enforces the specified timeout on the request context.
func TimeoutMiddleware(timeout time.Duration) Middleware {
	if timeout == 0 {
		return func(next Next, ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
			return next(ctx, msg)
		}
	}
	return func(next Next, ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		return next(ctx, msg)
	}
}
