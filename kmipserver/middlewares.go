package kmipserver

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"
)

// Next defines a middleware function signature that takes a context and a KMIP request message,
// and returns a KMIP response message or an error. It is used to chain middleware handlers
// in the KMIP server processing pipeline.
type Next func(context.Context, *kmip.RequestMessage) (*kmip.ResponseMessage, error)

// Middleware defines a function type that wraps the processing of a KMIP request message.
// It takes the next handler in the chain, a context, and the incoming KMIP request message,
// and returns a KMIP response message or an error. Middlewares can be used to implement
// cross-cutting concerns such as logging, authentication, or request validation.
type Middleware func(next Next, ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error)

// DebugMiddleware returns a Middleware that logs the incoming KMIP request and the corresponding response
// to the provided io.Writer. It uses the given marshal function to serialize the request and response data,
// defaulting to ttlv.MarshalXML if marshal is nil. The middleware also logs the time taken to process the request.
// If the writer supports flushing, it will be flushed after logging. Any errors encountered during processing
// are also logged to the writer.
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
			fmt.Fprintf(out, "[ERROR] %s", err.Error())
			return nil, err
		}
		fmt.Fprintf(out, "\nResponse in %s:\n", time.Since(now))
		fmt.Fprintln(out, string(marshal(resp)))
		return resp, nil
	}
}

// BatchItemNext defines a middleware function signature for batch items that takes a context and a KMIP request batch item,
// and returns a KMIP response batch item. It is used to chain middleware handlers in the KMIP server's batch item
// processing pipeline.
type BatchItemNext func(ctx context.Context, bi *kmip.RequestBatchItem) (*kmip.ResponseBatchItem, error)

// BatchItemMiddleware defines a function type that wraps the processing of a KMIP request batch item.
// It takes the next handler in the chain, a context, and the incoming KMIP request batch item,
// and returns a KMIP response batch item. This allows for implementing cross-cutting concerns
// specific to individual batch items, such as logging, authentication, or request validation.
type BatchItemMiddleware func(next BatchItemNext, ctx context.Context, bi *kmip.RequestBatchItem) (*kmip.ResponseBatchItem, error)
