package kmipserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

var defaultSupportedVersion = []kmip.ProtocolVersion{kmip.V1_4, kmip.V1_3, kmip.V1_2, kmip.V1_1, kmip.V1_0}

type OperationHandler interface {
	HandleOperation(ctx context.Context, req kmip.OperationPayload) (kmip.OperationPayload, error)
}

type handlerFunc func(ctx context.Context, req kmip.OperationPayload) (kmip.OperationPayload, error)

func (h handlerFunc) HandleOperation(ctx context.Context, req kmip.OperationPayload) (kmip.OperationPayload, error) {
	return h(ctx, req)
}

func HandleFunc[Req, Resp kmip.OperationPayload](h func(ctx context.Context, req Req) (Resp, error)) OperationHandler {
	return handlerFunc(func(ctx context.Context, req kmip.OperationPayload) (kmip.OperationPayload, error) {
		payload, ok := req.(Req)
		if !ok {
			// TODO: Should probably be a panic here as this can only be caused by a programming error.
			return nil, errors.New("Invalid payload")
		}
		return h(ctx, payload)
	})
}

type BatchExecutor struct {
	routes      map[kmip.Operation]OperationHandler
	middlewares []Middleware
	// biMiddlewares     []BatchItemMiddleware
	supportedVersions []kmip.ProtocolVersion
}

func NewBatchExecutor() *BatchExecutor {
	return &BatchExecutor{
		routes:            make(map[kmip.Operation]OperationHandler),
		middlewares:       nil,
		supportedVersions: defaultSupportedVersion,
	}
}

func (exec *BatchExecutor) SetSupportedProtocolVersions(versions ...kmip.ProtocolVersion) {
	if len(versions) == 0 {
		versions = defaultSupportedVersion
	}
	slices.SortFunc(versions, ttlv.CompareVersions)
	versions = slices.Compact(versions)
	exec.supportedVersions = versions
}

func (exec *BatchExecutor) Use(m ...Middleware) {
	exec.middlewares = append(exec.middlewares, m...)
}

// func (exec *BatchExecutor) BatchItemUse(m ...Middleware) {
// 	exec.middlewares = append(exec.middlewares, m...)
// }

//TODO: Per batch item middlewares

func (exec *BatchExecutor) Route(op kmip.Operation, hdl OperationHandler) {
	exec.routes[op] = hdl
}

func (exec *BatchExecutor) HandleRequest(ctx context.Context, req *kmip.RequestMessage) *kmip.ResponseMessage {
	i := 0
	var next Next
	next = func(ctx context.Context, rm *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
		if i < len(exec.middlewares) {
			mdl := exec.middlewares[i]
			i++
			return mdl(next, ctx, req)
		}
		return exec.handleRequest(ctx, req)
	}

	ctx = newBatchContext(ctx, req.Header)
	resp, err := next(ctx, req)

	if err != nil {
		return exec.handleMessageError(ctx, req, err)
	}
	return resp
}

func (exec *BatchExecutor) handleRequest(ctx context.Context, req *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
	//TODO: Check request timestamp
	//TODO: Middleware maybe ?
	//TODO: Check other header params

	// Check for version compatibility
	if !slices.Contains(exec.supportedVersions, req.Header.ProtocolVersion) {
		return nil, Errorf(kmip.ReasonInvalidMessage, "Unsupported protocol version")
	}

	errorContinuationOption := kmip.Continue
	if co := req.Header.BatchErrorContinuationOption; co != nil {
		if *co == kmip.Undo {
			// Reject request if set to Undo as we don't support transactions
			return nil, Errorf(kmip.ReasonFeatureNotSupported, `"Undo" BatchErrorContinuationOption is not supported`)
		}
		errorContinuationOption = *co
	}

	if int(req.Header.BatchCount) != len(req.BatchItem) {
		return nil, Errorf(kmip.ReasonInvalidMessage, "Batch Count Mismatch")
	}
	response := &kmip.ResponseMessage{
		Header: kmip.ResponseHeader{
			ProtocolVersion:        req.Header.ProtocolVersion,
			TimeStamp:              time.Now(),
			BatchCount:             req.Header.BatchCount,
			ClientCorrelationValue: req.Header.ClientCorrelationValue,
		},
		BatchItem: make([]kmip.ResponseBatchItem, len(req.BatchItem)),
	}

	stopped := false
	for i := range req.BatchItem {
		if stopped {
			response.BatchItem[i] = kmip.ResponseBatchItem{
				Operation:         req.BatchItem[i].Operation,
				UniqueBatchItemID: req.BatchItem[i].UniqueBatchItemID,
				ResultStatus:      kmip.StatusOperationFailed,
				ResultReason:      kmip.ReasonOperationCanceledByRequester,
				ResultMessage:     "Batch has stopped because of an error",
			}
			continue
		}
		response.BatchItem[i] = exec.executeItem(ctx, req.BatchItem[i])
		if response.BatchItem[i].ResultStatus == kmip.StatusOperationFailed && errorContinuationOption == kmip.Stop {
			stopped = true
		}
	}
	return response, nil
}

func (exec *BatchExecutor) executeItem(ctx context.Context, bi kmip.RequestBatchItem) (resp kmip.ResponseBatchItem) {
	var err error
	resp = kmip.ResponseBatchItem{
		Operation:         bi.Operation,
		UniqueBatchItemID: bi.UniqueBatchItemID,
	}
	defer func() {
		err := recover()
		if err == nil {
			return
		}
		slog.Error("Batch item handler panicked", "err", err)
		slog.Error("STACK TRACE: " + string(debug.Stack()))
		var e error
		switch er := err.(type) {
		case error:
			e = er
		case string:
			e = errors.New(er)
		case fmt.Stringer:
			e = errors.New(er.String())
		default:
			//TODO: Do not return the error message, but log it instead
			e = fmt.Errorf("Internal Server Error: %s", er)
		}
		exec.handleBatchItemError(ctx, &resp, e)
	}()

	if me := bi.MessageExtension; me != nil {
		if me.CriticalityIndicator {
			//TODO: When batch item middleware support has landed, move this into a middleware maybe
			exec.handleBatchItemError(ctx, &resp, Errorf(kmip.ReasonFeatureNotSupported, "Critical message extension not supported"))
			return
		}
	}

	switch pl := bi.RequestPayload.(type) {
	case *payloads.DiscoverVersionsRequestPayload:
		if route, ok := exec.routes[bi.Operation]; ok {
			resp.ResponsePayload, err = route.HandleOperation(ctx, pl)
		} else {
			resp.ResponsePayload, err = exec.handleDiscover(pl)
		}
	default:
		route, ok := exec.routes[bi.Operation]
		if !ok {
			err = ErrOperationNotSupported
			break
		}
		resp.ResponsePayload, err = route.HandleOperation(ctx, pl)
	}
	if err != nil {
		exec.handleBatchItemError(ctx, &resp, err)
		return resp
	}
	return resp
}

func (exec *BatchExecutor) handleBatchItemError(ctx context.Context, bi *kmip.ResponseBatchItem, err error) {
	handleBatchItemError(ctx, bi, err)
}

func (exec *BatchExecutor) handleMessageError(ctx context.Context, req *kmip.RequestMessage, err error) *kmip.ResponseMessage {
	return handleMessageError(ctx, req, err)
}

func (exec *BatchExecutor) handleDiscover(req *payloads.DiscoverVersionsRequestPayload) (*payloads.DiscoverVersionsRequestPayload, error) {
	resp := &payloads.DiscoverVersionsRequestPayload{}
	if len(req.ProtocolVersion) == 0 {
		resp.ProtocolVersion = exec.supportedVersions
		return resp, nil
	}
	for _, v := range exec.supportedVersions {
		if slices.Contains(req.ProtocolVersion, v) {
			resp.ProtocolVersion = append(resp.ProtocolVersion, v)
		}
	}
	return resp, nil
}
