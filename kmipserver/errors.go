package kmipserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"
)

type Error struct {
	Reason  kmip.ResultReason
	Message string
}

func (e Error) Error() string {
	if e.Message == "" {
		return ttlv.EnumStr(e.Reason)
	}
	return e.Message
}

func Errorf(reason kmip.ResultReason, format string, args ...any) error {
	return Error{
		Reason:  reason,
		Message: fmt.Sprintf(format, args...),
	}
}

var (
	ErrOperationNotSupported = Errorf(kmip.ResultReasonOperationNotSupported, "Operation not supported")
	ErrFeatureNotSupported   = Errorf(kmip.ResultReasonFeatureNotSupported, "Feature not supported")
	ErrMissingData           = Errorf(kmip.ResultReasonMissingData, "Missing data")
	ErrItemNotFound          = Errorf(kmip.ResultReasonItemNotFound, "Item not found")
	ErrPermissionDenied      = Errorf(kmip.ResultReasonPermissionDenied, "Permission denied")
	ErrInvalidMessage        = Errorf(kmip.ResultReasonInvalidMessage, "Invalid message")
	ErrInvalidField          = Errorf(kmip.ResultReasonInvalidField, "Invalid field")
)

func handleMessageError(ctx context.Context, req *kmip.RequestMessage, err error) *kmip.ResponseMessage {
	header := kmip.ResponseHeader{
		ProtocolVersion: kmip.V1_0,
		TimeStamp:       time.Now(),
		BatchCount:      1,
	}
	if req != nil {
		if req.Header.ProtocolVersion != (kmip.ProtocolVersion{}) {
			header.ProtocolVersion = req.Header.ProtocolVersion
		}
		header.ClientCorrelationValue = req.Header.ClientCorrelationValue
		header.ServerCorrelationValue = req.Header.ServerCorrelationValue
	}

	bi := kmip.ResponseBatchItem{}
	handleBatchItemError(ctx, &bi, err)

	return &kmip.ResponseMessage{
		Header:    header,
		BatchItem: []kmip.ResponseBatchItem{bi},
	}
}

func handleBatchItemError(ctx context.Context, bi *kmip.ResponseBatchItem, err error) {
	if err == nil {
		return
	}
	// Always clear the ID placeholder on error
	//TODO: Double check against the KMIP specification about this
	ClearIdPlaceholder(ctx)
	bi.ResultStatus = kmip.ResultStatusOperationFailed
	var e Error
	if errors.As(err, &e) {
		bi.ResultReason = e.Reason
	} else {
		bi.ResultReason = kmip.ResultReasonGeneralFailure
	}
	//TODO: Do not return the error message if the error is not of type kmipserver.Error. Log it instead.
	bi.ResultMessage = err.Error()
}
