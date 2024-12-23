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
	ErrOperationNotSupported = Errorf(kmip.ReasonOperationNotSupported, "Operation not supported")
	ErrFeatureNotSupported   = Errorf(kmip.ReasonFeatureNotSupported, "Feature not supported")
	ErrMissingData           = Errorf(kmip.ReasonMissingData, "Missing data")
	ErrItemNotFound          = Errorf(kmip.ReasonItemNotFound, "Item not found")
	ErrPermissionDenied      = Errorf(kmip.ReasonPermissionDenied, "Permission denied")
	ErrInvalidMessage        = Errorf(kmip.ReasonInvalidMessage, "Invalid message")
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
	bi.ResultStatus = kmip.StatusOperationFailed
	var e Error
	if errors.As(err, &e) {
		bi.ResultReason = e.Reason
	} else {
		bi.ResultReason = kmip.ReasonGeneralFailure
	}
	//TODO: Do not return the error message if the error is not of type kmipserver.Error. Log it instead.
	bi.ResultMessage = err.Error()
}
