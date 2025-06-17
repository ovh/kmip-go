package kmipclient

import (
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// Revoke creates an ExecRevoke operation for the specified unique identifier.
// This method prepares a revoke request payload for the specified object ID using the client instance.
// The returned ExecRevoke can be used to execute the revoke operation by calling Exec or ExecContext.
//
// Parameters:
//   - id: The unique identifier of the object to be revoked.
//
// Returns:
//   - ExecRevoke: Executor for the Revoke operation, pre-filled with the unique identifier.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecRevoke.
//   - If the object does not exist or cannot be revoked, an error will be returned during execution.
func (c *Client) Revoke(id string) ExecRevoke {
	return ExecRevoke{
		Executor[*payloads.RevokeRequestPayload, *payloads.RevokeResponsePayload]{
			client: c,
			req: &payloads.RevokeRequestPayload{
				UniqueIdentifier: id,
				RevocationReason: kmip.RevocationReason{
					RevocationReasonCode: kmip.RevocationReasonCodeUnspecified,
				},
			},
		},
	}
}

// ExecRevoke is a specialized executor for handling Revoke operations.
// It embeds the generic Executor with request and response payload types specific to
// the Revoke KMIP operation, facilitating the execution and management of revoke requests and their responses.
//
// Usage:
//
//	exec := client.Revoke("object-id").WithRevocationReasonCode(...).WithRevocationMessage("reason")
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the revoke operation if the object does not exist,
//     is not in a state that can be revoked, or if the server returns an error.
type ExecRevoke struct {
	Executor[*payloads.RevokeRequestPayload, *payloads.RevokeResponsePayload]
}

// WithRevocationReasonCode sets the RevocationReasonCode for the revoke request.
//
// Parameters:
//   - code: The revocation reason code to set.
//
// Returns:
//   - ExecRevoke: The updated ExecRevoke with the reason code set.
//
// Errors:
//   - No error is returned by this method. If the code is not supported by the server, an error may occur during execution.
func (ex ExecRevoke) WithRevocationReasonCode(code kmip.RevocationReasonCode) ExecRevoke {
	ex.req.RevocationReason.RevocationReasonCode = code
	return ex
}

// WithRevocationMessage sets the RevocationMessage for the revoke request.
//
// Parameters:
//   - msg: The revocation message to set.
//
// Returns:
//   - ExecRevoke: The updated ExecRevoke with the message set.
//
// Errors:
//   - No error is returned by this method. If the message is not supported by the server, an error may occur during execution.
func (ex ExecRevoke) WithRevocationMessage(msg string) ExecRevoke {
	if msg != "" {
		ex.req.RevocationReason.RevocationMessage = msg
	}
	return ex
}

// WithCompromiseOccurrenceDate sets the CompromiseOccurrenceDate for the revoke request.
//
// Parameters:
//   - dt: The time of compromise occurrence.
//
// Returns:
//   - ExecRevoke: The updated ExecRevoke with the compromise occurrence date set.
//
// Errors:
//   - No error is returned by this method. If the value is not supported by the server, an error may occur during execution.
func (ex ExecRevoke) WithCompromiseOccurrenceDate(dt time.Time) ExecRevoke {
	ex.req.CompromiseOccurrenceDate = &dt
	return ex
}
