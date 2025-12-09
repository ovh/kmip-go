package kmipclient

import (
	"github.com/ovh/kmip-go/payloads"
)

// Activate creates and returns an ExecActivate struct initialized with the provided unique identifier.
// This method prepares an activation request payload for the specified object ID using the client instance.
// The returned ExecActivate can be used to execute the activation operation by calling Exec or ExecContext.
//
// Parameters:
//   - id: Unique identifier of the KMIP object to activate.
//
// Returns:
//   - ExecActivate: Executor for the Activate operation, pre-filled with the unique identifier.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecActivate.
func (c *KMIPClient) Activate(id string) ExecActivate {
	return ExecActivate{
		client: c,
		req: &payloads.ActivateRequestPayload{
			UniqueIdentifier: id,
		},
	}
}

// ExecActivate is a type alias for Executor that operates on ActivateRequestPayload and ActivateResponsePayload.
// It is used to execute activation operations within the KMIP client. Use Exec or ExecContext to perform the operation.
//
// Usage:
//
//	exec := client.Activate("object-id")
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the activation operation if the object does not exist,
//     is not in a state that can be activated, or if the server returns an error.
type ExecActivate = Executor[*payloads.ActivateRequestPayload, *payloads.ActivateResponsePayload]
