package kmipclient

import (
	"github.com/ovh/kmip-go/payloads"
)

// Destroy creates an ExecDestroy operation for the specified unique identifier.
// It prepares a DestroyRequestPayload with the given ID and associates it with the client.
// The returned ExecDestroy can be used to execute the destroy operation on the KMIP server
// by calling Exec or ExecContext.
//
// Parameters:
//   - id: The unique identifier of the object to be destroyed.
//
// Returns:
//   - ExecDestroy: An executable destroy operation configured with the provided identifier.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecDestroy.
//   - If the object does not exist or cannot be destroyed, an error will be returned during execution.
func (c *KMIPClient) Destroy(id string) ExecDestroy {
	return ExecDestroy{
		client: c,
		req: &payloads.DestroyRequestPayload{
			UniqueIdentifier: id,
		},
	}
}

// ExecDestroy is a type alias for Executor specialized with DestroyRequestPayload and DestroyResponsePayload.
// It is used to execute destroy operations in the KMIP client, handling the request and response payloads
// specific to the destroy operation.
//
// Usage:
//
//	exec := client.Destroy("object-id")
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the destroy operation if the object does not exist,
//     is not in a state that can be destroyed, or if the server returns an error.
type ExecDestroy = Executor[*payloads.DestroyRequestPayload, *payloads.DestroyResponsePayload]
