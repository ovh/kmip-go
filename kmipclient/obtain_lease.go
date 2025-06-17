package kmipclient

import "github.com/ovh/kmip-go/payloads"

// ObtainLease creates an ExecObtainLease operation to obtain a lease for the object identified by the given unique identifier.
// The returned ExecObtainLease can be executed to perform the obtain lease operation.
//
// Parameters:
//   - id: The unique identifier of the object for which to obtain a lease.
//
// Returns:
//   - ExecObtainLease: An executor for the obtain lease operation.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecObtainLease.
//   - If the object does not exist or the server rejects the operation, an error will be returned during execution.
func (c *Client) ObtainLease(id string) ExecObtainLease {
	return ExecObtainLease{
		client: c,
		req: &payloads.ObtainLeaseRequestPayload{
			UniqueIdentifier: id,
		},
	}
}

// ExecObtainLease is a type alias for Executor that operates on ObtainLeaseRequestPayload and ObtainLeaseResponsePayload.
// It is used to execute obtain lease operations within the KMIP client, handling the request and response payloads
// specific to the obtain lease functionality.
//
// Usage:
//
//	exec := client.ObtainLease("object-id")
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the obtain lease operation if the object does not exist,
//     or if the server returns an error.
type ExecObtainLease = Executor[*payloads.ObtainLeaseRequestPayload, *payloads.ObtainLeaseResponsePayload]
