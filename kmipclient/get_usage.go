package kmipclient

import "github.com/ovh/kmip-go/payloads"

// GetUsageAllocation creates an ExecGetUsageAllocation instance with the specified unique identifier
// and usage limits count. This function initializes the request payload with the provided parameters.
// Note that the returned value does not execute the operation; the Exec or ExecContext method must be called to perform the execution.
//
// Parameters:
//   - id: A string representing the unique identifier for the usage allocation request.
//   - limitCount: An int64 representing the usage limits count for the allocation.
//
// Returns:
//   - ExecGetUsageAllocation: An instance initialized with the provided client and request payload.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecGetUsageAllocation.
//   - If the object does not exist or the server rejects the operation, an error will be returned during execution.
func (c *Client) GetUsageAllocation(id string, limitCount int64) ExecGetUsageAllocation {
	return ExecGetUsageAllocation{
		client: c,
		req: &payloads.GetUsageAllocationRequestPayload{
			UniqueIdentifier: id,
			UsageLimitsCount: limitCount,
		},
	}
}

// ExecGetUsageAllocation is a type alias for Executor that operates on GetUsageAllocationRequestPayload and GetUsageAllocationResponsePayload.
// It is used to execute get usage allocation operations within the KMIP client, handling the request and response payloads
// specific to the get usage allocation functionality.
//
// Usage:
//
//	exec := client.GetUsageAllocation("object-id", 10)
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the get usage allocation operation if the object does not exist,
//     or if the server returns an error.
type ExecGetUsageAllocation = Executor[*payloads.GetUsageAllocationRequestPayload, *payloads.GetUsageAllocationResponsePayload]
