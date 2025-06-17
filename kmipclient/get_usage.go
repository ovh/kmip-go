package kmipclient

import "github.com/ovh/kmip-go/payloads"

// GetUsageAllocation creates an ExecGetUsageAllocation instance with the specified unique identifier
// and usage limits count. This function initializes the request payload with the provided parameters.
// Note that the returned value does not execute the operation; the Exec method must be called to perform the execution.
//
// Parameters:
//   - id: A string representing the unique identifier for the usage allocation request.
//   - limitCount: An int64 representing the usage limits count for the allocation.
//
// Returns:
//
// An ExecGetUsageAllocation instance initialized with the provided client and request payload.
func (c *Client) GetUsageAllocation(id string, limitCount int64) ExecGetUsageAllocation {
	return ExecGetUsageAllocation{
		client: c,
		req: &payloads.GetUsageAllocationRequestPayload{
			UniqueIdentifier: id,
			UsageLimitsCount: limitCount,
		},
	}
}

type ExecGetUsageAllocation = Executor[*payloads.GetUsageAllocationRequestPayload, *payloads.GetUsageAllocationResponsePayload]
