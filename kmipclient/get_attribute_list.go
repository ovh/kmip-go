package kmipclient

import "github.com/ovh/kmip-go/payloads"

// GetAttributeList creates an ExecGetAttributeList operation to retrieve the list of attribute names
// for the object identified by the given unique identifier. The returned ExecGetAttributeList can be
// executed to obtain the list of attribute names supported by the object.
//
// Parameters:
//   - id: The unique identifier of the object whose attribute list is to be retrieved.
//
// Returns:
//   - ExecGetAttributeList: An executor for the get attribute list operation.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecGetAttributeList.
//   - If the object does not exist or the server rejects the operation, an error will be returned during execution.
func (c *KMIPClient) GetAttributeList(id string) ExecGetAttributeList {
	return ExecGetAttributeList{
		client: c,
		req: &payloads.GetAttributeListRequestPayload{
			UniqueIdentifier: id,
		},
	}
}

// ExecGetAttributeList is a type alias for Executor that operates on GetAttributeListRequestPayload and GetAttributeListResponsePayload.
// It is used to execute get attribute list operations within the KMIP client, handling the request and response payloads
// specific to the get attribute list functionality.
//
// Usage:
//
//	exec := client.GetAttributeList("object-id")
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the get attribute list operation if the object does not exist,
//     or if the server returns an error.
type ExecGetAttributeList = Executor[*payloads.GetAttributeListRequestPayload, *payloads.GetAttributeListResponsePayload]
