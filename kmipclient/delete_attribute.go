package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// DeleteAttribute creates an ExecDeleteAttribute operation to remove an attribute from an existing object
// identified by the given unique identifier and attribute name. The returned ExecDeleteAttribute can be
// further configured (e.g., with an index) and executed to perform the deletion.
//
// Parameters:
//   - id: The unique identifier of the object from which the attribute will be deleted.
//   - name: The name of the attribute to delete.
//
// Returns:
//   - ExecDeleteAttribute: An executor for the delete attribute operation.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecDeleteAttribute.
//   - If the attribute or object does not exist, or the server rejects the operation, an error will be returned during execution.
func (c *Client) DeleteAttribute(id string, name kmip.AttributeName) ExecDeleteAttribute {
	return ExecDeleteAttribute{
		Executor[*payloads.DeleteAttributeRequestPayload, *payloads.DeleteAttributeResponsePayload]{
			client: c,
			req: &payloads.DeleteAttributeRequestPayload{
				UniqueIdentifier: id,
				AttributeName:    name,
			},
		},
	}
}

// ExecDeleteAttribute is a specialized executor for handling DeleteAttribute operations.
// It embeds the generic Executor with request and response payload types specific to
// the DeleteAttribute KMIP operation, facilitating the execution and management of
// attribute deletion requests and their corresponding responses.
//
// Usage:
//
//	exec := client.DeleteAttribute("object-id", kmip.AttributeNameCustom)
//	exec = exec.WithIndex(1) // Optional: set attribute index
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the delete attribute operation if the object or attribute does not exist,
//     or if the server returns an error.
type ExecDeleteAttribute struct {
	Executor[*payloads.DeleteAttributeRequestPayload, *payloads.DeleteAttributeResponsePayload]
}

// WithIndex sets the AttributeIndex field of the request to the provided index value.
// This is useful when deleting an attribute that supports multiple values and you want to specify
// the position of the attribute value to delete.
//
// Parameters:
//   - index: The index of the attribute value to delete.
//
// Returns:
//   - ExecDeleteAttribute: The updated ExecDeleteAttribute instance to allow for method chaining.
//
// Errors:
//   - No error is returned by this method. If the index is not supported by the server or is out of range,
//     an error may occur during execution.
func (ex ExecDeleteAttribute) WithIndex(index int32) ExecDeleteAttribute {
	ex.req.AttributeIndex = &index
	return ex
}
