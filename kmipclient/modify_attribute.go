package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// ModifyAttribute creates an ExecModifyAttribute operation to modify an attribute of an existing object
// identified by the given unique identifier and attribute name. The returned ExecModifyAttribute can be
// further configured (e.g., with an index) and executed to perform the modification.
//
// Parameters:
//   - id: The unique identifier of the object whose attribute will be modified.
//   - name: The name of the attribute to modify.
//   - value: The new value to set for the attribute.
//
// Returns:
//   - ExecModifyAttribute: An executor for the modify attribute operation.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecModifyAttribute.
//   - If the attribute or object does not exist, or the server rejects the operation, an error will be returned during execution.
func (c *KMIPClient) ModifyAttribute(id string, name kmip.AttributeName, value any) ExecModifyAttribute {
	return ExecModifyAttribute{
		Executor[*payloads.ModifyAttributeRequestPayload, *payloads.ModifyAttributeResponsePayload]{
			client: c,
			req: &payloads.ModifyAttributeRequestPayload{
				UniqueIdentifier: id,
				Attribute:        kmip.Attribute{AttributeName: name, AttributeValue: value},
			},
		},
	}
}

// ExecModifyAttribute is a specialized executor for handling ModifyAttribute operations.
// It embeds the generic Executor with request and response payload types specific to
// the ModifyAttribute KMIP operation, facilitating the execution and management of
// attribute modification requests and their corresponding responses.
//
// Usage:
//
//	exec := client.ModifyAttribute("object-id", kmip.AttributeNameCustom, "new-value")
//	exec = exec.WithIndex(1) // Optional: set attribute index
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the modify attribute operation if the object or attribute does not exist,
//     or if the server returns an error.
type ExecModifyAttribute struct {
	Executor[*payloads.ModifyAttributeRequestPayload, *payloads.ModifyAttributeResponsePayload]
}

// WithIndex sets the AttributeIndex field of the request's Attribute to the provided index value.
// This is useful when modifying an attribute that supports multiple values and you want to specify
// the position of the attribute value to modify.
//
// Parameters:
//   - index: The index of the attribute value to modify.
//
// Returns:
//   - ExecModifyAttribute: The updated ExecModifyAttribute instance to allow for method chaining.
//
// Errors:
//   - No error is returned by this method. If the index is not supported by the server or is out of range,
//     an error may occur during execution.
func (ex ExecModifyAttribute) WithIndex(index int32) ExecModifyAttribute {
	ex.req.Attribute.AttributeIndex = &index
	return ex
}
