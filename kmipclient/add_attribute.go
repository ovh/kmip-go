package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// AddAttribute creates an ExecAddAttribute operation to add a new attribute to an existing object
// identified by the given unique identifier. The attribute is specified by its name and value.
//
// Parameters:
//   - id: The unique identifier of the object to which the attribute will be added.
//   - name: The name of the attribute to add.
//   - value: The value of the attribute to add. This can be any type supported by the KMIP attribute system.
//
// Returns:
//   - ExecAddAttribute: An executor that can be used to perform the add attribute operation.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecAddAttribute.
//   - If the attribute name or value is not supported by the server, an error will be returned during execution.
func (c *Client) AddAttribute(id string, name kmip.AttributeName, value any) ExecAddAttribute {
	return ExecAddAttribute{
		Executor[*payloads.AddAttributeRequestPayload, *payloads.AddAttributeResponsePayload]{
			client: c,
			req: &payloads.AddAttributeRequestPayload{
				UniqueIdentifier: id,
				Attribute:        kmip.Attribute{AttributeName: name, AttributeValue: value},
			},
		},
	}
}

// ExecAddAttribute is a specialized executor for handling AddAttribute operations.
// It embeds the generic Executor with request and response payload types specific to
// the AddAttribute KMIP operation, facilitating the execution and management of
// attribute addition requests and their corresponding responses.
//
// Usage:
//
//	exec := client.AddAttribute("object-id", kmip.AttributeNameCustom, "value")
//	exec = exec.WithIndex(1) // Optional: set attribute index
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the add attribute operation if the object does not exist,
//     if the attribute is not supported, or if the server returns an error.
type ExecAddAttribute struct {
	Executor[*payloads.AddAttributeRequestPayload, *payloads.AddAttributeResponsePayload]
}

// WithIndex sets the AttributeIndex field of the request's Attribute to the provided index value.
// This is useful when adding an attribute that supports multiple values and you want to specify
// the position of the new attribute value.
//
// Parameters:
//   - index: The index at which to add the attribute value.
//
// Returns:
//   - ExecAddAttribute: The updated ExecAddAttribute instance to allow for method chaining.
//
// Errors:
//   - No error is returned by this method. If the index is not supported by the server or is out of range,
//     an error may occur during execution.
func (ex ExecAddAttribute) WithIndex(index int32) ExecAddAttribute {
	ex.req.Attribute.AttributeIndex = &index
	return ex
}
