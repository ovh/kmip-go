package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// GetAttributes retrieves the specified attributes for a given unique identifier.
// It returns an ExecGetAttributes instance which can be used to execute the request.
// Note that the returned value does not execute the operation. Exec() or ExecContext() must be called to execute the operation.
//
// Parameters:
//   - id: The unique identifier for which attributes are to be retrieved.
//   - attributes: A variadic list of attribute names to be retrieved.
//
// Returns:
//   - ExecGetAttributes: An instance that can be used to execute the GetAttributes request.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecGetAttributes.
//   - If the object does not exist or the server rejects the operation, an error will be returned during execution.
func (c *Client) GetAttributes(id string, attributes ...kmip.AttributeName) ExecGetAttributes {
	return ExecGetAttributes{
		Executor[*payloads.GetAttributesRequestPayload, *payloads.GetAttributesResponsePayload]{
			client: c,
			req: &payloads.GetAttributesRequestPayload{
				UniqueIdentifier: id,
			},
		},
	}.WithAttributes(attributes...)
}

// ExecGetAttributes is a specialized executor for handling GetAttributes operations.
// It embeds the generic Executor with request and response payload types specific to
// the GetAttributes KMIP operation, facilitating the execution and management of
// attribute retrieval requests and their corresponding responses.
//
// Usage:
//
//	exec := client.GetAttributes("object-id", kmip.AttributeNameCustom)
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the get attributes operation if the object does not exist,
//     or if the server returns an error.
type ExecGetAttributes struct {
	Executor[*payloads.GetAttributesRequestPayload, *payloads.GetAttributesResponsePayload]
}

// WithAttributes appends the provided attribute names to the request's AttributeName slice
// and returns the updated ExecGetAttributes instance.
//
// Parameters:
//   - names: A variadic list of kmip.AttributeName to be added to the request.
//
// Returns:
//   - ExecGetAttributes: An updated ExecGetAttributes instance with the provided attribute names appended.
//
// Errors:
//   - No error is returned by this method. If the attribute names are not supported by the server,
//     an error may occur during execution.
func (ex ExecGetAttributes) WithAttributes(names ...kmip.AttributeName) ExecGetAttributes {
	ex.req.AttributeName = append(ex.req.AttributeName, names...)
	return ex
}
