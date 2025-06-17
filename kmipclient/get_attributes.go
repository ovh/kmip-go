package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// GetAttributes retrieves the specified attributes for a given unique identifier.
// It returns an ExecGetAttributes instance which can be used to execute the request.
// Note that the returned value does not execute the operation. Exec() must be called to execute the operation.
//
// Parameters:
//   - id: The unique identifier for which attributes are to be retrieved.
//   - attributes: A variadic list of attribute names to be retrieved.
//
// Returns:
//   - ExecGetAttributes: An instance that can be used to execute the GetAttributes request.
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
//
// An updated ExecGetAttributes instance with the provided attribute names appended.
func (ex ExecGetAttributes) WithAttributes(names ...kmip.AttributeName) ExecGetAttributes {
	ex.req.AttributeName = append(ex.req.AttributeName, names...)
	return ex
}
