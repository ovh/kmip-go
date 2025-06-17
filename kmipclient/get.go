package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// Get creates an ExecGet instance to execute a KMIP Get operation.
// This function prepares a Get request for the object identified by the given unique identifier.
// The returned ExecGet must be executed using Exec or ExecContext to perform the operation.
//
// Parameters:
//   - id: Unique identifier of the KMIP object to retrieve.
//
// Returns:
//   - ExecGet: Executor for the Get operation, pre-filled with the unique identifier.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecGet.
func (c *Client) Get(id string) ExecGet {
	return ExecGet{
		Executor[*payloads.GetRequestPayload, *payloads.GetResponsePayload]{
			client: c,
			req: &payloads.GetRequestPayload{
				UniqueIdentifier: id,
			},
		},
	}
}

// ExecGet is a specialized executor for handling KMIP Get operations.
// It embeds the generic Executor with request and response payload types
// specific to the Get operation, enabling type-safe execution of Get requests.
//
// Use the WithKeyFormat, WithKeyWrapType, WithKeyCompression, or WithKeyWrapping methods
// to further customize the Get request before execution.
type ExecGet struct {
	Executor[*payloads.GetRequestPayload, *payloads.GetResponsePayload]
}

func (ex ExecGet) WithKeyFormat(format kmip.KeyFormatType) ExecGet {
	ex.req.KeyFormatType = format
	return ex
}

// WithKeyWrapType sets the KeyWrapType for the Get request.
// Use this to specify the desired wrapping format for the key material.
//
// Parameters:
//   - format: The desired key wrap type.
//
// Returns:
//   - ExecGet: The updated ExecGet with the KeyWrapType set.
//
// Errors:
//   - No error is returned by this method. If the wrap type is not supported by the server, an error may occur during execution.
func (ex ExecGet) WithKeyWrapType(format kmip.KeyFormatType) ExecGet {
	ex.req.KeyWrapType = format
	return ex
}

// WithKeyCompression sets the KeyCompressionType for the Get request.
// Use this to specify the desired compression for the key material.
//
// Parameters:
//   - compression: The desired key compression type.
//
// Returns:
//   - ExecGet: The updated ExecGet with the KeyCompressionType set.
//
// Errors:
//   - No error is returned by this method. If the compression type is not supported by the server, an error may occur during execution.
func (ex ExecGet) WithKeyCompression(compression kmip.KeyCompressionType) ExecGet {
	ex.req.KeyCompressionType = compression
	return ex
}

// WithKeyWrapping sets the KeyWrappingSpecification for the Get request.
// Use this to specify how the key material should be wrapped in the response.
//
// Parameters:
//   - spec: The key wrapping specification.
//
// Returns:
//   - ExecGet: The updated ExecGet with the KeyWrappingSpecification set.
//
// Errors:
//   - No error is returned by this method. If the wrapping specification is not supported by the server, an error may occur during execution.
func (ex ExecGet) WithKeyWrapping(spec kmip.KeyWrappingSpecification) ExecGet {
	ex.req.KeyWrappingSpecification = &spec
	return ex
}
