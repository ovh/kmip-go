package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// Get creates an ExecGet instance to execute a KMIP Get operation.
// It takes a unique identifier as a parameter and returns an ExecGet
// which contains the request payload with the provided unique identifier.
//
// Calling this function does not execute the operation. You must call the ExecGet.Exec method to execute the operation.
//
// Parameters:
//   - id: A string representing the unique identifier of the object to be retrieved.
//
// Returns:
//
//   - ExecGet: An instance of ExecGet containing the request payload with the unique identifier.
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

type ExecGet struct {
	Executor[*payloads.GetRequestPayload, *payloads.GetResponsePayload]
}

func (ex ExecGet) WithKeyFormat(format kmip.KeyFormatType) ExecGet {
	ex.req.KeyFormatType = format
	return ex
}

func (ex ExecGet) WithKeyWrapType(format kmip.KeyFormatType) ExecGet {
	ex.req.KeyWrapType = format
	return ex
}

func (ex ExecGet) WithKeyCompression(compression kmip.KeyCompressionType) ExecGet {
	ex.req.KeyCompressionType = compression
	return ex
}

func (ex ExecGet) WithKeyWrapping(spec kmip.KeyWrappingSpecification) ExecGet {
	ex.req.KeyWrappingSpecification = &spec
	return ex
}
