package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// ExecImport represents the execution of an import operation with the KMIP client.
type ExecImport struct {
	Executor[*payloads.ImportRequestPayload, *payloads.ImportResponsePayload]
}

// ExecExport represents the execution of an export operation with the KMIP client.
type ExecExport struct {
	Executor[*payloads.ExportRequestPayload, *payloads.ExportResponsePayload]
}

// ExecImportWantsAAD is a helper type that allows for fluent-style configuration of an import operation.
type ExecImportWantsAAD struct {
	req    *payloads.ImportRequestPayload
	client *Client
}

// Import initializes an import operation with the client.
func (c *Client) Import() ExecImportWantsAAD {
	return ExecImportWantsAAD{
		client: c,
		req:    &payloads.ImportRequestPayload{},
	}
}

// Export initializes an export operation with the client for a given key ID.
func (c *Client) Export(id string) ExecExport {
	return ExecExport{
		Executor[*payloads.ExportRequestPayload, *payloads.ExportResponsePayload]{
			client: c,
			req:    &payloads.ExportRequestPayload{UniqueIdentifier: id},
		},
	}
}

// WithReplaceExisting sets the ReplaceExisting flag in the import request.
func (ex ExecImportWantsAAD) WithReplaceExisting(replaceExisting bool) ExecImportWantsAAD {
	ex.req.ReplaceExisting = replaceExisting
	return ex
}

// WithKeyWrapType sets the KeyWrapType in the import request.
func (ex ExecImportWantsAAD) WithKeyWrapType(keyWrapType kmip.KeyWrapType) ExecImportWantsAAD {
	ex.req.KeyWrapType = keyWrapType
	return ex
}

// AAD sets the AuthenticatedEncryptionAdditionalData in the import request and finalizes the import operation.
func (ex ExecImportWantsAAD) AAD(aad []byte) ExecImport {
	ex.req.AuthenticatedEncryptionAdditionalData = aad
	return ExecImport{
		Executor[*payloads.ImportRequestPayload, *payloads.ImportResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}

// WithKeyFormatType sets the KeyFormatType in the export request.
func (ex ExecExport) WithKeyFormatType(keyFormatType kmip.KeyFormatType) ExecExport {
	ex.req.KeyFormatType = keyFormatType
	return ex
}

// WithKeyWrapType sets the KeyWrapType in the export request.
func (ex ExecExport) WithKeyWrapType(keyWrapType kmip.KeyWrapType) ExecExport {
	ex.req.KeyWrapType = keyWrapType
	return ex
}

// WithKeyCompressionType sets the KeyCompressionType in the export request.
func (ex ExecExport) WithKeyCompressionType(keyCompressionType kmip.KeyCompressionType) ExecExport {
	ex.req.KeyCompressionType = keyCompressionType
	return ex
}

// WithKeyWrappingSpecification sets the KeyWrappingSpecification in the export request.
func (ex ExecExport) WithKeyWrappingSpecification(keyWrappingSpecification kmip.KeyWrappingSpecification) ExecExport {
	ex.req.KeyWrappingSpecification = keyWrappingSpecification
	return ex
}
