package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// ExecImport represents the execution of an import operation with the KMIP client.
type ExecImport struct {
	AttributeExecutor[*payloads.ImportRequestPayload, *payloads.ImportResponsePayload, ExecImport]
}

// ExecExport represents the execution of an export operation with the KMIP client.
type ExecExport struct {
	Executor[*payloads.ExportRequestPayload, *payloads.ExportResponsePayload]
}

// Import initializes an import operation with the client.
func (c *Client) Import(id string, object kmip.Object) ExecImport {
	return ExecImport{
		AttributeExecutor[*payloads.ImportRequestPayload, *payloads.ImportResponsePayload, ExecImport]{
			Executor[*payloads.ImportRequestPayload, *payloads.ImportResponsePayload]{
				client: c,
				req: &payloads.ImportRequestPayload{
					UniqueIdentifier: id,
				},
			},
			func(rrp **payloads.ImportRequestPayload) *[]kmip.Attribute {
				return &(*rrp).Attribute
			},
			func(ae AttributeExecutor[*payloads.ImportRequestPayload, *payloads.ImportResponsePayload, ExecImport]) ExecImport {
				return ExecImport{ae}
			},
		},
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
func (ex ExecImport) WithReplaceExisting(replaceExisting bool) ExecImport {
	ex.req.ReplaceExisting = replaceExisting
	return ex
}

// WithKeyWrapType sets the KeyWrapType in the import request.
func (ex ExecImport) WithKeyWrapType(keyWrapType kmip.KeyWrapType) ExecImport {
	ex.req.KeyWrapType = keyWrapType
	return ex
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
func (ex ExecExport) WithKeyWrappingSpecification(keyWrappingSpecification *kmip.KeyWrappingSpecification) ExecExport {
	ex.req.KeyWrappingSpecification = keyWrappingSpecification
	return ex
}
