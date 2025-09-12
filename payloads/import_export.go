package payloads

import "github.com/ovh/kmip-go"

// init registers the Import and Export operation payloads with the KMIP package.
func init() {
	kmip.RegisterOperationPayload[ImportRequestPayload, ImportResponsePayload](kmip.OperationImport)
	kmip.RegisterOperationPayload[ExportRequestPayload, ExportResponsePayload](kmip.OperationExport)
}

// ImportRequestPayload represents the payload for the Import operation request.
type ImportRequestPayload struct {
	// UniqueIdentifier is an optional field that specifies the unique identifier of the object to be imported.
	UniqueIdentifier string
	// ReplaceExisting is an optional field that specifies whether to replace an existing object with the imported one.
	ReplaceExisting bool `ttlv:",omitempty"`
	// KeyWrapType is an optional field that specifies the key wrapping type used for the imported key material.
	KeyWrapType kmip.KeyWrapType `ttlv:",omitempty"`
	// Attribute is an optional field that specifies additional attributes for the imported object.
	Attribute []kmip.Attribute `ttlv:",omitempty"`
	// Object is a required field that specifies the object to be imported.
	Object kmip.Object
}

// Operation returns the operation type for the ImportRequestPayload.
func (a *ImportRequestPayload) Operation() kmip.Operation {
	return kmip.OperationImport
}

// ImportResponsePayload represents the payload for the Import operation response.
type ImportResponsePayload struct {
	// UniqueIdentifier is a required field that specifies the unique identifier of the imported object.
	UniqueIdentifier string
}

// Operation returns the operation type for the ImportResponsePayload.
func (a *ImportResponsePayload) Operation() kmip.Operation {
	return kmip.OperationImport
}

// ExportRequestPayload represents the payload for the Export operation request.
type ExportRequestPayload struct {
	// UniqueIdentifier is an optional field that specifies the unique identifier of the object to be exported.
	UniqueIdentifier string `ttlv:",omitempty"`
	// KeyFormatType is an optional field that specifies the format type of the exported key material.
	KeyFormatType kmip.KeyFormatType `ttlv:",omitempty"`
	// KeyWrapType is an optional field that specifies the key wrapping type used for the exported key material.
	KeyWrapType kmip.KeyWrapType `ttlv:",omitempty"`
	// KeyCompressionType is an optional field that specifies the compression type used for the exported key material.
	KeyCompressionType kmip.KeyCompressionType `ttlv:",omitempty"`
	// KeyWrappingSpecification is an optional field that specifies the key wrapping specification for the exported key material.
	KeyWrappingSpecification kmip.KeyWrappingSpecification `ttlv:",omitempty"`
}

// Operation returns the operation type for the ExportRequestPayload.
func (a *ExportRequestPayload) Operation() kmip.Operation {
	return kmip.OperationExport
}

// ExportResponsePayload represents the payload for the Export operation response.
type ExportResponsePayload struct {
	// ObjectType is a required field that specifies the type of the exported object.
	ObjectType kmip.ObjectType
	// UniqueIdentifier is a required field that specifies the unique identifier of the exported object.
	UniqueIdentifier string
	// Attribute is a required field that specifies additional attributes for the exported object.
	Attribute []kmip.Attribute
	// The object being returned.
	Object kmip.Object
}

// Operation returns the operation type for the ExportResponsePayload.
func (a *ExportResponsePayload) Operation() kmip.Operation {
	return kmip.OperationExport
}
