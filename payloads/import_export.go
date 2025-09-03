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
	ReplaceExisting bool `ttlv:",omitempty,version=v1.4.."`
	// KeyWrapType is an optional field that specifies the key wrapping type used for the imported key material.
	KeyWrapType kmip.KeyWrapType `ttlv:",omitempty,version=v1.4.."`
	// Attribute is an optional field that specifies additional attributes for the imported object.
	Attribute kmip.Attribute `ttlv:",omitempty,version=v1.4.."`
	// AuthenticatedEncryptionAdditionalData is a required field that specifies additional data for authenticated encryption.
	AuthenticatedEncryptionAdditionalData []byte `ttlv:",version=v1.4.."`
}

// Operation returns the operation type for the ImportRequestPayload.
func (a *ImportRequestPayload) Operation() kmip.Operation {
	return kmip.OperationImport
}

// ImportResponsePayload represents the payload for the Import operation response.
type ImportResponsePayload struct {
	// UniqueIdentifier is a required field that specifies the unique identifier of the imported object.
	UniqueIdentifier string `ttlv:",version=v1.4.."`
}

// Operation returns the operation type for the ImportResponsePayload.
func (a *ImportResponsePayload) Operation() kmip.Operation {
	return kmip.OperationImport
}

// ExportRequestPayload represents the payload for the Export operation request.
type ExportRequestPayload struct {
	// UniqueIdentifier is an optional field that specifies the unique identifier of the object to be exported.
	UniqueIdentifier string `ttlv:",omitempty,version=v1.4.."`
	// KeyFormatType is an optional field that specifies the format type of the exported key material.
	KeyFormatType kmip.KeyFormatType `ttlv:",omitempty,version=v1.4.."`
	// KeyWrapType is an optional field that specifies the key wrapping type used for the exported key material.
	KeyWrapType kmip.KeyWrapType `ttlv:",omitempty,version=v1.4.."`
	// KeyCompressionType is an optional field that specifies the compression type used for the exported key material.
	KeyCompressionType kmip.KeyCompressionType `ttlv:",omitempty,version=v1.4.."`
	// KeyWrappingSpecification is an optional field that specifies the key wrapping specification for the exported key material.
	KeyWrappingSpecification kmip.KeyWrappingSpecification `ttlv:",omitempty,version=v1.4.."`
}

// Operation returns the operation type for the ExportRequestPayload.
func (a *ExportRequestPayload) Operation() kmip.Operation {
	return kmip.OperationExport
}

// ExportResponsePayload represents the payload for the Export operation response.
type ExportResponsePayload struct {
	// ObjectType is a required field that specifies the type of the exported object.
	ObjectType kmip.ObjectType `ttlv:",version=v1.4.."`
	// UniqueIdentifier is a required field that specifies the unique identifier of the exported object.
	UniqueIdentifier string `ttlv:",version=v1.4.."`
	// Attribute is a required field that specifies additional attributes for the exported object.
	Attribute kmip.Attribute `ttlv:",version=v1.4.."`
	// AuthenticatedEncryptionAdditionalData is a required field that specifies additional data for authenticated encryption.
	AuthenticatedEncryptionAdditionalData []byte `ttlv:",version=v1.4.."`
}

// Operation returns the operation type for the ExportResponsePayload.
func (a *ExportResponsePayload) Operation() kmip.Operation {
	return kmip.OperationExport
}
