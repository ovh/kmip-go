package payloads

import "github.com/ovh/kmip-go"

// init registers the Import and Export operation payloads with the KMIP package.
func init() {
	kmip.RegisterOperationPayload[ImportRequestPayload, ImportResponsePayload](kmip.OperationImport)
	kmip.RegisterOperationPayload[ExportRequestPayload, ExportResponsePayload](kmip.OperationExport)
}

// This operation requests the server to Import a Managed Object specified by its Unique Identifier.
// The request specifies the object being imported and all the attributes to be assigned to the object.
// The attribute rules for each attribute for “Initially set by” and “When implicitly set” SHALL NOT be enforced as all attributes
// MUST be set to the supplied values rather than any server generated values.
//
// Special authentication and authorization SHOULD be enforced to perform this request.
// Only the object owner or an authorized security officer SHOULD be allowed to issue this request.
//
// The response contains the Unique Identifier provided in the request or assigned by the server.
// The server SHALL copy the Unique Identifier returned by this operations into the ID Placeholder variable.
type ImportRequestPayload struct {
	// The Unique Identifier of the object to be imported.
	UniqueIdentifier string
	// A Boolean.  If specified and true then any existing object with the same Unique Identifier SHALL be replaced by this operation.
	// If absent or false then the operation SHALL fail if there is an existing object with the same Unique Identifier.
	ReplaceExisting bool `ttlv:",omitempty"`
	// If Not Wrapped then the server SHALL unwrap the object before storing it, and return an error if the wrapping key is not available.
	// Otherwise the server SHALL store the object as provided.
	KeyWrapType kmip.KeyWrapType `ttlv:",omitempty"`
	// All of the object’s Attributes.
	Attribute []kmip.Attribute `ttlv:",omitempty"`
	// The object value being imported, in the same manner as the Register operation.
	Object kmip.Object
}

// Operation returns the operation type for the ImportRequestPayload.
func (a *ImportRequestPayload) Operation() kmip.Operation {
	return kmip.OperationImport
}

// Response for the Import operation.
type ImportResponsePayload struct {
	// The Unique Identifier of the object.
	UniqueIdentifier string
}

// Operation returns the operation type for the ImportResponsePayload.
func (a *ImportResponsePayload) Operation() kmip.Operation {
	return kmip.OperationImport
}

// This operation requests that the server returns a Managed Object specified by its Unique Identifier, together with its attributes.
//
// The Key Format Type, Key Wrap Type, Key Compression Type and Key Wrapping Specification SHALL have the same semantics as for the Get operation.
// If the Managed Object has been Destroyed then the key material for the specified managed object SHALL not be returned in the response.
//
// The server SHALL copy the Unique Identifier returned by this operations into the ID Placeholder variable.
// Special authentication and authorization SHOULD be enforced to perform this request.
//
// Only the object owner or an authorized security officer SHOULD be allowed to issue this request.
type ExportRequestPayload struct {
	// Determines the object being requested. If omitted, then the IDPlaceholder value is used by the server as the Unique Identifier.
	UniqueIdentifier string `ttlv:",omitempty"`
	// Determines the key format type to be returned.
	KeyFormatType kmip.KeyFormatType `ttlv:",omitempty"`
	// Determines the Key Wrap Type of the returned key value.
	KeyWrapType kmip.KeyWrapType `ttlv:",omitempty"`
	// Determines the compression method for elliptic curve public keys.
	KeyCompressionType kmip.KeyCompressionType `ttlv:",omitempty"`
	// Specifies keys and other information for wrapping the returned object.
	KeyWrappingSpecification *kmip.KeyWrappingSpecification `ttlv:",omitempty"`
}

// Operation returns the operation type for the ExportRequestPayload.
func (a *ExportRequestPayload) Operation() kmip.Operation {
	return kmip.OperationExport
}

// Response for the Export operation.
type ExportResponsePayload struct {
	// Type of object.
	ObjectType kmip.ObjectType
	// The Unique Identifier of the object.
	UniqueIdentifier string
	// All of the object’s Attributes.
	Attribute []kmip.Attribute
	// The object value being returned, in the same manner as the Get operation.
	Object kmip.Object
}

// Operation returns the operation type for the ExportResponsePayload.
func (a *ExportResponsePayload) Operation() kmip.Operation {
	return kmip.OperationExport
}
