package payloads

import "github.com/ovh/kmip-go"

func init() {
	kmip.RegisterOperationPayload[DeriveKeyRequestPayload, DeriveKeyResponsePayload](kmip.OperationDeriveKey)
}

// This request is used to derive a Symmetric Key or Secret Data object from keys or Secret Data
// objects that are already known to the key management system. The request SHALL only apply to
// Managed Cryptographic Objects that have the Derive Key bit set in the Cryptographic Usage Mask
// attribute of the specified Managed Object.
//
// The fields in the request specify the Unique Identifiers of the keys or Secret Data objects to be
// used for derivation, the method to be used to perform the derivation, and any parameters needed
// by the specified method.
type DeriveKeyRequestPayload struct {
	// Determines the type of object to be created.
	ObjectType kmip.ObjectType
	// Determines the object or objects to be used to derive a new key.
	// Note that the current value of the ID Placeholder SHALL NOT be used in place of a Unique
	// Identifier in this operation. MAY be repeated.
	UniqueIdentifier []string
	// An Enumeration object specifying the method to be used to derive the new key.
	DerivationMethod kmip.DerivationMethod
	// A Structure object containing the parameters needed by the specified derivation method.
	DerivationParameters kmip.DerivationParameters
	// Specifies desired attributes to be associated with the new object using templates and/or individual attributes;
	// the length and algorithm SHALL always be specified for the creation of a symmetric key.
	//
	// The Template Managed Object is deprecated as of version 1.3 of this specification and MAY be removed from subsequent versions of the specification.
	// Individual Attributes SHOULD be used in operations which currently support use of a Name within a Template-Attribute to reference a Template.
	TemplateAttribute kmip.TemplateAttribute
}

func (pl *DeriveKeyRequestPayload) Operation() kmip.Operation {
	return kmip.OperationDeriveKey
}

// Response for the DeriveKey operation.
//
// The response contains the Unique Identifier of the newly created derived key or Secret Data object.
type DeriveKeyResponsePayload struct {
	// The Unique Identifier of the newly derived key or Secret Data object.
	UniqueIdentifier string
	// An OPTIONAL list of object attributes with values that were not specified in the request, but have been implicitly set by the key management server.
	//
	// The Template Managed Object is deprecated as of version 1.3 of this specification and MAY be removed from subsequent versions of the specification.
	// Individual Attributes SHOULD be used in operations which currently support use of a Name within a Template-Attribute to reference a Template.
	TemplateAttribute *kmip.TemplateAttribute `ttlv:",omitempty"`
}

func (pl *DeriveKeyResponsePayload) Operation() kmip.Operation {
	return kmip.OperationDeriveKey
}
