package payloads

import (
	"time"

	"github.com/ovh/kmip-go"
)

func init() {
	kmip.RegisterOperationPayload[RekeyKeyPairRequestPayload, RekeyKeyPairResponsePayload](kmip.OperationReKeyKeyPair)
}

// This request is used to generate a replacement key pair for an existing public/private key pair.
// It is analogous to the Create Key Pair operation, except that attributes of the replacement key pair are
// copied from the existing key pair, with the exception of the attributes listed in Random Number Generator 3.44
//
// As the replacement of the key pair takes over the name attribute for the existing public/private key pair,
// Re-key Key Pair SHOULD only be performed once on a given key pair.
//
// For both the existing public key and private key, the server SHALL create a Link attribute of Link Type Replacement Key
// pointing to the replacement public and private key, respectively.
// For both the replacement public and private key, the server SHALL create a Link attribute of Link Type Replaced Key
// pointing to the existing public and private key, respectively.
//
// The server SHALL copy the Private Key Unique Identifier of the replacement private key returned by this operation into the
// ID Placeholder variable.
//
// An Offset MAY be used to indicate the difference between the Initialization Date and the Activation Date of the replacement key pair.
// If no Offset is specified, the Activation Date and Deactivation Date values are copied from the existing key pair.
// If Offset is set and dates exist for the existing key pair, then the dates of the replacement key pair SHALL be set based on the
// dates of the existing key pair as follows
//   - Initial Date (IT1) -> Initial Date (IT2) > IT1
//   - Activation Date (AT1) -> Activation Date (AT2) =  IT2+ Offset
//   - Deactivation Date (DT1) -> Deactivation Date = DT1+(AT2- AT1)
//
// Attributes for the replacement key pair that are not copied from the existing key pair and which are handled in a specific way are:
//   - Private Key Unique Identifier: New value generated
//   - Public Key Unique Identifier: New value generated
//   - Name: Set to the name(s) of the existing public/private keys; all name attributes of the existing public/private keys are removed.
//   - Digest: Recomputed for both replacement public and private keys from the new public and private key values
//   - Usage Limits: The Total Bytes/Total Objects value is copied from the existing key pair, while the Byte Count/Object Count values are set to the Total Bytes/Total Objects.
//   - State: Set based on attributes values, such as dates.
//   - Initial Date: Set to the current time
//   - Destroy Date: Not set
//   - Compromise Occurrence Date: Not set
//   - Compromise Date: Not set
//   - Revocation Reason: Not set
//   - Link: Set to point to the existing public/private keys as the replaced public/private keys
//   - Last Change Date: Set to current time
//   - Random Number Generator: Set to the random number generator used for creating the new managed object. Not copied from the original object.
//
// For multi-instance attributes, the union of the values found in the templates and attributes of the Common, Private,
// and Public Key Template-Attribute is used. For single-instance attributes, the order of precedence is as follows:
//  1. attributes specified explicitly in the Private and Public Key Template-Attribute, then
//  2. attributes specified via templates in the Private and Public Key Template-Attribute, then
//  3. attributes specified explicitly in the Common Template-Attribute, then
//  4. attributes specified via templates in the Common Template-Attribute.
//
// If there are multiple templates in the Common, Private, or Public Key Template-Attribute, then the subsequent value
// of the single-instance attribute takes precedence.
type RekeyKeyPairRequestPayload struct {
	// Determines the existing Asymmetric key pair to be re-keyed.
	// If omitted, then the ID Placeholder is substituted by the server.
	PrivateKeyUniqueIdentifier string `ttlv:",omitempty"`
	// An Interval object indicating the difference between the Initialization date and
	// the Activation Date of the replacement key pair to be created.
	Offset *time.Duration
	// Specifies desired attributes in templates and/or as individual attributes that apply
	// to both the Private and Public Key Objects.
	//
	// The Template Managed Object is deprecated as of version 1.3 of this specification and MAY be
	// removed from subsequent versions of the specification. Individual Attributes SHOULD be used in
	// operations which currently support use of a Name within a Template-Attribute to reference a Template.
	CommonTemplateAttribute *kmip.TemplateAttribute
	// Specifies templates and/or attributes that apply to the Private Key Object. Order of precedence applies.
	//
	// The Template Managed Object is deprecated as of version 1.3 of this specification and MAY be
	// removed from subsequent versions of the specification. Individual Attributes SHOULD be used in
	//  operations which currently support use of a Name within a Template-Attribute to reference a Template.
	PrivateKeyTemplateAttribute *kmip.TemplateAttribute
	// Specifies templates and/or attributes that apply to the Public Key Object. Order of precedence applies.
	//
	// The Template Managed Object is deprecated as of version 1.3 of this specification and MAY be
	// removed from subsequent versions of the specification. Individual Attributes SHOULD be used in
	// operations which currently support use of a Name within a Template-Attribute to reference a Template.
	PublicKeyTemplateAttribute *kmip.TemplateAttribute
}

func (a *RekeyKeyPairRequestPayload) Operation() kmip.Operation {
	return kmip.OperationReKeyKeyPair
}

// Response for the Re-Key-Key Pair operation.
type RekeyKeyPairResponsePayload struct {
	// The Unique Identifier of the newly created replacement Private Key object.
	PrivateKeyUniqueIdentifier string
	// The Unique Identifier of the newly created replacement Public Key object.
	PublicKeyUniqueIdentifier string
	// An OPTIONAL list of attributes, for the Private Key Object, with values that were not specified in the request,
	// but have been implicitly set by the key management server.
	//
	// The Template Managed Object is deprecated as of version 1.3 of this specification and
	// MAY be removed from subsequent versions of the specification. Individual Attributes SHOULD be
	// used in operations which currently support use of a Name within a Template-Attribute to reference a Template.
	PrivateKeyTemplateAttribute *kmip.TemplateAttribute
	// An OPTIONAL list of attributes, for the Public Key Object, with values that were not specified in the request,
	// but have been implicitly set by the key management server.
	//
	// The Template Managed Object is deprecated as of version 1.3 of this specification and MAY be
	// removed from subsequent versions of the specification. Individual Attributes SHOULD be used in operations
	// which currently support use of a Name within a Template-Attribute to reference a Template.
	PublicKeyTemplateAttribute *kmip.TemplateAttribute
}

func (a *RekeyKeyPairResponsePayload) Operation() kmip.Operation {
	return kmip.OperationReKeyKeyPair
}
