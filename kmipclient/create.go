package kmipclient

import (
	"math"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// Create initializes and returns a new ExecCreateWantType instance associated with the current Client.
// This method is typically used to begin the creation process for a KMIP object using the client context.
func (c *KMIPClient) Create() ExecCreateWantType {
	return ExecCreateWantType{
		client: c,
	}
}

// ExecCreateWantType encapsulates the dependencies required to execute a create operation,
// primarily holding a reference to the Client used for communication with the KMIP server.
type ExecCreateWantType struct {
	client Client
}

// Object creates a new ExecCreate instance configured to create a KMIP object of the specified type,
// with the provided attributes. It constructs the appropriate CreateRequestPayload and sets up the
// attribute executor for further configuration or execution.
//
// Parameters:
//   - objectType: The KMIP object type to be created.
//   - attrs:      Optional list of KMIP attributes to associate with the object.
//
// Returns:
//   - ExecCreate: An executor for the create operation, allowing further configuration or execution.
func (ex ExecCreateWantType) Object(objectType kmip.ObjectType, attrs ...kmip.Attribute) ExecCreate {
	return ExecCreate{
		AttributeExecutor[*payloads.CreateRequestPayload, *payloads.CreateResponsePayload, ExecCreate]{
			Executor[*payloads.CreateRequestPayload, *payloads.CreateResponsePayload]{
				client: ex.client,
				req: &payloads.CreateRequestPayload{
					ObjectType:        objectType,
					TemplateAttribute: kmip.TemplateAttribute{Attribute: attrs},
				},
			},
			func(crp **payloads.CreateRequestPayload) *[]kmip.Attribute {
				return &(*crp).TemplateAttribute.Attribute
			},
			func(ae AttributeExecutor[*payloads.CreateRequestPayload, *payloads.CreateResponsePayload, ExecCreate]) ExecCreate {
				return ExecCreate{ae}
			},
		},
	}
}

// SymmetricKey configures the creation of a symmetric key object with the specified
// cryptographic algorithm, key length, and usage mask. It panics if the provided
// length is negative or exceeds the maximum value for an int32. The method sets
// the object type to SymmetricKey and attaches the relevant cryptographic attributes.
//
// Parameters:
//   - alg: The cryptographic algorithm to use for the symmetric key (e.g., AES, 3DES).
//   - length: The length of the key in bits. Must be between 0 and math.MaxInt32.
//   - usage: The intended usage mask for the key (bitmask of allowed operations).
//
// Returns:
//   - ExecCreate: The updated ExecCreate object with the symmetric key attributes set.
//
// Errors:
//   - Panics if length is negative or exceeds math.MaxInt32.
//   - Errors may be returned when executing the operation if the server does not support the requested algorithm or key length.
func (ex ExecCreateWantType) SymmetricKey(alg kmip.CryptographicAlgorithm, length int, usage kmip.CryptographicUsageMask) ExecCreate {
	if length > math.MaxInt32 || length < 0 {
		panic("length is out of range")
	}
	return ex.Object(kmip.ObjectTypeSymmetricKey).
		WithAttribute(kmip.AttributeNameCryptographicAlgorithm, alg).
		WithAttribute(kmip.AttributeNameCryptographicLength, int32(length)).
		WithAttribute(kmip.AttributeNameCryptographicUsageMask, usage)
}

// AES creates a symmetric key of the specified length using the AES cryptographic algorithm,
// and assigns the provided cryptographic usage mask. It returns an ExecCreate instance
// configured for AES key creation.
//
// Parameters:
//   - length: The length of the AES key in bits (e.g., 128, 192, 256).
//   - usage: The intended cryptographic usage mask for the key.
//
// Returns:
//   - ExecCreate: An instance configured for AES key creation.
//
// Errors:
//   - Panics if length is negative or exceeds math.MaxInt32.
//   - Errors may be returned when executing the operation if the server does not support the requested key length.
func (ex ExecCreateWantType) AES(length int, usage kmip.CryptographicUsageMask) ExecCreate {
	return ex.SymmetricKey(kmip.CryptographicAlgorithmAES, length, usage)
}

// TDES creates a symmetric key using the 3DES cryptographic algorithm with the specified key length and usage mask.
// It returns an ExecCreate configured for 3DES key creation.
//
// Parameters:
//   - length: The length of the 3DES key in bits.
//   - usage: The intended cryptographic usage mask for the key.
//
// Returns:
//   - ExecCreate: An instance configured for 3DES key creation.
//
// Deprecated: 3DES is considered insecure and shouldn't be used.
//
// Errors:
//   - Panics if length is negative or exceeds math.MaxInt32.
//   - Errors may be returned when executing the operation if the server does not support the requested key length.
func (ex ExecCreateWantType) TDES(length int, usage kmip.CryptographicUsageMask) ExecCreate {
	return ex.SymmetricKey(kmip.CryptographicAlgorithm3DES, length, usage)
}

// Skipjack creates a symmetric key with the SKIPJACK cryptographic algorithm and a key length of 80 bits.
// It sets the specified cryptographic usage mask for the key.
// Returns an ExecCreate instance configured with these parameters.
//
// Deprecated: SKIPJACK is insecure and shouldn't be used.
//
// Errors:
//   - Errors may be returned when executing the operation if the server does not support SKIPJACK.
func (ex ExecCreateWantType) Skipjack(usage kmip.CryptographicUsageMask) ExecCreate {
	return ex.SymmetricKey(kmip.CryptographicAlgorithmSKIPJACK, 80, usage)
}

// ExecCreate is a wrapper struct that embeds AttributeExecutor to facilitate the execution
// of KMIP Create operations. It manages the request and response payloads specific to the
// Create operation, providing type safety and reuse of attribute execution logic.
type ExecCreate struct {
	AttributeExecutor[*payloads.CreateRequestPayload, *payloads.CreateResponsePayload, ExecCreate]
}

// WithTemplates appends the provided KMIP names to the TemplateAttribute's Name slice
// in the ExecCreate request.
//
// Deprecated: Templates have been deprecated in KMIP v1.3.
func (ex ExecCreate) WithTemplates(names ...kmip.Name) ExecCreate {
	ex.req.TemplateAttribute.Name = append(ex.req.TemplateAttribute.Name, names...)
	return ex
}

// WithTemplate adds a new name with the specified value and type to the TemplateAttribute of the request.
//
// Deprecated: Templates have been deprecated in KMIP v1.3.
func (ex ExecCreate) WithTemplate(name string, nameType kmip.NameType) ExecCreate {
	ex.req.TemplateAttribute.Name = append(ex.req.TemplateAttribute.Name, kmip.Name{NameValue: name, NameType: nameType})
	return ex
}
