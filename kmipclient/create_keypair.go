package kmipclient

import (
	"math"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// CreateKeyPair initializes and returns an ExecCreateKeyPair instance with default template attributes
// for common, private, and public key templates. This method prepares the request payload for creating
// a new key pair using the KMIP protocol.
//
// Returns:
//   - ExecCreateKeyPair: An executor configured with the client and default key pair request payload.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecCreateKeyPair.
//   - If the server does not support key pair creation or the request is malformed, an error will be returned during execution.
func (c *KMIPClient) CreateKeyPair() ExecCreateKeyPair {
	return ExecCreateKeyPair{
		Executor[*payloads.CreateKeyPairRequestPayload, *payloads.CreateKeyPairResponsePayload]{
			client: c,
			req: &payloads.CreateKeyPairRequestPayload{
				CommonTemplateAttribute:     &kmip.TemplateAttribute{},
				PrivateKeyTemplateAttribute: &kmip.TemplateAttribute{},
				PublicKeyTemplateAttribute:  &kmip.TemplateAttribute{},
			},
		},
	}
}

// ExecCreateKeyPair is a specialized executor for handling CreateKeyPair operations.
// It embeds the generic Executor with request and response payload types specific to
// key pair creation, enabling execution of KMIP CreateKeyPair requests and processing
// of their responses.
//
// Usage:
//
//	exec := client.CreateKeyPair().RSA(2048, privateUsage, publicUsage)
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the key pair creation operation if the parameters are invalid,
//     the server does not support the requested algorithm or curve, or if the server returns an error.
type ExecCreateKeyPair struct {
	Executor[*payloads.CreateKeyPairRequestPayload, *payloads.CreateKeyPairResponsePayload]
}

// RSA configures the ExecCreateKeyPair to generate an RSA key pair with the specified bit length and usage masks.
// It sets the cryptographic algorithm to RSA, assigns the provided bit length, and applies the given usage masks
// to the public and private keys respectively. If the bit length is out of the valid int32 range, the function panics.
//
// Parameters:
//   - bitlen: The length of the RSA key in bits.
//   - privateUsage: The cryptographic usage mask for the private key.
//   - publicUsage: The cryptographic usage mask for the public key.
//
// Returns:
//   - ExecCreateKeyPairAttr: The configured key pair attributes for RSA key generation.
//
// Errors:
//   - Panics if bitlen is negative or exceeds the maximum int32 value.
//   - Errors may be returned when executing the operation if the server does not support the requested bit length.
func (ex ExecCreateKeyPair) RSA(bitlen int, privateUsage, publicUsage kmip.CryptographicUsageMask) ExecCreateKeyPairAttr {
	if bitlen > math.MaxInt32 || bitlen < 0 {
		panic("bitlen is out of range")
	}
	return ex.Common().
		WithAttribute(kmip.AttributeNameCryptographicAlgorithm, kmip.CryptographicAlgorithmRSA).
		WithAttribute(kmip.AttributeNameCryptographicLength, int32(bitlen)).
		PublicKey().WithAttribute(kmip.AttributeNameCryptographicUsageMask, publicUsage).
		PrivateKey().WithAttribute(kmip.AttributeNameCryptographicUsageMask, privateUsage).
		Common()
}

// ECDSA configures the ExecCreateKeyPair operation for generating an ECDSA key pair.
// It sets the cryptographic algorithm to ECDSA, specifies the curve and its bit length,
// and applies the provided cryptographic usage masks to the public and private keys.
//
// Parameters:
//   - curve: The recommended elliptic curve to use for key generation.
//   - privateUsage: The cryptographic usage mask for the private key.
//   - publicUsage: The cryptographic usage mask for the public key.
//
// Returns:
//   - ExecCreateKeyPairAttr: The configured key pair creation attributes.
//
// Errors:
//   - Errors may be returned when executing the operation if the server does not support the requested curve.
func (ex ExecCreateKeyPair) ECDSA(curve kmip.RecommendedCurve, privateUsage, publicUsage kmip.CryptographicUsageMask) ExecCreateKeyPairAttr {
	return ex.Common().
		WithAttribute(kmip.AttributeNameCryptographicAlgorithm, kmip.CryptographicAlgorithmECDSA).
		WithAttribute(kmip.AttributeNameCryptographicLength, curve.Bitlen()).
		WithAttribute(kmip.AttributeNameCryptographicDomainParameters, kmip.CryptographicDomainParameters{RecommendedCurve: curve}).
		PublicKey().WithAttribute(kmip.AttributeNameCryptographicUsageMask, publicUsage).
		PrivateKey().WithAttribute(kmip.AttributeNameCryptographicUsageMask, privateUsage).
		Common()
}

// Common returns an ExecCreateKeyPairAttr that provides access to the common template
// attributes and names within a CreateKeyPairRequestPayload. This method constructs
// an attribute executor for handling the common attributes and names, ensuring
// backward compatibility with existing structures. It is primarily used to facilitate
// attribute manipulation for key pair creation requests in the KMIP client.
//
// Usage:
//
//	attr := exec.Common().WithAttribute(...)
//	names := exec.Common().WithTemplates(...)
//
// Errors:
//   - No error is returned by this method. Errors may occur during execution if the attributes are not supported.
func (ex ExecCreateKeyPair) Common() ExecCreateKeyPairAttr {
	return ExecCreateKeyPairAttr{
		AttributeExecutor[*payloads.CreateKeyPairRequestPayload, *payloads.CreateKeyPairResponsePayload, ExecCreateKeyPairAttr]{
			ex.Executor,
			func(ckprp **payloads.CreateKeyPairRequestPayload) *[]kmip.Attribute {
				return &(*ckprp).CommonTemplateAttribute.Attribute
			},
			func(ae AttributeExecutor[*payloads.CreateKeyPairRequestPayload, *payloads.CreateKeyPairResponsePayload, ExecCreateKeyPairAttr]) ExecCreateKeyPairAttr {
				return ExecCreateKeyPairAttr{ae, func(ckprp *payloads.CreateKeyPairRequestPayload) *[]kmip.Name {
					//nolint:staticcheck // for backward compatibility
					return &ckprp.CommonTemplateAttribute.Name
				}}
			},
		},
		func(ckprp *payloads.CreateKeyPairRequestPayload) *[]kmip.Name {
			//nolint:staticcheck // for backward compatibility
			return &ckprp.CommonTemplateAttribute.Name
		},
	}
}

// PrivateKey returns an ExecCreateKeyPairAttr configured to operate on the
// PrivateKeyTemplateAttribute of a CreateKeyPairRequestPayload. This allows
// manipulation of private key attributes and names within the key pair creation
// request, supporting both attribute and name access for backward compatibility.
//
// Usage:
//
//	attr := exec.PrivateKey().WithAttribute(...)
//	names := exec.PrivateKey().WithTemplates(...)
//
// Errors:
//   - No error is returned by this method. Errors may occur during execution if the attributes are not supported.
func (ex ExecCreateKeyPair) PrivateKey() ExecCreateKeyPairAttr {
	return ExecCreateKeyPairAttr{
		AttributeExecutor[*payloads.CreateKeyPairRequestPayload, *payloads.CreateKeyPairResponsePayload, ExecCreateKeyPairAttr]{
			ex.Executor,
			func(ckprp **payloads.CreateKeyPairRequestPayload) *[]kmip.Attribute {
				return &(*ckprp).PrivateKeyTemplateAttribute.Attribute
			},
			func(ae AttributeExecutor[*payloads.CreateKeyPairRequestPayload, *payloads.CreateKeyPairResponsePayload, ExecCreateKeyPairAttr]) ExecCreateKeyPairAttr {
				return ExecCreateKeyPairAttr{ae, func(ckprp *payloads.CreateKeyPairRequestPayload) *[]kmip.Name {
					//nolint:staticcheck // for backward compatibility
					return &ckprp.PrivateKeyTemplateAttribute.Name
				}}
			},
		},
		func(ckprp *payloads.CreateKeyPairRequestPayload) *[]kmip.Name {
			//nolint:staticcheck // for backward compatibility
			return &ckprp.PrivateKeyTemplateAttribute.Name
		},
	}
}

// PublicKey returns an ExecCreateKeyPairAttr configured to operate on the PublicKeyTemplateAttribute
// of the CreateKeyPairRequestPayload. This allows for manipulation of public key attributes and names
// within the key pair creation request, supporting backward compatibility for legacy field usage.
//
// Usage:
//
//	attr := exec.PublicKey().WithAttribute(...)
//	names := exec.PublicKey().WithTemplates(...)
//
// Errors:
//   - No error is returned by this method. Errors may occur during execution if the attributes are not supported.
func (ex ExecCreateKeyPair) PublicKey() ExecCreateKeyPairAttr {
	return ExecCreateKeyPairAttr{
		AttributeExecutor[*payloads.CreateKeyPairRequestPayload, *payloads.CreateKeyPairResponsePayload, ExecCreateKeyPairAttr]{
			ex.Executor,
			func(ckprp **payloads.CreateKeyPairRequestPayload) *[]kmip.Attribute {
				return &(*ckprp).PublicKeyTemplateAttribute.Attribute
			},
			func(ae AttributeExecutor[*payloads.CreateKeyPairRequestPayload, *payloads.CreateKeyPairResponsePayload, ExecCreateKeyPairAttr]) ExecCreateKeyPairAttr {
				return ExecCreateKeyPairAttr{ae, func(ckprp *payloads.CreateKeyPairRequestPayload) *[]kmip.Name {
					//nolint:staticcheck // for backward compatibility
					return &ckprp.PublicKeyTemplateAttribute.Name
				}}
			},
		},
		func(ckprp *payloads.CreateKeyPairRequestPayload) *[]kmip.Name {
			//nolint:staticcheck // for backward compatibility
			return &ckprp.PublicKeyTemplateAttribute.Name
		},
	}
}

type ExecCreateKeyPairAttr struct {
	AttributeExecutor[*payloads.CreateKeyPairRequestPayload, *payloads.CreateKeyPairResponsePayload, ExecCreateKeyPairAttr]
	tmplFunc func(*payloads.CreateKeyPairRequestPayload) *[]kmip.Name
}

// Deprecated: Templates have been deprecated in KMIP v1.3.
func (ex ExecCreateKeyPairAttr) WithTemplates(names ...kmip.Name) ExecCreateKeyPairAttr {
	tmpl := ex.tmplFunc(ex.req)
	*tmpl = append(*tmpl, names...)
	return ex
}

// Deprecated: Templates have been deprecated in KMIP v1.3.
func (ex ExecCreateKeyPairAttr) WithTemplate(name string, nameType kmip.NameType) ExecCreateKeyPairAttr {
	ex.WithTemplates(kmip.Name{NameValue: name, NameType: nameType})
	return ex
}

func (ex ExecCreateKeyPairAttr) Common() ExecCreateKeyPairAttr {
	return ExecCreateKeyPair{ex.Executor}.Common()
}

func (ex ExecCreateKeyPairAttr) PrivateKey() ExecCreateKeyPairAttr {
	return ExecCreateKeyPair{ex.Executor}.PrivateKey()
}

func (ex ExecCreateKeyPairAttr) PublicKey() ExecCreateKeyPairAttr {
	return ExecCreateKeyPair{ex.Executor}.PublicKey()
}
