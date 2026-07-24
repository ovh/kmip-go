package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// ExecDeriveKey is a specialized executor for handling DeriveKey operations.
// It embeds the generic Executor with request and response payload types specific to
// the DeriveKey KMIP operation, facilitating the execution and management of key derivation requests and their responses.
//
// Usage:
//
//	resp, err := client.DeriveKey().ObjectType(kmip.ObjectTypeSymmetricKey).
//		WithUniqueIdentifiers("base-key-id").
//		WithDerivationMethod(kmip.DerivationMethodPBKDF2).
//		WithDerivationParameters(params).
//		ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the derive key operation if the base key is invalid,
//     the derivation method is not supported, or the derivation parameters are incorrect.
type ExecDeriveKey struct {
	Executor[*payloads.DeriveKeyRequestPayload, *payloads.DeriveKeyResponsePayload]
}

// DeriveKey creates an ExecDeriveKey executor for deriving a new key from existing keys or secret data.
func (c *Client) DeriveKey() ExecDeriveKey {
	return ExecDeriveKey{
		Executor[*payloads.DeriveKeyRequestPayload, *payloads.DeriveKeyResponsePayload]{
			client: c,
			req:    &payloads.DeriveKeyRequestPayload{},
		},
	}
}

// ObjectType sets the ObjectType field of the request.
// This determines the type of object to be created (e.g., SymmetricKey, SecretData).
//
// Parameters:
//   - objectType: The type of object to create.
func (ex ExecDeriveKey) ObjectType(objectType kmip.ObjectType) ExecDeriveKey {
	ex.req.ObjectType = objectType
	return ex
}

// WithUniqueIdentifiers sets the UniqueIdentifier field of the request.
// These are the objects to be used to derive a new key. MAY be repeated.
//
// Parameters:
//   - ids: One or more unique identifiers of the objects to use for derivation.
func (ex ExecDeriveKey) WithUniqueIdentifiers(ids ...string) ExecDeriveKey {
	ex.req.UniqueIdentifier = ids
	return ex
}

// WithDerivationMethod sets the DerivationMethod field of the request.
// This specifies the method to be used to derive the new key.
//
// Parameters:
//   - method: The derivation method (e.g., PBKDF2, HASH, HMAC).
func (ex ExecDeriveKey) WithDerivationMethod(method kmip.DerivationMethod) ExecDeriveKey {
	ex.req.DerivationMethod = method
	return ex
}

// WithDerivationParameters sets the DerivationParameters field of the request.
// These contain the parameters needed by the specified derivation method.
//
// Parameters:
//   - params: The derivation parameters.
func (ex ExecDeriveKey) WithDerivationParameters(params kmip.DerivationParameters) ExecDeriveKey {
	ex.req.DerivationParameters = params
	return ex
}

// WithTemplateAttribute sets the TemplateAttribute field of the request.
// This specifies desired attributes to be associated with the new object.
//
// Parameters:
//   - template: The template attribute containing desired object attributes.
func (ex ExecDeriveKey) WithTemplateAttribute(template kmip.TemplateAttribute) ExecDeriveKey {
	ex.req.TemplateAttribute = template
	return ex
}
