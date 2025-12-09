package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// ExecEncrypt is a specialized executor for handling Encrypt operations.
// It embeds the generic Executor with request and response payload types specific to
// the Encrypt KMIP operation, facilitating the execution and management of encrypt requests and their responses.
//
// Usage:
//
//	exec := client.Encrypt("key-id").WithIvCounterNonce(...).WithAAD(...).Data(...)
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the encrypt operation if the key is invalid,
//     the server rejects the operation, or the cryptographic parameters are not supported.
type ExecEncrypt struct {
	Executor[*payloads.EncryptRequestPayload, *payloads.EncryptResponsePayload]
}

// ExecDecrypt is a specialized executor for handling Decrypt operations.
// It embeds the generic Executor with request and response payload types specific to
// the Decrypt KMIP operation, facilitating the execution and management of decrypt requests and their responses.
//
// Usage:
//
//	exec := client.Decrypt("key-id").WithIvCounterNonce(...).WithAAD(...).WithAuthTag(...).Data(...)
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the decrypt operation if the key is invalid,
//     the server rejects the operation, or the cryptographic parameters are not supported.
type ExecDecrypt struct {
	Executor[*payloads.DecryptRequestPayload, *payloads.DecryptResponsePayload]
}

// ExecEncryptWantsData is a builder for configuring encryption parameters before providing the data to encrypt.
// Use WithIvCounterNonce, WithAAD, and WithCryptographicParameters to set encryption options, then call Data() to finalize.
type ExecEncryptWantsData struct {
	req    *payloads.EncryptRequestPayload
	client Client
}

// NewExecEncryptWantsData creates a new instance of ExecEncryptWantsData with the provided client and request payload.
// This function initializes the necessary components to configure encryption parameters before setting the data to be encrypted.
func NewExecEncryptWantsData(c Client, req *payloads.EncryptRequestPayload) ExecEncryptWantsData {
	return ExecEncryptWantsData{
		client: c,
		req:    req,
	}
}

// ExecDecryptWantsData is a builder for configuring decryption parameters before providing the data to decrypt.
// Use WithIvCounterNonce, WithAAD, WithCryptographicParameters, and WithAuthTag to set decryption options, then call Data() to finalize.
type ExecDecryptWantsData struct {
	req    *payloads.DecryptRequestPayload
	client Client
}

// NewExecDecryptWantsData creates a new instance of ExecDecryptWantsData with the provided client and request payload.
// This function initializes the necessary components to configure encryption parameters before setting the data to be encrypted.
func NewExecDecryptWantsData(c Client, req *payloads.DecryptRequestPayload) ExecDecryptWantsData {
	return ExecDecryptWantsData{
		client: c,
		req:    req,
	}
}

// Encrypt creates an ExecEncryptWantsData builder for encrypting data with the specified key ID.
// Returns an ExecEncryptWantsData that can be further configured before calling Data().
func (c *KMIPClient) Encrypt(id string) ExecEncryptWantsData {
	return ExecEncryptWantsData{
		client: c,
		req: &payloads.EncryptRequestPayload{
			UniqueIdentifier: id,
		},
	}
}

// Decrypt creates an ExecDecryptWantsData builder for decrypting data with the specified key ID.
// Returns an ExecDecryptWantsData that can be further configured before calling Data().
func (c *KMIPClient) Decrypt(id string) ExecDecryptWantsData {
	return ExecDecryptWantsData{
		client: c,
		req: &payloads.DecryptRequestPayload{
			UniqueIdentifier: id,
		},
	}
}

// WithIvCounterNonce sets the IV/counter/nonce for the encryption or decryption operation.
// Returns the updated builder for method chaining.
func (ex ExecEncryptWantsData) WithIvCounterNonce(iv []byte) ExecEncryptWantsData {
	ex.req.IVCounterNonce = iv
	return ex
}

// WithIvCounterNonce sets the IV/counter/nonce for the encryption or decryption operation.
// Returns the updated builder for method chaining.
func (ex ExecDecryptWantsData) WithIvCounterNonce(iv []byte) ExecDecryptWantsData {
	ex.req.IVCounterNonce = iv
	return ex
}

// WithAAD sets the additional authenticated data (AAD) for the encryption or decryption operation.
// Returns the updated builder for method chaining.
func (ex ExecEncryptWantsData) WithAAD(aad []byte) ExecEncryptWantsData {
	ex.req.AuthenticatedEncryptionAdditionalData = aad
	return ex
}

// WithAAD sets the additional authenticated data (AAD) for the encryption or decryption operation.
// Returns the updated builder for method chaining.
func (ex ExecDecryptWantsData) WithAAD(aad []byte) ExecDecryptWantsData {
	ex.req.AuthenticatedEncryptionAdditionalData = aad
	return ex
}

// WithCryptographicParameters sets the cryptographic parameters for the encryption or decryption operation.
// Returns the updated builder for method chaining.
func (ex ExecEncryptWantsData) WithCryptographicParameters(params kmip.CryptographicParameters) ExecEncryptWantsData {
	ex.req.CryptographicParameters = &params
	return ex
}

// WithCryptographicParameters sets the cryptographic parameters for the encryption or decryption operation.
// Returns the updated builder for method chaining.
func (ex ExecDecryptWantsData) WithCryptographicParameters(params kmip.CryptographicParameters) ExecDecryptWantsData {
	ex.req.CryptographicParameters = &params
	return ex
}

// WithAuthTag sets the authentication tag for the decryption operation (for AEAD modes).
// Returns the updated builder for method chaining.
func (ex ExecDecryptWantsData) WithAuthTag(tag []byte) ExecDecryptWantsData {
	ex.req.AuthenticatedEncryptionTag = tag
	return ex
}

// Data finalizes the encryption or decryption request by providing the data to be processed.
// Returns the corresponding ExecEncrypt or ExecDecrypt executor.
func (ex ExecEncryptWantsData) Data(data []byte) ExecEncrypt {
	ex.req.Data = data
	return ExecEncrypt{
		Executor[*payloads.EncryptRequestPayload, *payloads.EncryptResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}

// Data finalizes the encryption or decryption request by providing the data to be processed.
// Returns the corresponding ExecEncrypt or ExecDecrypt executor.
func (ex ExecDecryptWantsData) Data(data []byte) ExecDecrypt {
	ex.req.Data = data
	return ExecDecrypt{
		Executor[*payloads.DecryptRequestPayload, *payloads.DecryptResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}
