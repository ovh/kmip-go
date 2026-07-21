package payloads

import "github.com/ovh/kmip-go"

func init() {
	kmip.RegisterOperationPayload[HashRequestPayload, HashResponsePayload](kmip.OperationHash)
}

// This operation requests the server to perform a hash operation on the data provided.
// The request contains information about the cryptographic parameters (hash algorithm) and the data to be hashed.
// The response contains the result of the hash operation.
// The success or failure of the operation is indicated by the Result Status (and if failure the Result Reason) in the response header.
type HashRequestPayload struct {
	// The Cryptographic Parameters (Hashing Algorithm) corresponding to the particular hash method requested.
	CryptographicParameters kmip.CryptographicParameters
	// The data to be hashed (as a Byte String). Required for single-part, optional for multi-part.
	Data []byte `ttlv:",omitempty"`
	// Specifies the existing stream or by-parts cryptographic operation
	// (as returned from a previous call to this operation).
	CorrelationValue []byte `ttlv:",omitempty,version=v1.3.."`
	// Initial operation as Boolean.
	InitIndicator *bool `ttlv:",version=v1.3.."`
	// Final operation as Boolean.
	FinalIndicator *bool `ttlv:",version=v1.3.."`
}

func (pl *HashRequestPayload) Operation() kmip.Operation {
	return kmip.OperationHash
}

// Response for the hash operation.
//
// The response contains the result of the hash operation.
type HashResponsePayload struct {
	// The hashed data (as a Byte String). Required for single-part, optional for multi-part.
	Data []byte `ttlv:",omitempty"`
	// Specifies the stream or by-parts value to be provided in subsequent calls to this operation
	// for performing cryptographic operations.
	CorrelationValue []byte `ttlv:",omitempty,version=v1.3.."`
}

func (pl *HashResponsePayload) Operation() kmip.Operation {
	return kmip.OperationHash
}
