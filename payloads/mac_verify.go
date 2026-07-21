package payloads

import "github.com/ovh/kmip-go"

func init() {
	kmip.RegisterOperationPayload[MACRequestPayload, MACResponsePayload](kmip.OperationMAC)
	kmip.RegisterOperationPayload[MACVerifyRequestPayload, MACVerifyResponsePayload](kmip.OperationMACVerify)
}

// This operation requests the server to perform a MAC operation on the data provided using a
// Managed Cryptographic Object as the key for the MAC operation.
//
// The request contains the Unique Identifier of the Managed Cryptographic Object that is the key
// and the data to be processed. The cryptographic parameters MAY be omitted from the request
// as they can be specified as associated attributes of the Managed Cryptographic Object.
//
// If the Managed Cryptographic Object referenced has a Usage Limits attribute then the server SHALL
// obtain an allocation from the current Usage Limits value prior to performing the MAC operation.
// If the allocation is unable to be obtained the operation SHALL return with a result status of
// Operation Failed and result reason of Permission Denied.
type MACRequestPayload struct {
	// The Unique Identifier of the Managed Cryptographic Object that is the key to use for the MAC operation.
	// If omitted, then the ID Placeholder value SHALL be used by the server as the Unique Identifier.
	UniqueIdentifier string `ttlv:",omitempty"`
	// The Cryptographic Parameters (MAC Algorithm or Cryptographic Algorithm and Hashing Algorithm)
	// corresponding to the particular MAC generation method requested. If omitted then the
	// Cryptographic Parameters associated with the Managed Cryptographic Object with the lowest
	// Attribute Index SHALL be used.
	CryptographicParameters *kmip.CryptographicParameters `ttlv:",omitempty"`
	// The data to be processed. Mandatory for single-part operation, optional for multi-part.
	Data []byte `ttlv:",omitempty"`
	// Specifies the existing stream or by-parts cryptographic operation
	// (as returned from a previous call to this operation).
	CorrelationValue []byte `ttlv:",omitempty,version=v1.3.."`
	// Initial operation.
	InitIndicator *bool `ttlv:",version=v1.3.."`
	// Final operation.
	FinalIndicator *bool `ttlv:",version=v1.3.."`
}

func (pl *MACRequestPayload) Operation() kmip.Operation {
	return kmip.OperationMAC
}

// Response for the MAC operation.
//
// The response contains the Unique Identifier of the Managed Cryptographic Object used as the key and
// the result of the MAC operation.
//
// The success or failure of the operation is indicated by the Result Status (and if failure the Result Reason)
// in the response header.
type MACResponsePayload struct {
	// The Unique Identifier of the Managed Cryptographic Object that is the key used for the MAC operation.
	UniqueIdentifier string
	// The MAC data. Mandatory for single-part operation, not for multi-part.
	MACData []byte `ttlv:",omitempty"`
	// Specifies the stream or by-parts value to be provided in subsequent calls to this operation
	// for performing cryptographic operations.
	CorrelationValue []byte `ttlv:",omitempty,version=v1.3.."`
}

func (pl *MACResponsePayload) Operation() kmip.Operation {
	return kmip.OperationMAC
}

// This operation requests the server to perform a MAC verification operation on the provided data
// using a Managed Cryptographic Object as the key for the MAC verification operation.
//
// The request contains the Unique Identifier of the Managed Cryptographic Object that is the key,
// the data to be processed, and the MAC to be verified. The cryptographic parameters MAY be omitted
// from the request as they can be specified as associated attributes of the Managed Cryptographic Object.
type MACVerifyRequestPayload struct {
	// The Unique Identifier of the Managed Cryptographic Object that is the key to use for the MAC
	// verification operation. If omitted, then the ID Placeholder value SHALL be used by the server
	// as the Unique Identifier.
	UniqueIdentifier string `ttlv:",omitempty"`
	// The Cryptographic Parameters (MAC Algorithm or Cryptographic Algorithm and Hashing Algorithm)
	// corresponding to the particular MAC verification method requested. If omitted then the
	// Cryptographic Parameters associated with the Managed Cryptographic Object with the lowest
	// Attribute Index SHALL be used.
	CryptographicParameters *kmip.CryptographicParameters `ttlv:",omitempty"`
	// The data to be verified.
	Data []byte `ttlv:",omitempty"`
	// The MAC data to be verified. Mandatory for single-part operation, not for multi-part.
	MACData []byte `ttlv:",omitempty"`
	// Specifies the existing stream or by-parts cryptographic operation
	// (as returned from a previous call to this operation).
	CorrelationValue []byte `ttlv:",omitempty,version=v1.3.."`
	// Initial operation.
	InitIndicator *bool `ttlv:",version=v1.3.."`
	// Final operation.
	FinalIndicator *bool `ttlv:",version=v1.3.."`
}

func (pl *MACVerifyRequestPayload) Operation() kmip.Operation {
	return kmip.OperationMACVerify
}

// Response for the MACVerify operation.
//
// The response contains the Unique Identifier of the Managed Cryptographic Object used as the key.
// The validity of the MAC is indicated by the Validity Indicator field.
//
// The success or failure of the operation is indicated by the Result Status (and if failure the Result Reason)
// in the response header.
type MACVerifyResponsePayload struct {
	// The Unique Identifier of the Managed Cryptographic Object that is the key used for the verification operation.
	UniqueIdentifier string
	// An Enumeration object indicating whether the MAC is valid, invalid, or unknown.
	ValidityIndicator kmip.ValidityIndicator
	// Specifies the stream or by-parts value to be provided in subsequent calls to this operation
	// for performing cryptographic operations.
	CorrelationValue []byte `ttlv:",omitempty,version=v1.3.."`
}

func (pl *MACVerifyResponsePayload) Operation() kmip.Operation {
	return kmip.OperationMACVerify
}
