package payloads

import (
	"time"

	"github.com/ovh/kmip-go"
)

func init() {
	kmip.RegisterOperationPayload[CheckRequestPayload, CheckResponsePayload](kmip.OperationCheck)
}

// This operation requests that the server check for the use of a Managed Object according to values
// specified in the request. This operation SHOULD only be used when placed in a batched set of
// operations, usually following a Locate, Create, Create Pair, Derive Key, Certify, Re-Certify,
// Re-key or Re-key Key Pair operation, and followed by a Get operation.
//
// If the server determines that the client is allowed to use the object according to the specified
// attributes, then the server returns the Unique Identifier of the object.
//
// If the server determines that the client is not allowed to use the object according to the specified
// attributes, then the server empties the ID Placeholder and does not return the Unique Identifier,
// and the operation returns the set of attributes specified in the request that caused the server
// policy denial.
type CheckRequestPayload struct {
	// The Unique Identifier of the object being checked.
	// If omitted, then the ID Placeholder value SHALL be used by the server as the Unique Identifier.
	UniqueIdentifier string `ttlv:",omitempty"`
	// Specifies the number of Usage Limits Units to be protected to be checked against server policy.
	UsageLimitsCount *int64 `ttlv:",omitempty"`
	// Specifies the Cryptographic Usage for which the client intends to use the object.
	// This allows the server to determine if the policy allows this client to perform these operations
	// with the object.
	CryptographicUsageMask kmip.CryptographicUsageMask `ttlv:",omitempty"`
	// Specifies a Lease Time value that the Client is asking the server to validate against server policy.
	LeaseTime *time.Duration `ttlv:",omitempty"`
}

func (pl *CheckRequestPayload) Operation() kmip.Operation {
	return kmip.OperationCheck
}

// Response for the Check operation.
//
// If the server determines that the client is allowed to use the object according to the specified
// attributes, then the response contains the Unique Identifier of the object.
//
// If the server determines that the client is not allowed to use the object, then the Unique
// Identifier is not returned and the response contains the attributes that caused the denial.
type CheckResponsePayload struct {
	// The Unique Identifier of the object.
	// Not present if the server determined the client is not allowed to use the object.
	UniqueIdentifier string `ttlv:",omitempty"`
	// Returned by the server if the Usage Limits Count specified in the Request Payload is larger
	// than the value that the server policy allows.
	UsageLimitsCount *int64 `ttlv:",omitempty"`
	// Returned by the server if the Cryptographic Usage Mask specified in the Request Payload is
	// rejected by the server for policy violation.
	CryptographicUsageMask kmip.CryptographicUsageMask `ttlv:",omitempty"`
	// Returned by the server if the Lease Time value in the Request Payload is larger than a valid
	// Lease Time that the server MAY grant.
	LeaseTime *time.Duration `ttlv:",omitempty"`
}

func (pl *CheckResponsePayload) Operation() kmip.Operation {
	return kmip.OperationCheck
}
