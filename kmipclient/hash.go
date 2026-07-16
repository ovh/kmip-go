package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// ExecHash is a specialized executor for handling Hash operations.
// It embeds the generic Executor with request and response payload types specific to
// the Hash KMIP operation, facilitating the execution and management of hash requests and their responses.
//
// Usage:
//
//	exec := client.Hash().WithCryptographicParameters(...).Data(...)
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the hash operation if the cryptographic parameters are invalid,
//     or the server rejects the operation.
type ExecHash struct {
	Executor[*payloads.HashRequestPayload, *payloads.HashResponsePayload]
}

// ExecHashWantsCryptographicParameters is an intermediate builder type that enforces
// setting CryptographicParameters before providing data.
// This ensures type safety at compile time - Data() cannot be called without
// first calling WithCryptographicParameters().
type ExecHashWantsCryptographicParameters struct {
	client *Client
	req    *payloads.HashRequestPayload
}

// ExecHashWantsData is a builder for providing the data to hash after cryptographic parameters are set.
type ExecHashWantsData struct {
	req    *payloads.HashRequestPayload
	client *Client
}

// Hash creates an ExecHashWantsCryptographicParameters builder for hashing data.
// Returns an intermediate builder that enforces setting CryptographicParameters first.
func (c *Client) Hash() ExecHashWantsCryptographicParameters {
	return ExecHashWantsCryptographicParameters{
		client: c,
		req:    &payloads.HashRequestPayload{},
	}
}

// WithCryptographicParameters sets the CryptographicParameters for the hash operation.
// The CryptographicParameters should include the HashingAlgorithm.
// Returns an ExecHashWantsData builder for providing the data to hash.
func (ex ExecHashWantsCryptographicParameters) WithCryptographicParameters(params kmip.CryptographicParameters) ExecHashWantsData {
	ex.req.CryptographicParameters = params
	return ExecHashWantsData{
		client: ex.client,
		req:    ex.req,
	}
}

// Data finalizes the hash request by providing the data to be hashed.
// Returns an ExecHash executor for executing the hash operation.
func (ex ExecHashWantsData) Data(data []byte) ExecHash {
	ex.req.Data = data
	return ExecHash{
		Executor[*payloads.HashRequestPayload, *payloads.HashResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}
