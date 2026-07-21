package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// ExecMAC is a specialized executor for handling MAC operations.
// It embeds the generic Executor with request and response payload types specific to
// the MAC KMIP operation, facilitating the execution and management of MAC requests and their responses.
//
// Usage:
//
//	exec := client.MAC("key-id").WithCryptographicParameters(...).Data(...)
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the MAC operation if the key is invalid,
//     the server rejects the operation, or the cryptographic parameters are not supported.
type ExecMAC struct {
	Executor[*payloads.MACRequestPayload, *payloads.MACResponsePayload]
}

// ExecMACVerify is a specialized executor for handling MACVerify operations.
// It embeds the generic Executor with request and response payload types specific to
// the MACVerify KMIP operation, facilitating the execution and management of MAC verification requests and their responses.
//
// Usage:
//
//	exec := client.MACVerify("key-id").WithCryptographicParameters(...).Data(...).MACData(...)
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the MAC verification operation if the key is invalid,
//     the server rejects the operation, or the cryptographic parameters are not supported.
type ExecMACVerify struct {
	Executor[*payloads.MACVerifyRequestPayload, *payloads.MACVerifyResponsePayload]
}

// ExecMACWantsData is a builder for providing the data to MAC after specifying the key.
type ExecMACWantsData struct {
	req    *payloads.MACRequestPayload
	client *Client
}

// ExecMACVerifyWantsData is a builder for providing the data to verify after specifying the key.
type ExecMACVerifyWantsData struct {
	req    *payloads.MACVerifyRequestPayload
	client *Client
}

// ExecMACVerifyWantsMAC is an intermediate builder type that enforces providing MAC data
// after the data to be verified has been set.
type ExecMACVerifyWantsMAC struct {
	req    *payloads.MACVerifyRequestPayload
	client *Client
}

// MAC initializes a MAC operation for the object identified by the given unique identifier.
// It returns an ExecMACWantsData struct, which allows the caller to configure cryptographic
// parameters and provide the data to be MACed.
//
// Parameters:
//   - id: The unique identifier of the cryptographic object to use for the MAC operation.
//     If empty, the server will use the ID Placeholder.
func (c *Client) MAC(id string) ExecMACWantsData {
	return ExecMACWantsData{
		client: c,
		req: &payloads.MACRequestPayload{
			UniqueIdentifier: id,
		},
	}
}

// WithCryptographicParameters sets the CryptographicParameters field of the request.
// It returns the updated ExecMACWantsData to allow for method chaining.
func (ex ExecMACWantsData) WithCryptographicParameters(params kmip.CryptographicParameters) ExecMACWantsData {
	ex.req.CryptographicParameters = &params
	return ex
}

// Data sets the data to be MACed in the request and returns an ExecMAC instance
// for executing the MAC operation with the provided data.
func (ex ExecMACWantsData) Data(data []byte) ExecMAC {
	ex.req.Data = data
	return ExecMAC{
		Executor[*payloads.MACRequestPayload, *payloads.MACResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}

// MACVerify initializes a MAC verification operation for the object identified by the given unique identifier.
// It returns an ExecMACVerifyWantsData struct, which allows the caller to configure cryptographic
// parameters, provide the data to be verified, and the MAC data to verify against.
//
// Parameters:
//   - id: The unique identifier of the cryptographic object to use for the MAC verification operation.
//     If empty, the server will use the ID Placeholder.
func (c *Client) MACVerify(id string) ExecMACVerifyWantsData {
	return ExecMACVerifyWantsData{
		client: c,
		req: &payloads.MACVerifyRequestPayload{
			UniqueIdentifier: id,
		},
	}
}

// WithCryptographicParameters sets the CryptographicParameters field of the request.
// It returns the updated ExecMACVerifyWantsData to allow for method chaining.
func (ex ExecMACVerifyWantsData) WithCryptographicParameters(params kmip.CryptographicParameters) ExecMACVerifyWantsData {
	ex.req.CryptographicParameters = &params
	return ex
}

// Data sets the data to be verified in the request and returns an ExecMACVerifyWantsMAC instance
// for providing the MAC data and executing the verification operation.
func (ex ExecMACVerifyWantsData) Data(data []byte) ExecMACVerifyWantsMAC {
	ex.req.Data = data
	return ExecMACVerifyWantsMAC(ex)
}

// MACData sets the MAC data to be verified in the request and returns an ExecMACVerify
// instance for executing the MAC verification operation.
func (ex ExecMACVerifyWantsMAC) MACData(macData []byte) ExecMACVerify {
	ex.req.MACData = macData
	return ExecMACVerify{
		Executor[*payloads.MACVerifyRequestPayload, *payloads.MACVerifyResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}

// MACData sets the MAC data to be verified directly without providing data first.
// This is useful when the data is provided as part of the MAC calculation elsewhere.
func (ex ExecMACVerifyWantsData) MACData(macData []byte) ExecMACVerify {
	ex.req.MACData = macData
	return ExecMACVerify{
		Executor[*payloads.MACVerifyRequestPayload, *payloads.MACVerifyResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}

// Data sets the data to be verified in the request.
// Returns the updated ExecMACVerify for further configuration or execution.
func (ex ExecMACVerify) Data(data []byte) ExecMACVerify {
	ex.req.Data = data
	return ex
}
