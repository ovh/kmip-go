package kmipclient

import (
	"github.com/ovh/kmip-go/payloads"
)

// ExecRNGRetrieve is a specialized executor for handling RNGRetrieve operations.
// It embeds the generic Executor with request and response payload types specific to
// the RNGRetrieve KMIP operation, facilitating the execution and management of
// random number generation requests and their responses.
//
// Usage:
//
//	resp, err := client.RNGRetrieve(32).ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the RNG retrieve operation if the server
//     does not support the requested quantity, or the operation is not permitted.
type ExecRNGRetrieve struct {
	Executor[*payloads.RNGRetrieveRequestPayload, *payloads.RNGRetrieveResponsePayload]
}

// RNGRetrieve creates an ExecRNGRetrieve executor for retrieving random data from the server's RNG.
//
// Parameters:
//   - dataLength: The amount of random data to retrieve (in bytes).
//
// For FIPS 186-2, the value is limited to 20 bytes per request.
// For FIPS 186-3, the value is limited to 64 bytes per request.
// For other algorithms, the server MAY impose limits on the quantity requested.
func (c *Client) RNGRetrieve(dataLength int32) ExecRNGRetrieve {
	return ExecRNGRetrieve{
		Executor[*payloads.RNGRetrieveRequestPayload, *payloads.RNGRetrieveResponsePayload]{
			client: c,
			req: &payloads.RNGRetrieveRequestPayload{
				DataLength: dataLength,
			},
		},
	}
}
