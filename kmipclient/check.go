package kmipclient

import (
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// ExecCheck is a specialized executor for handling Check operations.
// It embeds the generic Executor with request and response payload types specific to
// the Check KMIP operation, facilitating the execution and management of check requests and their responses.
//
// Usage:
//
//	resp, err := client.Check("key-id").WithUsageLimit(1000).ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the check operation if the key is invalid,
//     the server rejects the operation, or the specified attributes are not compatible.
type ExecCheck struct {
	Executor[*payloads.CheckRequestPayload, *payloads.CheckResponsePayload]
}

// Check creates an ExecCheck executor for checking an object's usability.
// The object is identified by the provided unique identifier.
//
// Parameters:
//   - id: The unique identifier of the object to check. If empty, the server will use the ID Placeholder.
func (c *Client) Check(id string) ExecCheck {
	return ExecCheck{
		Executor[*payloads.CheckRequestPayload, *payloads.CheckResponsePayload]{
			client: c,
			req: &payloads.CheckRequestPayload{
				UniqueIdentifier: id,
			},
		},
	}
}

// WithUsageLimitsCount sets the UsageLimitsCount field of the request.
// This specifies the number of Usage Limits Units to be protected and checked against server policy.
//
// Parameters:
//   - count: The usage limits count to check.
func (ex ExecCheck) WithUsageLimitsCount(count int64) ExecCheck {
	ex.req.UsageLimitsCount = &count
	return ex
}

// WithCryptographicUsageMask sets the CryptographicUsageMask field of the request.
// This specifies the cryptographic operations for which the client intends to use the object.
//
// Parameters:
//   - mask: The cryptographic usage mask specifying intended operations.
func (ex ExecCheck) WithCryptographicUsageMask(mask kmip.CryptographicUsageMask) ExecCheck {
	ex.req.CryptographicUsageMask = mask
	return ex
}

// WithLeaseTime sets the LeaseTime field of the request.
// This specifies a desired lease time to validate against server policy.
//
// Parameters:
//   - duration: The desired lease time duration.
func (ex ExecCheck) WithLeaseTime(duration time.Duration) ExecCheck {
	ex.req.LeaseTime = &duration
	return ex
}
