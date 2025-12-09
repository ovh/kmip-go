package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// Locate creates an ExecLocate operation for searching KMIP objects based on attributes and filters.
// The returned ExecLocate can be further configured with additional filters (e.g., storage status mask, max items, offset, group member)
// and executed to perform the locate operation.
//
// Returns:
//   - ExecLocate: An executor for the locate operation.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecLocate.
//   - If the search criteria are not supported or the server rejects the operation, an error will be returned during execution.
func (c *KMIPClient) Locate() ExecLocate {
	return ExecLocate{
		AttributeExecutor[*payloads.LocateRequestPayload, *payloads.LocateResponsePayload, ExecLocate]{
			Executor[*payloads.LocateRequestPayload, *payloads.LocateResponsePayload]{
				client: c,
				req:    &payloads.LocateRequestPayload{},
			},
			func(lrp **payloads.LocateRequestPayload) *[]kmip.Attribute {
				return &(*lrp).Attribute
			},
			func(ae AttributeExecutor[*payloads.LocateRequestPayload, *payloads.LocateResponsePayload, ExecLocate]) ExecLocate {
				return ExecLocate{ae}
			},
		},
	}
}

// ExecLocate is a specialized executor for handling Locate operations.
// It embeds the generic AttributeExecutor with request and response payload types specific to
// the Locate KMIP operation, facilitating the execution and management of locate requests and their responses.
//
// Usage:
//
//	exec := client.Locate().WithStorageStatusMask(mask).WithMaxItems(10)
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the locate operation if the criteria are invalid,
//     or if the server returns an error.
type ExecLocate struct {
	AttributeExecutor[*payloads.LocateRequestPayload, *payloads.LocateResponsePayload, ExecLocate]
}

// WithStorageStatusMask sets the StorageStatusMask filter for the locate request.
// Use this to filter results by storage status (e.g., online, archival).
//
// Parameters:
//   - mask: The storage status mask to filter located objects.
//
// Returns:
//   - ExecLocate: The updated ExecLocate with the StorageStatusMask set.
//
// Errors:
//   - No error is returned by this method. If the mask is not supported by the server, an error may occur during execution.
func (ex ExecLocate) WithStorageStatusMask(mask kmip.StorageStatusMask) ExecLocate {
	ex.req.StorageStatusMask = mask
	return ex
}

// WithMaxItems sets the maximum number of items to return in the locate response.
//
// Parameters:
//   - maximum: The maximum number of items to return.
//
// Returns:
//   - ExecLocate: The updated ExecLocate with the maximum items set.
//
// Errors:
//   - No error is returned by this method. If the value is not supported by the server, an error may occur during execution.
func (ex ExecLocate) WithMaxItems(maximum int32) ExecLocate {
	ex.req.MaximumItems = maximum
	return ex
}

// WithOffset sets the offset for the locate request, specifying how many items to skip before returning results.
//
// Parameters:
//   - offset: The number of items to skip.
//
// Returns:
//   - ExecLocate: The updated ExecLocate with the offset set.
//
// Errors:
//   - No error is returned by this method. If the value is not supported by the server, an error may occur during execution.
func (ex ExecLocate) WithOffset(offset int32) ExecLocate {
	ex.req.OffsetItems = offset
	return ex
}

// WithObjectGroupMember sets the ObjectGroupMember filter for the locate request.
//
// Parameters:
//   - groupMember: The object group member filter to apply.
//
// Returns:
//   - ExecLocate: The updated ExecLocate with the ObjectGroupMember set.
//
// Errors:
//   - No error is returned by this method. If the value is not supported by the server, an error may occur during execution.
func (ex ExecLocate) WithObjectGroupMember(groupMember kmip.ObjectGroupMember) ExecLocate {
	ex.req.ObjectGroupMember = groupMember
	return ex
}
