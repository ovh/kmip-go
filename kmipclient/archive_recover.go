package kmipclient

import (
	"github.com/ovh/kmip-go/payloads"
)

// Archive creates an ExecArchive operation for the specified unique identifier.
// This method prepares an archive request payload for the specified object ID using the client instance.
// The returned ExecArchive can be used to execute the archive operation by calling Exec or ExecContext.
//
// Parameters:
//   - id: The unique identifier of the object to be archived.
//
// Returns:
//   - ExecArchive: Executor for the Archive operation, pre-filled with the unique identifier.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecArchive.
//   - If the object does not exist or cannot be archived, an error will be returned during execution.
func (c *KMIPClient) Archive(id string) ExecArchive {
	return ExecArchive{
		client: c,
		req: &payloads.ArchiveRequestPayload{
			UniqueIdentifier: id,
		},
	}
}

// ExecArchive is a type alias for Executor that operates on ArchiveRequestPayload and ArchiveResponsePayload types.
// It is used to execute archive operations within the KMIP client, handling the request and response payloads
// specific to the archive functionality.
//
// Usage:
//
//	exec := client.Archive("object-id")
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the archive operation if the object does not exist,
//     is not in a state that can be archived, or if the server returns an error.
type ExecArchive = Executor[*payloads.ArchiveRequestPayload, *payloads.ArchiveResponsePayload]

// Recover creates and returns an ExecRecover instance initialized with the provided unique identifier.
// This method prepares a recovery request payload for the specified object ID, allowing the client
// to initiate a recover operation using the KMIP protocol. The returned ExecRecover can be executed
// to perform the recovery operation.
//
// Parameters:
//   - id: The unique identifier of the object to be recovered.
//
// Returns:
//   - ExecRecover: Executor for the Recover operation, pre-filled with the unique identifier.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecRecover.
//   - If the object does not exist or cannot be recovered, an error will be returned during execution.
func (c *KMIPClient) Recover(id string) ExecRecover {
	return ExecRecover{
		client: c,
		req: &payloads.RecoverRequestPayload{
			UniqueIdentifier: id,
		},
	}
}

// ExecRecover is a type alias for Executor specialized with RecoverRequestPayload and RecoverResponsePayload.
// It is used to execute KMIP recover operations, handling the request and response payloads for recovery actions.
//
// Usage:
//
//	exec := client.Recover("object-id")
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the recover operation if the object does not exist,
//     is not in a state that can be recovered, or if the server returns an error.
type ExecRecover = Executor[*payloads.RecoverRequestPayload, *payloads.RecoverResponsePayload]
