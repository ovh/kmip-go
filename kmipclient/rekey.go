package kmipclient

import (
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// Rekey creates an ExecRekey operation for the specified unique identifier.
// This method prepares a rekey request payload for the specified object ID using the client instance.
// The returned ExecRekey can be used to execute the rekey operation by calling Exec or ExecContext.
//
// Parameters:
//   - id: The unique identifier of the object to be rekeyed.
//
// Returns:
//   - ExecRekey: Executor for the Rekey operation, pre-filled with the unique identifier.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecRekey.
//   - If the object does not exist or cannot be rekeyed, an error will be returned during execution.
func (c *Client) Rekey(id string) ExecRekey {
	return ExecRekey{
		AttributeExecutor[*payloads.RekeyRequestPayload, *payloads.RekeyResponsePayload, ExecRekey]{
			Executor[*payloads.RekeyRequestPayload, *payloads.RekeyResponsePayload]{
				client: c,
				req: &payloads.RekeyRequestPayload{
					UniqueIdentifier:  id,
					TemplateAttribute: &kmip.TemplateAttribute{},
				},
			},
			func(lrp **payloads.RekeyRequestPayload) *[]kmip.Attribute {
				return &(*lrp).TemplateAttribute.Attribute
			},
			func(ae AttributeExecutor[*payloads.RekeyRequestPayload, *payloads.RekeyResponsePayload, ExecRekey]) ExecRekey {
				return ExecRekey{ae}
			},
		},
	}
}

// ExecRekey is a specialized executor for handling Rekey operations.
// It embeds the generic AttributeExecutor with request and response payload types specific to
// the Rekey KMIP operation, facilitating the execution and management of rekey requests and their responses.
//
// Usage:
//
//	exec := client.Rekey("object-id").WithOffset(time.Hour)
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the rekey operation if the object does not exist,
//     is not in a state that can be rekeyed, or if the server returns an error.
type ExecRekey struct {
	AttributeExecutor[*payloads.RekeyRequestPayload, *payloads.RekeyResponsePayload, ExecRekey]
}

// WithOffset sets the Offset field for the rekey request, specifying a time duration to offset the rekey operation.
//
// Parameters:
//   - offset: The time.Duration to offset the rekey operation.
//
// Returns:
//   - ExecRekey: The updated ExecRekey with the offset set.
//
// Errors:
//   - No error is returned by this method. If the value is not supported by the server, an error may occur during execution.
func (ex ExecRekey) WithOffset(offset time.Duration) ExecRekey {
	ex.req.Offset = &offset
	return ex
}

// Deprecated: Templates have been deprecated in KMIP v1.3.
func (ex ExecRekey) WithTemplates(names ...kmip.Name) ExecRekey {
	ex.req.TemplateAttribute.Name = append(ex.req.TemplateAttribute.Name, names...)
	return ex
}

// Deprecated: Templates have been deprecated in KMIP v1.3.
func (ex ExecRekey) WithTemplate(name string, nameType kmip.NameType) ExecRekey {
	ex.req.TemplateAttribute.Name = append(ex.req.TemplateAttribute.Name, kmip.Name{NameValue: name, NameType: nameType})
	return ex
}
