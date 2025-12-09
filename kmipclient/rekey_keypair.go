package kmipclient

import (
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// ExecRekeyKeyPair is a builder for the RekeyKeyPair KMIP operation.
// It provides methods to set attributes for the common, private key, and public key template attributes
// when rekeying a key pair. This type embeds AttributeExecutor to allow attribute chaining and
// supports backward compatibility for template names.
type ExecRekeyKeyPair struct {
	AttributeExecutor[*payloads.RekeyKeyPairRequestPayload, *payloads.RekeyKeyPairResponsePayload, ExecRekeyKeyPair]
	tmplFunc func(*payloads.RekeyKeyPairRequestPayload) *[]kmip.Name
}

// NewExecRekeyKeyPair creates a new instance of ExecRekeyKeyPair with the provided AttributeExecutor and template function.
// The AttributeExecutor handles the setting of attributes, while the template function is responsible for returning
// the name templates for the RekeyKeyPair operation.
func NewExecRekeyKeyPair(ae AttributeExecutor[*payloads.RekeyKeyPairRequestPayload, *payloads.RekeyKeyPairResponsePayload, ExecRekeyKeyPair],
	tmplFunc func(*payloads.RekeyKeyPairRequestPayload) *[]kmip.Name) ExecRekeyKeyPair {
	return ExecRekeyKeyPair{
		AttributeExecutor: ae,
		tmplFunc:          tmplFunc,
	}
}

// RekeyKeyPair initializes a RekeyKeyPair operation for the given private key ID.
// It returns an ExecRekeyKeyPair builder for setting template attributes and executing the operation.
func (c *KMIPClient) RekeyKeyPair(privateKeyId string) ExecRekeyKeyPair {
	return ExecRekeyKeyPair{
		AttributeExecutor[*payloads.RekeyKeyPairRequestPayload, *payloads.RekeyKeyPairResponsePayload, ExecRekeyKeyPair]{
			Executor[*payloads.RekeyKeyPairRequestPayload, *payloads.RekeyKeyPairResponsePayload]{
				client: c,
				req: &payloads.RekeyKeyPairRequestPayload{
					PrivateKeyUniqueIdentifier:  privateKeyId,
					CommonTemplateAttribute:     &kmip.TemplateAttribute{},
					PrivateKeyTemplateAttribute: &kmip.TemplateAttribute{},
					PublicKeyTemplateAttribute:  &kmip.TemplateAttribute{},
				},
			},
			func(lrp **payloads.RekeyKeyPairRequestPayload) *[]kmip.Attribute {
				return &(*lrp).CommonTemplateAttribute.Attribute
			},
			func(ae AttributeExecutor[*payloads.RekeyKeyPairRequestPayload, *payloads.RekeyKeyPairResponsePayload, ExecRekeyKeyPair]) ExecRekeyKeyPair {
				return ExecRekeyKeyPair{ae, func(ckprp *payloads.RekeyKeyPairRequestPayload) *[]kmip.Name {
					//nolint:staticcheck // for backward compatibility
					return &ckprp.CommonTemplateAttribute.Name
				}}
			},
		},
		func(ckprp *payloads.RekeyKeyPairRequestPayload) *[]kmip.Name {
			//nolint:staticcheck // for backward compatibility
			return &ckprp.CommonTemplateAttribute.Name
		},
	}
}

// WithOffset sets the Offset field (activation delay) for the RekeyKeyPair request payload.
// This allows specifying a time.Duration after which the new key pair becomes active.
//
// Parameters:
//   - offset: The duration to set as the offset.
//
// Returns:
//   - ExecRekeyKeyPair: The updated builder with the offset set.
func (ex ExecRekeyKeyPair) WithOffset(offset time.Duration) ExecRekeyKeyPair {
	ex.req.Offset = &offset
	return ex
}

// Common selects the common template attribute for setting attributes on the RekeyKeyPair request.
func (ex ExecRekeyKeyPair) Common() ExecRekeyKeyPair {
	return ExecRekeyKeyPair{
		AttributeExecutor[*payloads.RekeyKeyPairRequestPayload, *payloads.RekeyKeyPairResponsePayload, ExecRekeyKeyPair]{
			ex.Executor,
			func(ckprp **payloads.RekeyKeyPairRequestPayload) *[]kmip.Attribute {
				return &(*ckprp).CommonTemplateAttribute.Attribute
			},
			func(ae AttributeExecutor[*payloads.RekeyKeyPairRequestPayload, *payloads.RekeyKeyPairResponsePayload, ExecRekeyKeyPair]) ExecRekeyKeyPair {
				return ExecRekeyKeyPair{ae, func(ckprp *payloads.RekeyKeyPairRequestPayload) *[]kmip.Name {
					//nolint:staticcheck // for backward compatibility
					return &ckprp.CommonTemplateAttribute.Name
				}}
			},
		},
		func(ckprp *payloads.RekeyKeyPairRequestPayload) *[]kmip.Name {
			//nolint:staticcheck // for backward compatibility
			return &ckprp.CommonTemplateAttribute.Name
		},
	}
}

// PrivateKey selects the private key template attribute for setting attributes on the RekeyKeyPair request.
func (ex ExecRekeyKeyPair) PrivateKey() ExecRekeyKeyPair {
	return ExecRekeyKeyPair{
		AttributeExecutor[*payloads.RekeyKeyPairRequestPayload, *payloads.RekeyKeyPairResponsePayload, ExecRekeyKeyPair]{
			ex.Executor,
			func(ckprp **payloads.RekeyKeyPairRequestPayload) *[]kmip.Attribute {
				return &(*ckprp).PrivateKeyTemplateAttribute.Attribute
			},
			func(ae AttributeExecutor[*payloads.RekeyKeyPairRequestPayload, *payloads.RekeyKeyPairResponsePayload, ExecRekeyKeyPair]) ExecRekeyKeyPair {
				return ExecRekeyKeyPair{ae, func(ckprp *payloads.RekeyKeyPairRequestPayload) *[]kmip.Name {
					//nolint:staticcheck // for backward compatibility
					return &ckprp.PrivateKeyTemplateAttribute.Name
				}}
			},
		},
		func(ckprp *payloads.RekeyKeyPairRequestPayload) *[]kmip.Name {
			//nolint:staticcheck // for backward compatibility
			return &ckprp.PrivateKeyTemplateAttribute.Name
		},
	}
}

// PublicKey selects the public key template attribute for setting attributes on the RekeyKeyPair request.
func (ex ExecRekeyKeyPair) PublicKey() ExecRekeyKeyPair {
	return ExecRekeyKeyPair{
		AttributeExecutor[*payloads.RekeyKeyPairRequestPayload, *payloads.RekeyKeyPairResponsePayload, ExecRekeyKeyPair]{
			ex.Executor,
			func(ckprp **payloads.RekeyKeyPairRequestPayload) *[]kmip.Attribute {
				return &(*ckprp).PublicKeyTemplateAttribute.Attribute
			},
			func(ae AttributeExecutor[*payloads.RekeyKeyPairRequestPayload, *payloads.RekeyKeyPairResponsePayload, ExecRekeyKeyPair]) ExecRekeyKeyPair {
				return ExecRekeyKeyPair{ae, func(ckprp *payloads.RekeyKeyPairRequestPayload) *[]kmip.Name {
					//nolint:staticcheck // for backward compatibility
					return &ckprp.PublicKeyTemplateAttribute.Name
				}}
			},
		},
		func(ckprp *payloads.RekeyKeyPairRequestPayload) *[]kmip.Name {
			//nolint:staticcheck // for backward compatibility
			return &ckprp.PublicKeyTemplateAttribute.Name
		},
	}
}
