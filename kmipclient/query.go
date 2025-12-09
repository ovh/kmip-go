package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

func (c *KMIPClient) Query() ExecQuery {
	return ExecQuery{
		Executor[*payloads.QueryRequestPayload, *payloads.QueryResponsePayload]{
			client: c,
			req:    &payloads.QueryRequestPayload{},
		},
	}
}

// ExecQuery is a specialized executor for handling Query operations.
// It embeds the generic Executor with request and response payload types specific to
// the Query KMIP operation, facilitating the execution and management of query requests and their responses.
//
// The following methods add specific QueryFunction values to the request, allowing you to query for
// supported operations, objects, server information, namespaces, extensions, attestation types, RNGs, validations, profiles, capabilities, and client registration methods.
// Some methods are only available in specific KMIP protocol versions (see comments).
//
// Usage:
//
//	exec := client.Query().Operations().Objects()
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the query operation if the query function is not supported by the server,
//     or if the server returns an error.
type ExecQuery struct {
	Executor[*payloads.QueryRequestPayload, *payloads.QueryResponsePayload]
}

// Operations adds the QueryFunctionOperations to the query request.
func (ex ExecQuery) Operations() ExecQuery {
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryFunctionOperations)
	return ex
}

// Objects adds the QueryFunctionObjects to the query request.
func (ex ExecQuery) Objects() ExecQuery {
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryFunctionObjects)
	return ex
}

// ServerInformation adds the QueryFunctionServerInformation to the query request.
func (ex ExecQuery) ServerInformation() ExecQuery {
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryFunctionServerInformation)
	return ex
}

// ApplicationNamespaces adds the QueryFunctionApplicationNamespaces to the query request.
func (ex ExecQuery) ApplicationNamespaces() ExecQuery {
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryFunctionApplicationNamespaces)
	return ex
}

// ExtensionList adds the QueryFunctionExtensionList to the query request.
// KMIP 1.1 and above. If used with an older protocol version, the server may return an error.
func (ex ExecQuery) ExtensionList() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryFunctionExtensionList)
	return ex
}

// ExtensionMap adds the QueryFunctionExtensionMap to the query request.
// KMIP 1.1 and above. If used with an older protocol version, the server may return an error.
func (ex ExecQuery) ExtensionMap() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryFunctionExtensionMap)
	return ex
}

// AttestationTypes adds the QueryFunctionAttestationTypes to the query request.
// KMIP 1.2 and above. If used with an older protocol version, the server may return an error.
func (ex ExecQuery) AttestationTypes() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryFunctionAttestationTypes)
	return ex
}

// RNGs adds the QueryFunctionRNGs to the query request.
// KMIP 1.3 and above. If used with an older protocol version, the server may return an error.
func (ex ExecQuery) RNGs() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryFunctionRNGs)
	return ex
}

// Validations adds the QueryFunctionValidations to the query request.
// KMIP 1.3 and above. If used with an older protocol version, the server may return an error.
func (ex ExecQuery) Validations() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryFunctionValidations)
	return ex
}

// Profiles adds the QueryFunctionProfiles to the query request.
// KMIP 1.3 and above. If used with an older protocol version, the server may return an error.
func (ex ExecQuery) Profiles() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryFunctionProfiles)
	return ex
}

// Capabilities adds the QueryFunctionCapabilities to the query request.
// KMIP 1.3 and above. If used with an older protocol version, the server may return an error.
func (ex ExecQuery) Capabilities() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryFunctionCapabilities)
	return ex
}

// ClientRegistrationMethods adds the QueryFunctionClientRegistrationMethods to the query request.
// KMIP 1.3 and above. If used with an older protocol version, the server may return an error.
func (ex ExecQuery) ClientRegistrationMethods() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryFunctionClientRegistrationMethods)
	return ex
}

// All adds all supported QueryFunction values to the query request, enabling a comprehensive query for all
// supported operations, objects, server information, namespaces, extensions, attestation types, RNGs, validations, profiles, capabilities, and client registration methods.
// This is a convenience method for requesting all available information from the KMIP server in a single query.
//
// Usage:
//
//	exec := client.Query().All()
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the query operation if any of the query functions are not supported by the server,
//     or if the server returns an error.
func (ex ExecQuery) All() ExecQuery {
	return ex.
		Operations().
		Objects().
		ServerInformation().
		ApplicationNamespaces().
		ExtensionList().
		ExtensionMap().
		AttestationTypes().
		RNGs().
		Validations().
		Profiles().
		Capabilities().
		ClientRegistrationMethods()
}
