package kmipclient

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

func (c *Client) Query() ExecQuery {
	return ExecQuery{
		Executor[*payloads.QueryRequestPayload, *payloads.QueryResponsePayload]{
			client: c,
			req:    &payloads.QueryRequestPayload{},
		},
	}
}

type ExecQuery struct {
	Executor[*payloads.QueryRequestPayload, *payloads.QueryResponsePayload]
}

func (ex ExecQuery) Operations() ExecQuery {
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryOperations)
	return ex
}
func (ex ExecQuery) Objects() ExecQuery {
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryObjects)
	return ex
}
func (ex ExecQuery) ServerInformation() ExecQuery {
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryServerInformation)
	return ex
}
func (ex ExecQuery) ApplicationNamespaces() ExecQuery {
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryApplicationNamespaces)
	return ex
}

// KMIP 1.1.
func (ex ExecQuery) ExtensionList() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryExtensionList)
	return ex
}

// KMIP 1.1.
func (ex ExecQuery) ExtensionMap() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryExtensionMap)
	return ex
}

// KMIP 1.2.
func (ex ExecQuery) AttestationTypes() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryAttestationTypes)
	return ex
}

// KMIP 1.3.
func (ex ExecQuery) RNGs() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryRNGs)
	return ex
}
func (ex ExecQuery) Validations() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryValidations)
	return ex
}
func (ex ExecQuery) Profiles() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryProfiles)
	return ex
}
func (ex ExecQuery) Capabilities() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryCapabilities)
	return ex
}
func (ex ExecQuery) ClientRegistrationMethods() ExecQuery {
	//TODO: Check client version first
	ex.req.QueryFunction = append(ex.req.QueryFunction, kmip.QueryClientRegistrationMethods)
	return ex
}

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
