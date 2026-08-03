package payloads

import "github.com/ovh/kmip-go"

func init() {
	kmip.RegisterOperationPayload[RNGRetrieveRequestPayload, RNGRetrieveResponsePayload](kmip.OperationRNGRetrieve)
}

// This operation requests the server to return output from a Random Number Generator (RNG).
//
// The request contains the quantity of output requested.
// The response contains the RNG output.
//
// The success or failure of the operation is indicated by the Result Status (and if failure
// the Result Reason) in the response header.
type RNGRetrieveRequestPayload struct {
	// The amount of random number generator output to be returned (in bytes).
	DataLength int32
}

func (pl *RNGRetrieveRequestPayload) Operation() kmip.Operation {
	return kmip.OperationRNGRetrieve
}

// Response for the RNGRetrieve operation.
//
// The response contains the RNG output.
type RNGRetrieveResponsePayload struct {
	// The random number generator output.
	Data []byte
}

func (pl *RNGRetrieveResponsePayload) Operation() kmip.Operation {
	return kmip.OperationRNGRetrieve
}
