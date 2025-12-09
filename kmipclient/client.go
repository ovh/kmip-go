// Package kmipclient provides a client implementation for interacting with KMIP (Key Management Interoperability Protocol) servers.
// It supports protocol version negotiation, TLS configuration, middleware chaining, and batch operations.
//
// The client is highly configurable via functional options, allowing customization of TLS settings, supported protocol versions,
// client certificates, and middleware. It provides methods for sending KMIP requests, handling batch operations, and cloning clients.
//
// Key Features:
//   - Protocol version negotiation with the KMIP server, with support for enforcing a specific version.
//   - Flexible TLS configuration, including custom root CAs, client certificates, and cipher suites.
//   - Middleware support for request/response processing.
//   - Batch operation support for sending multiple KMIP operations in a single request.
//   - Safe concurrent usage via internal locking.
//
// Usage Example:
//
//	netExec, err := kmipclient.Dial("kmip.example.com:5696",
//		kmipclient.WithClientCertFiles("client.crt", "client.key"),
//		kmipclient.WithRootCAFile("ca.crt"),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// client, err := kmipclient.NewClient(kmipclient.WithClientNetworkExecutor(netExec))
//
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer client.Close()
//
//	resp, err := client.Request(context.Background(), payload)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Types:
//
//   - Client: Represents a KMIP client controller.
//   - ClientNetworkExecutor : Represents the network connection.
//   - Option: Functional option for configuring the client.
//   - Executor: Generic type for building and executing KMIP requests.
//   - AttributeExecutor: Executor with attribute-building helpers.
//   - BatchExec: Helper for building and executing batch requests.
//   - BatchResult: Result type for batch operations.
//
// See the documentation for each type and function for more details.
package kmipclient

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"slices"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

var supportedVersions = []kmip.ProtocolVersion{kmip.V1_4, kmip.V1_3, kmip.V1_2, kmip.V1_1, kmip.V1_0}

type opts struct {
	supportedVersions []kmip.ProtocolVersion
	enforceVersion    *kmip.ProtocolVersion
	netExec           ClientNetworkExecutor

	//TODO: Add KMIP Authentication / Credentials
	//TODO: Overwrite default/preferred/supported key formats for register
}
type Option func(*opts) error

// WithKmipVersions returns an Option that sets the supported KMIP protocol versions for the client.
// It appends the provided versions to the existing list, sorts them in descending order,
// and removes any duplicate versions. This allows the client to negotiate the highest mutually
// supported protocol version with the KMIP server.
//
// Parameters:
//
//   - versions - One or more kmip.ProtocolVersion values to be supported by the client.
//
// Returns:
//
//   - Option - A function that applies the protocol versions configuration to the client options.
//   - error   - An error if the connection or protocol negotiation fails.
func WithKmipVersions(versions ...kmip.ProtocolVersion) Option {
	return func(o *opts) error {
		o.supportedVersions = append(o.supportedVersions, versions...)
		slices.SortFunc(o.supportedVersions, func(a, b kmip.ProtocolVersion) int {
			return ttlv.CompareVersions(b, a)
		})
		o.supportedVersions = slices.Compact(o.supportedVersions)
		return nil
	}
}

// EnforceVersion returns an Option that sets the enforced KMIP protocol version for the client.
// This ensures that all operations performed by the client will use the specified protocol version.
//
// Parameters:
//
//   - v - The KMIP protocol version to enforce.
//
// Returns:
//
//   - Option - A function that applies the enforced protocol version to the client options.
//   - error   - An error if the connection or protocol negotiation fails.
func EnforceVersion(v kmip.ProtocolVersion) Option {
	return func(o *opts) error {
		o.enforceVersion = &v
		return nil
	}
}

func WithClientNetworkExecutor(net ClientNetworkExecutor) Option {
	return func(o *opts) error {
		o.netExec = net
		return nil
	}
}

func NewClient(options ...Option) (Client, error) {
	return NewClientCtx(context.Background(), options...)
}

func NewClientCtx(ctx context.Context, options ...Option) (Client, error) {
	opts := opts{}
	for _, o := range options {
		if err := o(&opts); err != nil {
			return nil, err
		}
	}
	if len(opts.supportedVersions) == 0 {
		opts.supportedVersions = append(opts.supportedVersions, supportedVersions...)
	}

	if opts.netExec == nil {
		return nil, fmt.Errorf("Missing network connector for KMIP Client")
	}

	c := &KMIPClient{
		supportedVersions: opts.supportedVersions,
		version:           opts.enforceVersion,
		networkExecutor:   opts.netExec,
	}

	// Negotiate protocol version
	if err := c.negotiateVersion(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}

	return c, nil
}

// Client represents a KMIP client that manages a connection to a KMIP server,
// handles protocol version negotiation, and supports middleware for request/response
// processing. It provides thread-safe access to the underlying connection and
// configuration options such as supported protocol versions and custom dialers.
type Client interface {
	Clone() (Client, error)
	CloneCtx(context.Context) (Client, error)
	Version() kmip.ProtocolVersion
	Request(context.Context, kmip.OperationPayload) (kmip.OperationPayload, error)
	Batch(context.Context, ...kmip.OperationPayload) (BatchResult, error)
	BatchOpt(context.Context, []kmip.OperationPayload, ...BatchOption) (BatchResult, error)
	Close() error

	Get(id string) ExecGet
	AddAttribute(id string, name kmip.AttributeName, value any) ExecAddAttribute
	Query() ExecQuery
	Encrypt(id string) ExecEncryptWantsData
	Decrypt(id string) ExecDecryptWantsData
	GetAttributeList(id string) ExecGetAttributeList
	GetUsageAllocation(id string, limitCount int64) ExecGetUsageAllocation
	Activate(id string) ExecActivate
	Create() ExecCreateWantType
	Locate() ExecLocate
	Sign(id string) ExecSignWantsData
	SignatureVerify(id string) ExecSignatureVerifyWantsData
	Signer(ctx context.Context, privateKeyId, publicKeyId string) (crypto.Signer, error)
	ObtainLease(id string) ExecObtainLease
	Archive(id string) ExecArchive
	Recover(id string) ExecRecover
	Import(id string, object kmip.Object) ExecImport
	Export(id string) ExecExport
	RekeyKeyPair(privateKeyId string) ExecRekeyKeyPair
	Rekey(id string) ExecRekey
	Destroy(id string) ExecDestroy
	ModifyAttribute(id string, name kmip.AttributeName, value any) ExecModifyAttribute
	Revoke(id string) ExecRevoke
	CreateKeyPair() ExecCreateKeyPair
	GetAttributes(id string, attributes ...kmip.AttributeName) ExecGetAttributes
	Register() ExecRegisterWantType
	DeleteAttribute(id string, name kmip.AttributeName) ExecDeleteAttribute
}

// KMIPClient implements Client and manages a connection to a KMIP server, handling
// protocol version negotiation, middleware for request/response processing, and batch operations.
type KMIPClient struct {
	version           *kmip.ProtocolVersion
	supportedVersions []kmip.ProtocolVersion
	networkExecutor   ClientNetworkExecutor
}

// Close terminates the client's connection and releases any associated resources.
// It returns an error if the connection could not be closed.
func (c *KMIPClient) Close() error {
	return c.networkExecutor.Close()
}

// Version returns the KMIP protocol version used by the client.
func (c *KMIPClient) Version() kmip.ProtocolVersion {
	return *c.version
}

// Clone is like CloneCtx but uses internally a background context.
func (c *KMIPClient) Clone() (Client, error) {
	return c.CloneCtx(context.Background())
}

// CloneCtx clones the current kmip client into a new independent client
// with a separate new connection. The new client inherits allt he configured parameters
// as well as the negotiated kmip protocol version. Meaning that cloning a client does not perform
// protocol version negotiation.
//
// Cloning a closed client is valid and will create a new connected client.
func (c *KMIPClient) CloneCtx(ctx context.Context) (Client, error) {
	networkExecutor, err := c.networkExecutor.Clone()
	if err != nil {
		return nil, err
	}

	return &KMIPClient{
		networkExecutor:   networkExecutor,
		version:           c.version,
		supportedVersions: c.supportedVersions,
	}, nil
}

// negotiateVersion negotiates the KMIP protocol version to be used by the client.
// If the version is already set, it returns immediately. Otherwise, it sends a DiscoverVersions
// request to the server to determine the supported protocol versions. If the server does not support
// the DiscoverVersions operation, it falls back to KMIP v1.0, provided it is in the client's list of
// supported versions. If no common version is found between the client and server, or if any errors
// occur during negotiation, an error is returned. On success, the negotiated version is set in the client.
//
// Returns:
//   - error: If negotiation fails, no common version is found, or the server returns an error.
func (c *KMIPClient) negotiateVersion(ctx context.Context) error {
	if c.version != nil {
		return nil
	}
	msg := kmip.NewRequestMessage(kmip.V1_1, &payloads.DiscoverVersionsRequestPayload{
		ProtocolVersion: c.supportedVersions,
	})

	resp, err := c.networkExecutor.Roundtrip(ctx, &msg)
	if err != nil {
		return err
	}
	if resp.Header.BatchCount != 1 || len(resp.BatchItem) != 1 {
		return errors.New("Unexpected batch item count")
	}
	bi := resp.BatchItem[0]
	if bi.ResultStatus == kmip.ResultStatusOperationFailed && bi.ResultReason == kmip.ResultReasonOperationNotSupported {
		// If the discover operation is not supported, then fallbacks to kmip v1.0
		// but also check that v1.0 is in the client's supported version list and return an error if not.
		if !slices.Contains(c.supportedVersions, kmip.V1_0) {
			return errors.New("Protocol version negotiation failed. No common version found")
		}
		c.version = &kmip.V1_0
		return nil
	}
	if err := bi.Err(); err != nil {
		return err
	}
	serverVersions := bi.ResponsePayload.(*payloads.DiscoverVersionsResponsePayload).ProtocolVersion
	if len(serverVersions) == 0 {
		return errors.New("Protocol version negotiation failed. No common version found")
	}
	c.version = &serverVersions[0]
	return nil
}

// Request sends a single KMIP operation request with the specified payload and returns the corresponding response payload.
// It wraps the Batch method to handle single-operation requests, returning the response payload or an error if the operation fails.
//
// Parameters:
//
//   - ctx     - The context for controlling cancellation and deadlines.
//   - payload - The KMIP operation payload to send.
//
// Returns:
//
//   - The response payload for the operation, or an error if the request fails or the response contains an error.
func (c *KMIPClient) Request(ctx context.Context, payload kmip.OperationPayload) (kmip.OperationPayload, error) {
	resp, err := c.Batch(ctx, payload)
	if err != nil {
		return nil, err
	}
	bi := resp[0]
	if err := bi.Err(); err != nil {
		return nil, err
	}
	return bi.ResponsePayload, nil
}

// Batch sends one or more KMIP operation payloads to the server as a batch request.
// It returns a BatchResult containing the results of each operation, or an error if the request fails.
// This method is a convenience wrapper around BatchOpt.
//
// Parameters:
//
//	ctx      - The context for controlling cancellation and deadlines.
//	payloads - One or more KMIP operation payloads to be executed in the batch.
//
// Returns:
//
//	BatchResult - The results of the batch operations.
//	error       - An error if the batch request fails.
func (c *KMIPClient) Batch(ctx context.Context, payloads ...kmip.OperationPayload) (BatchResult, error) {
	return c.BatchOpt(ctx, payloads)
}

// BatchOpt sends a batch of KMIP operation payloads to the server and applies optional batch options.
// It constructs a KMIP request message with the provided payloads and applies any BatchOption functions.
// The request is sent using the client's Roundtrip method. If the response's batch count does not match
// the number of payloads, an error is returned. On success, it returns the batch result items.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout.
//   - payloads: Slice of KMIP operation payloads to be sent in the batch.
//   - opts: Optional BatchOption functions to modify the request message.
//
// Returns:
//   - BatchResult: The result items from the batch response.
//   - error: An error if the request fails or the batch count does not match.
func (c *KMIPClient) BatchOpt(ctx context.Context, payloads []kmip.OperationPayload, opts ...BatchOption) (BatchResult, error) {
	msg := kmip.NewRequestMessage(*c.version, payloads...)
	for _, opt := range opts {
		opt(&msg)
	}
	resp, err := c.networkExecutor.Roundtrip(ctx, &msg)
	if err != nil {
		return nil, err
	}
	// Check batch item count
	if int(resp.Header.BatchCount) != len(resp.BatchItem) || len(resp.BatchItem) != len(payloads) {
		return nil, errors.New("Batch count mismatch")
	}
	return resp.BatchItem, nil
}

// BatchOption defines a function type that modifies a kmip.RequestMessage,
// allowing customization of batch operations in KMIP client requests.
type BatchOption func(*kmip.RequestMessage)

// OnBatchErr returns a BatchOption that sets the BatchErrorContinuationOption in the request message header.
// This option determines how the server should handle errors encountered during batch processing.
// The provided 'opt' parameter specifies the desired error continuation behavior.
func OnBatchErr(opt kmip.BatchErrorContinuationOption) BatchOption {
	return func(rm *kmip.RequestMessage) {
		rm.Header.BatchErrorContinuationOption = opt
	}
}

// Executor is a generic type that facilitates the construction and execution of KMIP operations.
// It holds a reference to a Client, a request payload of type Req, and an error state.
// Req and Resp are type parameters constrained to kmip.OperationPayload, allowing
// Executor to be used with various KMIP operation request and response types.
type Executor[Req, Resp kmip.OperationPayload] struct {
	client Client
	req    Req
	err    error
}

// NewExecutor creates a new Executor instance with the provided client and request payload.
// It initializes the Executor with the specified client and request payload, ready for further
// configuration and execution of the KMIP operation.
//
// Parameters:
//
//   - c: The client to be used for executing the KMIP operation.
//   - req: The request payload for the KMIP operation.
//
// Returns:
//
//   - Executor[Req, Resp]: A new Executor instance configured with the provided client and request payload.
func NewExecutor[Req, Resp kmip.OperationPayload](c Client, req Req) Executor[Req, Resp] {
	return Executor[Req, Resp]{
		client: c,
		req:    req,
	}
}

// Exec sends the request to the remote KMIP server, and returns the parsed response.
//
// It returns an error if the request could not be sent, or if the server replies with
// KMIP error.
func (ex Executor[Req, Resp]) Exec() (Resp, error) {
	return ex.ExecContext(context.Background())
}

// ExecContext sends the request to the remote KMIP server, and returns the parsed response.
//
// It returns an error if the request could not be sent, or if the server replies with
// KMIP error.
func (ex Executor[Req, Resp]) ExecContext(ctx context.Context) (Resp, error) {
	req, err := ex.Build()
	if err != nil {
		var zero Resp
		return zero, err
	}
	resp, err := ex.client.Request(ctx, req)
	if err != nil {
		var zero Resp
		return zero, err
	}
	return resp.(Resp), nil
}

// MustExec is like Exec except it panics if the request fails.
func (ex Executor[Req, Resp]) MustExec() Resp {
	return ex.MustExecContext(context.Background())
}

// MustExecContext is like Exec except it panics if the request fails.
func (ex Executor[Req, Resp]) MustExecContext(ctx context.Context) Resp {
	resp, err := ex.ExecContext(ctx)
	if err != nil {
		//TODO: Add operation ID string
		panic(fmt.Errorf("Request failed: %w", err))
	}
	return resp
}

func (ex Executor[Req, Resp]) RequestPayload() Req {
	return ex.req
}

// Build constructs and returns the KMIP operation payload from the Executor.
// If there was an error during request initialization, it returns a zero-value
// request and wraps the original error with additional context.
func (ex Executor[Req, Resp]) Build() (kmip.OperationPayload, error) {
	if ex.err != nil {
		var zero Req
		return zero, fmt.Errorf("Request initialization failed: %w", ex.err)
	}
	return ex.req, nil
}

// AttributeExecutor is a generic struct that extends Executor to provide additional
// functionality for handling KMIP operation payloads with attribute manipulation.
//
// Type Parameters:
//   - Req:  The request payload type, which must implement kmip.OperationPayload.
//   - Resp: The response payload type, which must implement kmip.OperationPayload.
//   - Wrap: An arbitrary type used for wrapping or extending the executor.
//
// Fields:
//   - Executor: Embeds the base Executor for handling request and response payloads.
//   - attrFunc: A function that takes a pointer to the request payload and returns a pointer
//     to a slice of kmip.Attribute, allowing for attribute extraction or modification.
//   - wrap:     A function that takes an AttributeExecutor and returns a value of type Wrap,
//     enabling custom wrapping or extension of the executor's behavior.
type AttributeExecutor[Req, Resp kmip.OperationPayload, Wrap any] struct {
	Executor[Req, Resp]
	attrFunc func(*Req) *[]kmip.Attribute
	wrap     func(AttributeExecutor[Req, Resp, Wrap]) Wrap
}

// NewAttributeExecutor creates a new AttributeExecutor instance with the provided Executor, attribute function, and wrap function.
//
// Type Parameters:
//   - Req:  The request payload type, which must implement kmip.OperationPayload.
//   - Resp: The response payload type, which must implement kmip.OperationPayload.
//   - Wrap: An arbitrary type used for wrapping or extending the executor.
//
// Parameters:
//   - ex: The Executor to be used for executing the KMIP operation.
//   - attrFunc: A function that takes a pointer to the request payload and returns a pointer to a slice of kmip.Attribute.
//   - wrap: A function that takes an AttributeExecutor and returns a value of type Wrap.
//
// Returns:
//   - AttributeExecutor[Req, Resp, Wrap]: A new AttributeExecutor instance configured with the provided Executor, attribute function, and wrap function.
func NewAttributeExecutor[Req, Resp kmip.OperationPayload, Wrap any](ex Executor[Req, Resp],
	attrFunc func(*Req) *[]kmip.Attribute,
	wrap func(AttributeExecutor[Req, Resp, Wrap]) Wrap) AttributeExecutor[Req, Resp, Wrap] {
	return AttributeExecutor[Req, Resp, Wrap]{
		Executor: ex,
		attrFunc: attrFunc,
		wrap:     wrap,
	}
}

// WithAttributes appends the provided KMIP attributes to the request's attribute list.
//
// Parameters:
//
//   - attributes - One or more kmip.Attribute values to be added to the request.
func (ex AttributeExecutor[Req, Resp, Wrap]) WithAttributes(attributes ...kmip.Attribute) Wrap {
	attrPtr := ex.attrFunc(&ex.req)
	*attrPtr = append(*attrPtr, attributes...)
	return ex.wrap(ex)
}

// WithAttribute adds a single attribute to the executor by specifying the attribute name and value.
// The attribute index is set to nil by default.
//
// Parameters:
//   - name: The name of the attribute to add.
//   - value: The value of the attribute to add.
func (ex AttributeExecutor[Req, Resp, Wrap]) WithAttribute(name kmip.AttributeName, value any) Wrap {
	return ex.WithAttributes(kmip.Attribute{AttributeName: name, AttributeIndex: nil, AttributeValue: value})
}

// WithUniqueID sets the Unique Identifier attribute for the request.
// The Unique Identifier is typically used to specify the object to operate on in KMIP operations.
//
// Parameters:
//   - id: The unique identifier string to set.
func (ex AttributeExecutor[Req, Resp, Wrap]) WithUniqueID(id string) Wrap {
	return ex.WithAttribute(kmip.AttributeNameUniqueIdentifier, id)
}

// WithName sets the "Name" attribute for the request using the provided name string.
// It wraps the name in a kmip.Name struct with NameType set to UninterpretedTextString.
func (ex AttributeExecutor[Req, Resp, Wrap]) WithName(name string) Wrap {
	return ex.WithAttribute(kmip.AttributeNameName, kmip.Name{
		NameValue: name,
		NameType:  kmip.NameTypeUninterpretedTextString,
	})
}

// WithURI sets the URI attribute for the request by adding a Name attribute with the specified URI value.
//
// Parameters:
//   - uri: The URI string to be set as the Name attribute.
func (ex AttributeExecutor[Req, Resp, Wrap]) WithURI(uri string) Wrap {
	return ex.WithAttribute(kmip.AttributeNameName, kmip.Name{
		NameValue: uri,
		NameType:  kmip.NameTypeUri,
	})
}

// WithLink adds a Link attribute to the request, specifying the relationship between the current object
// and another KMIP object identified by linkedObjectID and the given linkType.
// This method is typically used to establish associations such as "parent", "child",
// or "previous" between managed objects in KMIP.
func (ex AttributeExecutor[Req, Resp, Wrap]) WithLink(linkType kmip.LinkType, linkedObjectID string) Wrap {
	return ex.WithAttribute(kmip.AttributeNameLink, kmip.Link{
		LinkType:               linkType,
		LinkedObjectIdentifier: linkedObjectID,
	})
}

// WithObjectType sets the ObjectType attribute for the request.
// It attaches the specified kmip.ObjectType to the request attributes.
func (ex AttributeExecutor[Req, Resp, Wrap]) WithObjectType(objectType kmip.ObjectType) Wrap {
	return ex.WithAttribute(kmip.AttributeNameObjectType, objectType)
}

// WithUsageLimit sets the usage limits attribute for a KMIP object.
// It specifies the total allowed usage, the unit of usage, and sets the usage count pointer.
// Parameters:
//   - total: The total number of allowed usages.
//   - unit: The unit of usage limits (e.g., operations, time).
func (ex AttributeExecutor[Req, Resp, Wrap]) WithUsageLimit(total int64, unit kmip.UsageLimitsUnit) Wrap {
	return ex.WithAttribute(kmip.AttributeNameUsageLimits, kmip.UsageLimits{
		UsageLimitsTotal: total,
		UsageLimitsCount: &total,
		UsageLimitsUnit:  unit,
	})
}

// PayloadBuilder defines an interface for building KMIP operation payloads.
// Implementations of this interface should provide the Build method, which
// constructs and returns a kmip.OperationPayload along with any error encountered
// during the building process.
type PayloadBuilder interface {
	Build() (kmip.OperationPayload, error)
}

// BatchExec manages the building and the execution of a batch of KMIP operations using a client.
// It holds a reference to the client, any error encountered during batch construction,
// and the list of operation payloads to be executed as a batch.
type BatchExec struct {
	client Client
	err    error
	batch  []kmip.OperationPayload
}

// Then appends a new operation to the current batch by applying the provided
// PayloadBuilder function to the client. If an error has already occurred in the
// Executor, it propagates the error to the BatchExec. Otherwise, it builds the
// new request and adds it to the batch. Returns a BatchExec containing the
// updated batch and any error encountered during the build process.
func (ex Executor[Req, Resp]) Then(f func(client Client) PayloadBuilder) BatchExec {
	batch := BatchExec{
		client: ex.client,
		batch:  []kmip.OperationPayload{ex.req},
	}
	if ex.err != nil {
		batch.err = ex.err
		return batch
	}
	req, err := f(ex.client).Build()
	if err != nil {
		batch.err = err
		return batch
	}
	return BatchExec{
		client: ex.client,
		batch:  []kmip.OperationPayload{ex.req, req},
	}
}

// Then adds a new payload to the batch by invoking the provided function f with the current client.
// If an error has already occurred in the batch execution, it returns the existing BatchExec without modification.
// Otherwise, it builds the payload using the PayloadBuilder returned by f, appends it to the batch, and returns the updated BatchExec.
// If building the payload results in an error, the error is stored in the BatchExec and returned.
func (ex BatchExec) Then(f func(client Client) PayloadBuilder) BatchExec {
	if ex.err != nil {
		return ex
	}
	req, err := f(ex.client).Build()
	if err != nil {
		ex.err = err
		return ex
	}
	ex.batch = append(ex.batch, req)
	return ex
}

// Exec sends the batch to the remote KMIP server, and returns the parsed responses.
//
// Parameters:
//   - opts: Optional BatchOption functions to modify the request message.
//
// Returns:
//   - BatchResult: The results of the batch operations.
//   - error: An error if the batch request fails.
func (ex BatchExec) Exec(opts ...BatchOption) (BatchResult, error) {
	return ex.ExecContext(context.Background(), opts...)
}

// ExecContext sends the batch to the remote KMIP server, and returns the parsed responses.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout.
//   - opts: Optional BatchOption functions to modify the request message.
//
// Returns:
//   - BatchResult: The results of the batch operations.
//   - error: An error if the batch request fails.
func (ex BatchExec) ExecContext(ctx context.Context, opts ...BatchOption) (BatchResult, error) {
	if ex.err != nil {
		return nil, fmt.Errorf("Request initialization failed: %w", ex.err)
	}
	resp, err := ex.client.BatchOpt(ctx, ex.batch, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// MustExec is like Exec except it panics if the request fails.
//
// Parameters:
//   - opts: Optional BatchOption functions to modify the request message.
//
// Returns:
//   - BatchResult: The results of the batch operations.
//
// Panics:
//   - If the request fails, this function panics with the error.
func (ex BatchExec) MustExec(opts ...BatchOption) BatchResult {
	return ex.MustExecContext(context.Background(), opts...)
}

// MustExecContext is like Exec except it panics if the request fails.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout.
//   - opts: Optional BatchOption functions to modify the request message.
//
// Returns:
//   - BatchResult: The results of the batch operations.
//
// Panics:
//   - If the request fails, this function panics with the error.
func (ex BatchExec) MustExecContext(ctx context.Context, opts ...BatchOption) BatchResult {
	resp, err := ex.ExecContext(ctx, opts...)
	if err != nil {
		//TODO: Add operation ID string
		panic(fmt.Errorf("Request failed: %w", err))
	}
	return resp
}

// BatchResult represents a collection of KMIP response batch items returned from a KMIP operation.
type BatchResult []kmip.ResponseBatchItem

// Unwrap checks for eventual errors in all the batch items, and returns an array
// of item's payloads, and the encountered errors. If an item has no payload, the returned
// array will contain a nil element at the item index.
//
// Returns:
//   - []kmip.OperationPayload: The slice of operation payloads from the batch result.
//   - error: An error if any batch item contains an error; otherwise, nil.
func (br BatchResult) Unwrap() ([]kmip.OperationPayload, error) {
	res := make([]kmip.OperationPayload, len(br))
	var errs []error
	for i, br := range br {
		if err := br.Err(); err != nil {
			errs = append(errs, err)
		}
		res[i] = br.ResponsePayload
	}
	return res, errors.Join(errs...)
}

// MustUnwrap is like Unwrap except that it panics if it encounters an error.
// This function should probably not be used in production code and exists only to ease
// testing and experimenting.
//
// Returns:
//   - []kmip.OperationPayload: The slice of operation payloads from the batch result.
//
// Panics:
//   - If any error is encountered in the batch result, this function panics with the error.
func (br BatchResult) MustUnwrap() []kmip.OperationPayload {
	res, err := br.Unwrap()
	if err != nil {
		panic(err)
	}
	return res
}
