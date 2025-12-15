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
//	client, err := kmipclient.Dial("kmip.example.com:5696",
//		kmipclient.WithClientCertFiles("client.crt", "client.key"),
//		kmipclient.WithRootCAFile("ca.crt"),
//	)
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
//   - Client: Represents a KMIP client connection.
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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

var supportedVersions = []kmip.ProtocolVersion{kmip.V1_4, kmip.V1_3, kmip.V1_2, kmip.V1_1, kmip.V1_0}

type opts struct {
	middlewares       []Middleware
	supportedVersions []kmip.ProtocolVersion
	enforceVersion    *kmip.ProtocolVersion
	rootCAs           [][]byte
	certs             []tls.Certificate
	serverName        string
	tlsCfg            *tls.Config
	tlsCiphers        []uint16
	dialer            DialerFunc
	//TODO: Add KMIP Authentication / Credentials
	//TODO: Overwrite default/preferred/supported key formats for register
}

func (o *opts) tlsConfig() (*tls.Config, error) {
	cfg := o.tlsCfg
	if cfg == nil {
		cfg = &tls.Config{
			MinVersion: tls.VersionTLS12, // As required by KMIP 1.4 spec

			// CipherSuites: []uint16{
			// 	// Mandatory support as per KMIP 1.4 spec
			// 	// tls.TLS_RSA_WITH_AES_256_CBC_SHA256, // Not supported in Go
			// 	tls.TLS_RSA_WITH_AES_128_CBC_SHA256, // insecure

			// 	// Optional support as per KMIP 1.4 spec
			// 	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			// 	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			// 	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			// 	tls.TLS_RSA_WITH_AES_128_CBC_SHA,            // insecure
			// 	tls.TLS_RSA_WITH_AES_256_CBC_SHA,            // insecure
			// 	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, // insecure
			// 	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,      // insecure
			// 	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,   // insecure
			// },
		}
	}
	if cfg.RootCAs == nil {
		if len(o.rootCAs) > 0 {
			cfg.RootCAs = x509.NewCertPool()
		} else {
			var err error
			if cfg.RootCAs, err = x509.SystemCertPool(); err != nil {
				return nil, err
			}
		}
	}
	for _, ca := range o.rootCAs {
		cfg.RootCAs.AppendCertsFromPEM(ca)
	}
	cfg.Certificates = append(cfg.Certificates, o.certs...)
	if cfg.ServerName == "" {
		cfg.ServerName = o.serverName
	}

	for _, cipher := range o.tlsCiphers {
		if !slices.Contains(cfg.CipherSuites, cipher) {
			cfg.CipherSuites = append(cfg.CipherSuites, cipher)
		}
	}

	return cfg, nil
}

type Option func(*opts) error

// WithMiddlewares returns an Option that appends the provided Middleware(s) to the client's middleware chain.
// This allows customization of the client's behavior by injecting additional processing steps.
//
// Usage:
//
//	client.New(WithMiddlewares(mw1, mw2, ...))
func WithMiddlewares(middlewares ...Middleware) Option {
	return func(o *opts) error {
		o.middlewares = append(o.middlewares, middlewares...)
		return nil
	}
}

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

// WithRootCAFile returns an Option that appends the contents of the specified
// PEM-encoded root CA file to the client's list of root certificate authorities.
// If the provided path is empty, no action is taken. If reading the file fails,
// the returned Option will propagate the error.
func WithRootCAFile(path string) Option {
	return func(o *opts) error {
		if path == "" {
			return nil
		}
		pem, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		o.rootCAs = append(o.rootCAs, pem)
		return nil
	}
}

// WithRootCAPem returns an Option that appends the provided PEM-encoded root CA certificate
// to the client's list of trusted root CAs. This can be used to add custom or additional
// root certificates for TLS connections.
//
// pem: The PEM-encoded root CA certificate as a byte slice.
//
// Example usage:
//
//	client, err := NewClient(WithRootCAPem(myRootCA))
func WithRootCAPem(pem []byte) Option {
	return func(o *opts) error {
		o.rootCAs = append(o.rootCAs, pem)
		return nil
	}
}

// WithClientCert returns an Option that appends the provided TLS client certificate
// to the client's certificate list. This is used to configure the client for mutual TLS authentication.
//
// - cert: The tls.Certificate to be added to the client's certificate pool.
//
// Returns an Option that can be used to configure the client.
func WithClientCert(cert tls.Certificate) Option {
	return func(o *opts) error {
		o.certs = append(o.certs, cert)
		return nil
	}
}

// WithClientCertFiles returns an Option that loads a client certificate and key from the specified
// files and appends them to the client's certificate pool. It returns an error if the certificate
// or key cannot be loaded.
//
// - certFile: path to the PEM-encoded client certificate file.
// - keyFile:  path to the PEM-encoded private key file.
func WithClientCertFiles(certFile, keyFile string) Option {
	return func(o *opts) error {
		tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
		o.certs = append(o.certs, tlsCert)
		return nil
	}
}

// WithClientCertPEM returns an Option that adds a client certificate to the TLS configuration
// using the provided PEM-encoded certificate and key blocks. The certificate and key must be
// in PEM format. If the certificate or key is invalid, an error is returned.
func WithClientCertPEM(certPEMBlock, keyPEMBlock []byte) Option {
	return func(o *opts) error {
		tlsCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
		if err != nil {
			return err
		}
		o.certs = append(o.certs, tlsCert)
		return nil
	}
}

// WithServerName returns an Option that sets the server name to be used by the client.
// This can be useful for specifying the expected server name in TLS connections.
//
// Parameters:
//   - name: the server name to use.
//
// Returns:
//   - Option: a function that sets the server name in the client's options.
//   - error   - An error if the connection or protocol negotiation fails.
func WithServerName(name string) Option {
	return func(o *opts) error {
		o.serverName = name
		return nil
	}
}

// WithTlsConfig returns an Option that sets the TLS configuration for the client.
// It allows fine-grained customization of the underlying TLS settings used for secure communication.
//
// Parameters:
//   - cfg: A pointer to a tls.Config struct containing the desired TLS settings.
//
// Returns:
//   - Option: A function that applies the provided TLS configuration to the client options.
//   - error   - An error if the connection or protocol negotiation fails.
func WithTlsConfig(cfg *tls.Config) Option {
	return func(o *opts) error {
		o.tlsCfg = cfg
		return nil
	}
}

// WithTlsCipherSuiteNames returns an Option that configures the TLS cipher suites to use,
// based on the provided list of cipher suite names. Each name is matched against the list
// of supported and insecure cipher suites. If a name does not match any known cipher suite,
// an error is returned. This option allows fine-grained control over the TLS cipher suites
// used by the client for secure connections.
//
// Example usage:
//
//	client, err := NewClient(
//	    WithTlsCipherSuiteNames("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384"),
//	)
func WithTlsCipherSuiteNames(ciphers ...string) Option {
	return func(o *opts) error {
	search:
		for _, cipherName := range ciphers {
			for _, s := range tls.CipherSuites() {
				if s.Name != cipherName {
					continue
				}
				o.tlsCiphers = append(o.tlsCiphers, s.ID)
				continue search
			}
			for _, s := range tls.InsecureCipherSuites() {
				if s.Name != cipherName {
					continue
				}
				o.tlsCiphers = append(o.tlsCiphers, s.ID)
				continue search
			}
			return fmt.Errorf("invalid TLS cipher name %q", cipherName)
		}
		return nil
	}
}

// WithTlsCipherSuites returns an Option that appends the provided TLS cipher suite IDs
// to the client's list of supported cipher suites. The cipher suites should be specified
// as uint16 values, typically using the constants defined in the crypto/tls package.
// This allows customization of the TLS handshake to restrict or prioritize certain ciphers.
//
// Example usage:
//
//	client := NewClient(WithTlsCipherSuites(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
func WithTlsCipherSuites(ciphers ...uint16) Option {
	return func(o *opts) error {
		o.tlsCiphers = append(o.tlsCiphers, ciphers...)
		return nil
	}
}

type DialerFunc func(ctx context.Context, addr string, tlsCfg *tls.Config) (net.Conn, error)

// WithDialerUnsafe customize the low-level network dialer used to establish the (secured) connection.
//
// When this option is provided, every other TLS related options are be ignored, and it's
// the dialer responsibility to setup the secured channel using TLS or any other security mechanism.
//
// This option is a low-level escape hatch mainly used for testing or to provide alternative secured
// channel implementation. Use at your own risks.
func WithDialerUnsafe(dialer DialerFunc) Option {
	return func(o *opts) error {
		o.dialer = dialer
		return nil
	}
}

func TlsDialer(ctx context.Context, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	tlsDialer := tls.Dialer{
		Config: tlsCfg,
	}
	return tlsDialer.DialContext(ctx, "tcp", addr)
}

// Client represents a KMIP client that manages a connection to a KMIP server,
// handles protocol version negotiation, and supports middleware for request/response
// processing. It provides thread-safe access to the underlying connection and
// configuration options such as supported protocol versions and custom dialers.
type Client struct {
	lock              *sync.Mutex
	conn              *conn
	version           *kmip.ProtocolVersion
	supportedVersions []kmip.ProtocolVersion
	dialer            func(context.Context) (*conn, error)
	middlewares       []Middleware
	addr              string
}

// Dial establishes a connection to the KMIP server at the specified address using the provided options.
// It is a convenience wrapper around DialContext with a background context.
// Returns a pointer to a Client and an error, if any occurs during connection setup.
func Dial(addr string, options ...Option) (*Client, error) {
	return DialContext(context.Background(), addr, options...)
}

// DialContext establishes a new KMIP client connection to the specified address using the provided context and optional configuration options.
// It applies the given options, sets up TLS configuration, and negotiates the protocol version with the server.
// Returns a pointer to the initialized Client or an error if the connection or negotiation fails.
//
// Parameters:
//
//   - ctx    - The context for controlling cancellation and timeout of the dialing process.
//   - addr   - The network address of the KMIP server to connect to.
//   - options - Optional configuration functions to customize client behavior.
//
// Returns:
//
//   - *Client - The initialized KMIP client.
//   - error   - An error if the connection or protocol negotiation fails.
func DialContext(ctx context.Context, addr string, options ...Option) (*Client, error) {
	opts := opts{}
	for _, o := range options {
		if err := o(&opts); err != nil {
			return nil, err
		}
	}
	if len(opts.supportedVersions) == 0 {
		opts.supportedVersions = append(opts.supportedVersions, supportedVersions...)
	}

	netDial := opts.dialer
	if netDial == nil {
		netDial = TlsDialer
	}

	tlsCfg, err := opts.tlsConfig()
	if err != nil {
		return nil, err
	}

	dialer := func(ctx context.Context) (*conn, error) {
		conn, err := netDial(ctx, addr, tlsCfg)
		if err != nil {
			return nil, err
		}
		return newConn(conn), nil
	}

	stream, err := dialer(ctx)
	if err != nil {
		return nil, err
	}

	c := &Client{
		lock:              new(sync.Mutex),
		conn:              stream,
		dialer:            dialer,
		supportedVersions: opts.supportedVersions,
		version:           opts.enforceVersion,
		middlewares:       opts.middlewares,
		addr:              addr,
	}

	// Negotiate protocol version
	if err := c.negotiateVersion(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}

	return c, nil
}

// Clone is like CloneCtx but uses internally a background context.
func (c *Client) Clone() (*Client, error) {
	return c.CloneCtx(context.Background())
}

// CloneCtx clones the current kmip client into a new independent client
// with a separate new connection. The new client inherits allt he configured parameters
// as well as the negotiated kmip protocol version. Meaning that cloning a client does not perform
// protocol version negotiation.
//
// Cloning a closed client is valid and will create a new connected client.
func (c *Client) CloneCtx(ctx context.Context) (*Client, error) {
	stream, err := c.dialer(ctx)
	if err != nil {
		return nil, err
	}
	version := *c.version
	return &Client{
		lock:              new(sync.Mutex),
		version:           &version,
		supportedVersions: slices.Clone(c.supportedVersions),
		dialer:            c.dialer,
		middlewares:       slices.Clone(c.middlewares),
		conn:              stream,
		addr:              c.addr,
	}, nil
}

// Version returns the KMIP protocol version used by the client.
func (c *Client) Version() kmip.ProtocolVersion {
	return *c.version
}

// Addr returns the address of the KMIP server that the client is configured to connect to.
func (c *Client) Addr() string {
	return c.addr
}

// Close terminates the client's connection and releases any associated resources.
// It returns an error if the connection could not be closed.
func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) reconnect(ctx context.Context) error {
	// fmt.Println("Reconnecting")
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	stream, err := c.dialer(ctx)
	if err != nil {
		return err
	}
	c.conn = stream
	return nil
}

// doRountrip sends a KMIP request message to the server and returns the corresponding response message.
// It ensures thread safety by locking the client during the operation. If the connection is not established,
// it attempts to reconnect. The method includes a retry mechanism for transient connection errors such as
// io.EOF and io.ErrClosedPipe, attempting to reconnect and resend the request up to three times before failing.
// Returns the response message on success, or an error if the operation ultimately fails.
func (c *Client) doRountrip(ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.conn == nil {
		if err := c.reconnect(ctx); err != nil {
			return nil, err
		}
	}

	//TODO: Better reconnection loop. Do we really need a retry counter here ?
	retry := 3
	for {
		resp, err := c.conn.roundtrip(ctx, msg)
		if err == nil {
			return resp, nil
		}
		if retry <= 0 || (!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe)) {
			return nil, err
		}
		if err := c.reconnect(ctx); err != nil {
			return nil, err
		}
		retry--
	}
}

// Roundtrip sends a KMIP request message through the client's middleware chain and returns the response.
// Each middleware can process the request and response, or pass it along to the next middleware in the chain.
// The final handler sends the request using the client's doRountrip method.
//
// Parameters:
//
//   - ctx - The context for controlling cancellation and deadlines.
//   - msg - The KMIP request message to be sent.
//
// Returns:
//
//   - *kmip.ResponseMessage - The KMIP response message received.
//   - error - Any error encountered during processing or sending the request.
func (c *Client) Roundtrip(ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
	i := 0
	var next func(ctx context.Context, req *kmip.RequestMessage) (*kmip.ResponseMessage, error)
	next = func(ctx context.Context, req *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
		if i < len(c.middlewares) {
			mdl := c.middlewares[i]
			i++
			return mdl(next, ctx, req)
		}
		return c.doRountrip(ctx, req)
	}
	return next(ctx, msg)
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
func (c *Client) negotiateVersion(ctx context.Context) error {
	if c.version != nil {
		return nil
	}
	msg := kmip.NewRequestMessage(kmip.V1_1, &payloads.DiscoverVersionsRequestPayload{
		ProtocolVersion: c.supportedVersions,
	})

	resp, err := c.Roundtrip(ctx, &msg)
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
func (c *Client) Request(ctx context.Context, payload kmip.OperationPayload) (kmip.OperationPayload, error) {
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
func (c *Client) Batch(ctx context.Context, payloads ...kmip.OperationPayload) (BatchResult, error) {
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
func (c *Client) BatchOpt(ctx context.Context, payloads []kmip.OperationPayload, opts ...BatchOption) (BatchResult, error) {
	msg := kmip.NewRequestMessage(*c.version, payloads...)
	for _, opt := range opts {
		opt(&msg)
	}
	resp, err := c.Roundtrip(ctx, &msg)
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
	client *Client
	req    Req
	err    error
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
	client *Client
	err    error
	batch  []kmip.OperationPayload
}

// Then appends a new operation to the current batch by applying the provided
// PayloadBuilder function to the client. If an error has already occurred in the
// Executor, it propagates the error to the BatchExec. Otherwise, it builds the
// new request and adds it to the batch. Returns a BatchExec containing the
// updated batch and any error encountered during the build process.
func (ex Executor[Req, Resp]) Then(f func(client *Client) PayloadBuilder) BatchExec {
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
func (ex BatchExec) Then(f func(client *Client) PayloadBuilder) BatchExec {
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
