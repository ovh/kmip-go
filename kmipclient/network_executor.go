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
)

type networtkOpts struct {
	middlewares []Middleware
	rootCAs     [][]byte
	certs       []tls.Certificate
	serverName  string
	tlsCfg      *tls.Config
	tlsCiphers  []uint16
	dialer      func(context.Context, string) (net.Conn, error)
}

type NetworkOption func(*networtkOpts) error

func (o *networtkOpts) tlsConfig() (*tls.Config, error) {
	cfg := o.tlsCfg
	if cfg == nil {
		cfg = &tls.Config{
			MinVersion: tls.VersionTLS12, // As required by KMIP 1.4 spec

			// CipherSuites: []uint16{
			// 	// Mandatory support as per KMIP 1.4 spec
			// 	// tls.TLS_RSA_WITH_AES_256_CBC_SHA256, // Not supported in Go
			// 	tls.TLS_RSA_WITH_AES_128_CBC_SHA256, // insecure

			// 	// NetworkOptional support as per KMIP 1.4 spec
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

// WithRootCAFile returns an NetworkOption that appends the contents of the specified
// PEM-encoded root CA file to the client's list of root certificate authorities.
// If the provided path is empty, no action is taken. If reading the file fails,
// the returned NetworkOption will propagate the error.
func WithRootCAFile(path string) NetworkOption {
	return func(o *networtkOpts) error {
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

// WithRootCAPem returns an NetworkOption that appends the provided PEM-encoded root CA certificate
// to the client's list of trusted root CAs. This can be used to add custom or additional
// root certificates for TLS connections.
//
// pem: The PEM-encoded root CA certificate as a byte slice.
//
// Example usage:
//
//	client, err := NewClient(WithRootCAPem(myRootCA))
func WithRootCAPem(pem []byte) NetworkOption {
	return func(o *networtkOpts) error {
		o.rootCAs = append(o.rootCAs, pem)
		return nil
	}
}

// WithClientCert returns an NetworkOption that appends the provided TLS client certificate
// to the client's certificate list. This is used to configure the client for mutual TLS authentication.
//
// - cert: The tls.Certificate to be added to the client's certificate pool.
//
// Returns an NetworkOption that can be used to configure the client.
func WithClientCert(cert tls.Certificate) NetworkOption {
	return func(o *networtkOpts) error {
		o.certs = append(o.certs, cert)
		return nil
	}
}

// WithClientCertFiles returns an NetworkOption that loads a client certificate and key from the specified
// files and appends them to the client's certificate pool. It returns an error if the certificate
// or key cannot be loaded.
//
// - certFile: path to the PEM-encoded client certificate file.
// - keyFile:  path to the PEM-encoded private key file.
func WithClientCertFiles(certFile, keyFile string) NetworkOption {
	return func(o *networtkOpts) error {
		tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
		o.certs = append(o.certs, tlsCert)
		return nil
	}
}

// WithClientCertPEM returns an NetworkOption that adds a client certificate to the TLS configuration
// using the provided PEM-encoded certificate and key blocks. The certificate and key must be
// in PEM format. If the certificate or key is invalid, an error is returned.
func WithClientCertPEM(certPEMBlock, keyPEMBlock []byte) NetworkOption {
	return func(o *networtkOpts) error {
		tlsCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
		if err != nil {
			return err
		}
		o.certs = append(o.certs, tlsCert)
		return nil
	}
}

// WithServerName returns an NetworkOption that sets the server name to be used by the client.
// This can be useful for specifying the expected server name in TLS connections.
//
// Parameters:
//   - name: the server name to use.
//
// Returns:
//   - NetworkOption: a function that sets the server name in the client's options.
//   - error   - An error if the connection or protocol negotiation fails.
func WithServerName(name string) NetworkOption {
	return func(o *networtkOpts) error {
		o.serverName = name
		return nil
	}
}

// WithTlsConfig returns an NetworkOption that sets the TLS configuration for the client.
// It allows fine-grained customization of the underlying TLS settings used for secure communication.
//
// Parameters:
//   - cfg: A pointer to a tls.Config struct containing the desired TLS settings.
//
// Returns:
//   - NetworkOption: A function that applies the provided TLS configuration to the client options.
//   - error   - An error if the connection or protocol negotiation fails.
func WithTlsConfig(cfg *tls.Config) NetworkOption {
	return func(o *networtkOpts) error {
		o.tlsCfg = cfg
		return nil
	}
}

// WithTlsCipherSuiteNames returns an NetworkOption that configures the TLS cipher suites to use,
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
func WithTlsCipherSuiteNames(ciphers ...string) NetworkOption {
	return func(o *networtkOpts) error {
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

// WithTlsCipherSuites returns an NetworkOption that appends the provided TLS cipher suite IDs
// to the client's list of supported cipher suites. The cipher suites should be specified
// as uint16 values, typically using the constants defined in the crypto/tls package.
// This allows customization of the TLS handshake to restrict or prioritize certain ciphers.
//
// Example usage:
//
//	client := NewClient(WithTlsCipherSuites(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
func WithTlsCipherSuites(ciphers ...uint16) NetworkOption {
	return func(o *networtkOpts) error {
		o.tlsCiphers = append(o.tlsCiphers, ciphers...)
		return nil
	}
}

// WithDialerUnsafe customize the low-level network dialer used to establish the (secured) connection.
//
// When this option is provided, every other TLS related options are be ignored, and it's
// the dialer responsibility to setup the secured channel using TLS or any other security mechanism.
//
// This option is a low-level escape hatch mainly used for testing or to provide alternative secured
// channel implementation. Use at your own risks.
func WithDialerUnsafe(dialer func(ctx context.Context, addr string) (net.Conn, error)) NetworkOption {
	return func(o *networtkOpts) error {
		o.dialer = dialer
		return nil
	}
}

// WithMiddlewares returns an NetworkOption that appends the provided Middleware(s) to the client's middleware chain.
// This allows customization of the client's behavior by injecting additional processing steps.
//
// Usage:
//
//	client.New(WithMiddlewares(mw1, mw2, ...))
func WithMiddlewares(middlewares ...Middleware) NetworkOption {
	return func(o *networtkOpts) error {
		o.middlewares = append(o.middlewares, middlewares...)
		return nil
	}
}

type ClientNetworkExecutor interface {
	Clone() (ClientNetworkExecutor, error)
	CloneCtx(context.Context) (ClientNetworkExecutor, error)
	Addr() string
	Close() error
	Roundtrip(context.Context, *kmip.RequestMessage) (*kmip.ResponseMessage, error)
}

type KMIPClientNetworkExecutor struct {
	conn        *conn
	dialer      func(context.Context) (*conn, error)
	lock        *sync.Mutex
	middlewares []Middleware
	addr        string
}

// Close terminates the client's connection and releases any associated resources.
// It returns an error if the connection could not be closed.
func (c *KMIPClientNetworkExecutor) Close() error {
	return c.conn.Close()
}

func (c *KMIPClientNetworkExecutor) reconnect(ctx context.Context) error {
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
func (c *KMIPClientNetworkExecutor) doRountrip(ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
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
func (c *KMIPClientNetworkExecutor) Roundtrip(ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
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

// Clone is like CloneCtx but uses internally a background context.
func (c *KMIPClientNetworkExecutor) Clone() (ClientNetworkExecutor, error) {
	return c.CloneCtx(context.Background())
}

// CloneCtx clones the current kmip client into a new independent client
// with a separate new connection. The new client inherits allt he configured parameters
// as well as the negotiated kmip protocol version. Meaning that cloning a client does not perform
// protocol version negotiation.
//
// Cloning a closed client is valid and will create a new connected client.
func (c *KMIPClientNetworkExecutor) CloneCtx(ctx context.Context) (ClientNetworkExecutor, error) {
	stream, err := c.dialer(ctx)
	if err != nil {
		return nil, err
	}
	return &KMIPClientNetworkExecutor{
		lock:        new(sync.Mutex),
		dialer:      c.dialer,
		middlewares: slices.Clone(c.middlewares),
		conn:        stream,
		addr:        c.addr,
	}, nil
}

// Addr returns the address of the KMIP server that the client is configured to connect to.
func (c *KMIPClientNetworkExecutor) Addr() string {
	return c.addr
}

// Dial establishes a connection to the KMIP server at the specified address using the provided options.
// It is a convenience wrapper around DialContext with a background context.
// Returns a pointer to a Client and an error, if any occurs during connection setup.
func Dial(addr string, options ...NetworkOption) (ClientNetworkExecutor, error) {
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
//   - options - NetworkOptional configuration functions to customize client behavior.
//
// Returns:
//
//   - Client - The initialized KMIP client.
//   - error   - An error if the connection or protocol negotiation fails.
func DialContext(ctx context.Context, addr string, options ...NetworkOption) (ClientNetworkExecutor, error) {
	opts := networtkOpts{}
	for _, o := range options {
		if err := o(&opts); err != nil {
			return nil, err
		}
	}

	netDial := opts.dialer
	if netDial == nil {
		tlsCfg, err := opts.tlsConfig()
		if err != nil {
			return nil, err
		}
		netDial = func(ctx context.Context, addr string) (net.Conn, error) {
			tlsDialer := tls.Dialer{
				Config: tlsCfg.Clone(),
			}
			return tlsDialer.DialContext(ctx, "tcp", addr)
		}
	}

	dialer := func(ctx context.Context) (*conn, error) {
		conn, err := netDial(ctx, addr)
		if err != nil {
			return nil, err
		}
		return newConn(conn), nil
	}

	stream, err := dialer(ctx)
	if err != nil {
		return nil, err
	}

	c :=
		&KMIPClientNetworkExecutor{
			lock:        new(sync.Mutex),
			conn:        stream,
			dialer:      dialer,
			middlewares: opts.middlewares,
			addr:        addr,
		}

	return c, nil
}
