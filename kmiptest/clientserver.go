// Package kmiptest provides utilities for testing KMIP (Key Management Interoperability Protocol) servers and clients.
// It includes helper functions to create in-memory KMIP servers and clients for use in unit tests.
//
// The package defines the TestingT interface, which abstracts the testing.T type, allowing for error reporting and cleanup registration.
//
// Functions:
//   - NewServer: Starts a new in-memory KMIP server with a self-signed certificate and the provided request handler.
//     Returns the server address and the PEM-encoded CA certificate.
//   - NewClientAndServer: Starts a new KMIP server and returns a connected client configured with the server's CA certificate.
//     Registers cleanup functions to shut down the server and client after the test.
package kmiptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/ttlv"

	"github.com/stretchr/testify/require"
)

// TestingT is an interface wrapper around *testing.T.
type TestingT interface {
	Errorf(format string, args ...any)
	FailNow()
	Cleanup(func())
}

func newRequestId() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	// Set version (4) and variant bits according to RFC 4122
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant is 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// NewServer starts a new in-memory TLS server for testing purposes using the provided
// kmipserver.RequestHandler. It generates a self-signed ECDSA certificate for the server,
// listens on a random local port, and starts serving requests in a separate goroutine.
// The server is automatically shut down when the test completes. The function returns
// the server's address and the PEM-encoded CA certificate as strings.
//
// Parameters:
//   - t: A TestingT instance (typically *testing.T or *testing.B) used for test assertions and cleanup.
//   - hdl: The kmipserver.RequestHandler to handle incoming requests.
//
// Returns:
//   - addr: The address the server is listening on (e.g., "127.0.0.1:port").
//   - ca: The PEM-encoded CA certificate used by the server.
func NewServer(t TestingT, hdl kmipserver.RequestHandler) (addr, ca string) {
	caTpl := x509.Certificate{
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SerialNumber: big.NewInt(2),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert, err := x509.CreateCertificate(rand.Reader, &caTpl, &caTpl, k.Public(), k)
	require.NoError(t, err)

	require.NoError(t, err)
	list, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: k}},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)

	srv := kmipserver.NewServer(list, hdl)
	go func() {
		if err := srv.Serve(); err != nil && !errors.Is(err, kmipserver.ErrShutdown) {
			t.Errorf("server error: %w", err)
		}
	}()
	t.Cleanup(func() {
		if err := srv.Shutdown(); err != nil {
			t.Errorf("server failed to shutdown: %w", err)
		}
	})

	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	return list.Addr().String(), string(pemCA)
}

// NewClientAndServer creates and returns a new KMIP client connected to a test server.
//
// It starts a new KMIP server using the provided request handler `hdl` and establishes a client
// connection to it. The client is configured with the server's CA certificate, a correlation value
// middleware, a testing middleware, and a debug middleware that outputs to stderr in XML format.
//
// The function registers a cleanup function to close the client connection when the test completes.
//
// Parameters:
//   - t: A testing interface used for assertions and cleanup registration.
//   - hdl: The KMIP server request handler.
//
// Returns:
//   - A pointer to the initialized KMIP client.
//
// The function will fail the test if the client cannot be created.
func NewClientAndServer(t TestingT, hdl kmipserver.RequestHandler) kmipclient.Client {
	addr, ca := NewServer(t, hdl)
	client, err := kmipclient.Dial(addr, kmipclient.WithRootCAPem([]byte(ca)), kmipclient.WithMiddlewares(
		kmipclient.CorrelationValueMiddleware(newRequestId),
		TestingMiddleware(t),
		kmipclient.DebugMiddleware(os.Stderr, ttlv.MarshalXML),
	))
	require.NoError(t, err)
	require.NotNil(t, client)
	t.Cleanup(func() {
		_ = client.Close()
	})
	return client
}
