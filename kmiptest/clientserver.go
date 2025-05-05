package kmiptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/ttlv"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestingT is an interface wrapper around *testing.T.
type TestingT interface {
	Errorf(format string, args ...any)
	FailNow()
	Cleanup(func())
}

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

func NewClientAndServer(t TestingT, hdl kmipserver.RequestHandler) *kmipclient.Client {
	addr, ca := NewServer(t, hdl)
	client, err := kmipclient.Dial(addr, kmipclient.WithRootCAPem([]byte(ca)), kmipclient.WithMiddlewares(
		kmipclient.CorrelationValueMiddleware(uuid.NewString),
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
