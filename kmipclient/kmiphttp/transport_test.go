package kmiphttp_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmipclient/kmiphttp"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"

	"github.com/stretchr/testify/require"
)

// newHTTPSTestServer wraps the given handler in an HTTPS httptest server and
// returns the host:port address (suitable for passing to Dial) and the PEM-encoded
// server certificate (suitable for WithRootCAPem).
func newHTTPSTestServer(t *testing.T, hdl http.Handler) (addr string, caPEM []byte) {
	t.Helper()
	srv := httptest.NewTLSServer(hdl)
	t.Cleanup(srv.Close)
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return srv.Listener.Addr().String(), caPEM
}

// newKMIPHTTPSServer registers an Activate handler and returns an HTTPS test server.
func newKMIPHTTPSServer(t *testing.T) (addr string, caPEM []byte) {
	t.Helper()
	mux := kmipserver.NewBatchExecutor()
	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(
		func(_ context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
			return &payloads.ActivateResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
		}))
	return newHTTPSTestServer(t, kmipserver.NewHTTPHandler(mux))
}

func TestHTTPTransport_WireFormats(t *testing.T) {
	addr, ca := newKMIPHTTPSServer(t)

	for _, tc := range []struct {
		name string
		f    kmiphttp.WireFormat
	}{
		{"TTLV", kmiphttp.WireTTLV},
		{"XML", kmiphttp.WireXML},
		{"JSON", kmiphttp.WireJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := kmipclient.Dial(addr,
				kmiphttp.WithTransport("/", kmiphttp.WithWireFormat(tc.f)),
				kmipclient.WithRootCAPem(ca),
			)
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })

			require.NotNil(t, client.Version())

			resp, err := client.Activate("uid-42").Exec()
			require.NoError(t, err)
			require.Equal(t, "uid-42", resp.UniqueIdentifier)
		})
	}
}

func TestHTTPTransport_DefaultWireIsTTLV(t *testing.T) {
	addr, ca := newKMIPHTTPSServer(t)

	client, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/"),
		kmipclient.WithRootCAPem(ca),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	resp, err := client.Activate("foo").Exec()
	require.NoError(t, err)
	require.Equal(t, "foo", resp.UniqueIdentifier)
}

func TestHTTPTransport_PathRoutedToServer(t *testing.T) {
	mux := http.NewServeMux()
	kmipMux := kmipserver.NewBatchExecutor()
	kmipMux.Route(kmip.OperationActivate, kmipserver.HandleFunc(
		func(_ context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
			return &payloads.ActivateResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
		}))
	mux.Handle("/kmip", kmipserver.NewHTTPHandler(kmipMux))

	addr, ca := newHTTPSTestServer(t, mux)

	client, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/kmip"),
		kmipclient.WithRootCAPem(ca),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	resp, err := client.Activate("p").Exec()
	require.NoError(t, err)
	require.Equal(t, "p", resp.UniqueIdentifier)
}

func TestHTTPTransport_NonOKError(t *testing.T) {
	addr, ca := newHTTPSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	}))

	_, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/"),
		kmipclient.WithRootCAPem(ca),
	)
	require.Error(t, err)
	var hErr *kmiphttp.Error
	require.ErrorAs(t, err, &hErr)
	require.Equal(t, http.StatusInternalServerError, hErr.StatusCode)
	require.Contains(t, string(hErr.Body), "boom")
}

func TestHTTPTransport_ResponseTooLarge(t *testing.T) {
	// Server returns a response with a deliberately large UID so the response body
	// exceeds the client's max-message-size while the request body remains small.
	addr, ca := newHTTPSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := &kmip.ResponseMessage{
			Header: kmip.ResponseHeader{
				ProtocolVersion: kmip.V1_4,
				BatchCount:      1,
			},
			BatchItem: []kmip.ResponseBatchItem{{
				Operation:    kmip.OperationActivate,
				ResultStatus: kmip.ResultStatusSuccess,
				ResponsePayload: &payloads.ActivateResponsePayload{
					UniqueIdentifier: strings.Repeat("a", 4096),
				},
			}},
		}
		body := ttlv.MarshalTTLV(resp)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))

	client, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/"),
		kmipclient.WithRootCAPem(ca),
		kmipclient.EnforceVersion(kmip.V1_4),
		kmipclient.WithMaxMessageSize(512),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Activate("uid").Exec()
	require.ErrorIs(t, err, kmipclient.ErrResponseTooLarge)
}

func TestHTTPTransport_HeaderInjected(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(
		func(_ context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
			return &payloads.ActivateResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
		}))

	var seen atomic.Value
	addr, ca := newHTTPSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Get("X-Foo"))
		kmipserver.NewHTTPHandler(mux).ServeHTTP(w, r)
	}))

	client, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/", kmiphttp.WithHeader("X-Foo", "bar")),
		kmipclient.WithRootCAPem(ca),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Activate("h").Exec()
	require.NoError(t, err)
	require.Equal(t, "bar", seen.Load())
}

func TestHTTPTransport_RejectsReservedHeader(t *testing.T) {
	for _, key := range []string{
		"Content-Type", "content-type", // canonicalization must be applied
		"Accept",
		"Content-Length",
		"Host",
		"Transfer-Encoding", "transfer-encoding",
		"Trailer",
	} {
		t.Run(key, func(t *testing.T) {
			_, err := kmipclient.Dial("127.0.0.1:1",
				kmiphttp.WithTransport("/", kmiphttp.WithHeader(key, "x")),
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), "reserved")
		})
	}
}

type countingRoundTripper struct {
	inner http.RoundTripper
	calls atomic.Int64
}

func (c *countingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return c.inner.RoundTrip(req)
}

// httpClientWithCA builds an *http.Client that trusts the given PEM CA. Used when
// passing a custom http.Client through WithClient (which bypasses kmipclient's
// own TLS plumbing).
func httpClientWithCA(t *testing.T, caPEM []byte, rt http.RoundTripper) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM), "appending CA")
	if base, ok := rt.(*countingRoundTripper); ok {
		inner := base.inner.(*http.Transport).Clone()
		inner.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		base.inner = inner
		return &http.Client{Transport: base}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr}
}

func TestHTTPTransport_CustomHTTPClient(t *testing.T) {
	addr, ca := newKMIPHTTPSServer(t)

	rt := &countingRoundTripper{inner: http.DefaultTransport}
	hc := httpClientWithCA(t, ca, rt)

	client, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/", kmiphttp.WithClient(hc)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Activate("a").Exec()
	require.NoError(t, err)
	_, err = client.Activate("b").Exec()
	require.NoError(t, err)

	// 1 DiscoverVersions during Dial + 2 Activate = 3
	require.GreaterOrEqual(t, rt.calls.Load(), int64(3))
}

func TestHTTPTransport_CloneSharesPool(t *testing.T) {
	addr, ca := newKMIPHTTPSServer(t)

	rt := &countingRoundTripper{inner: http.DefaultTransport}
	hc := httpClientWithCA(t, ca, rt)

	c1, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/", kmiphttp.WithClient(hc)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c1.Close() })

	c2, err := c1.Clone()
	require.NoError(t, err)
	t.Cleanup(func() { _ = c2.Close() })

	before := rt.calls.Load()
	_, err = c2.Activate("clone").Exec()
	require.NoError(t, err)
	require.Equal(t, before+1, rt.calls.Load(),
		"clone should reuse the same http.Client (no extra round-trip on Clone)")
}

func TestHTTPTransport_CloneCloseIndependence(t *testing.T) {
	addr, ca := newKMIPHTTPSServer(t)

	c1, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/"),
		kmipclient.WithRootCAPem(ca),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c1.Close() })

	c2, err := c1.Clone()
	require.NoError(t, err)
	t.Cleanup(func() { _ = c2.Close() })

	require.NoError(t, c1.Close())

	resp, err := c2.Activate("clone-survives").Exec()
	require.NoError(t, err)
	require.Equal(t, "clone-survives", resp.UniqueIdentifier)

	_, err = c1.Activate("orig-closed").Exec()
	require.ErrorIs(t, err, net.ErrClosed)
}

// TestHTTPTransport_RejectsBadPath covers every path-shape rejection in one
// table. Each case fails at config-validation time (no real connection to
// 127.0.0.1:1 is ever attempted), so the suite stays cheap.
func TestHTTPTransport_RejectsBadPath(t *testing.T) {
	for _, tc := range []struct {
		name      string
		path      string
		substring string
	}{
		{"NoLeadingSlash", "kmip", "must start with"},
		// Fragments are silently stripped from the request line by net/http;
		// rejecting at build time prevents that surprise.
		{"Fragment", "/kmip#frag", "fragment"},
		// KMIP-over-HTTPS has no query semantics, but a query string would
		// otherwise ride on every POST.
		{"QueryString", "/kmip?foo=bar", "query string"},
		// Caught by buildRequestURL's url.Parse — assert on "control" so the
		// expectation is pinned to net/url's "invalid control character in URL"
		// wording rather than any "kmip http:"-prefixed error.
		{"ControlChar", "/foo\x00bar", "control"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := kmipclient.Dial("127.0.0.1:1",
				kmiphttp.WithTransport(tc.path),
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.substring)
		})
	}
}

// TestHTTPTransport_AggregatesPathErrors locks in that all three path-shape
// checks (prefix, fragment, query) run independently, so a single bad path
// surfaces every problem at once instead of stopping at the first.
func TestHTTPTransport_AggregatesPathErrors(t *testing.T) {
	_, err := kmipclient.Dial("127.0.0.1:1",
		kmiphttp.WithTransport("bad#frag?q=1"),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "must start with")
	require.Contains(t, err.Error(), "fragment")
	require.Contains(t, err.Error(), "query string")
}

// TestHTTPTransport_DoesNotFollowRedirect locks in the documented contract
// that the default http.Client refuses to follow 3xx responses, surfacing
// them as a typed [*kmiphttp.Error] with the redirect status code.
//
// Implementation note: this test relies on Dial performing protocol version
// negotiation, which issues a real round-trip and therefore exercises the
// no-redirect policy. If version negotiation is ever made lazy, this test
// will need to issue an explicit round-trip after Dial instead.
func TestHTTPTransport_DoesNotFollowRedirect(t *testing.T) {
	addr, ca := newHTTPSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://elsewhere.invalid/")
		w.WriteHeader(http.StatusFound)
	}))

	_, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/"),
		kmipclient.WithRootCAPem(ca),
	)
	require.Error(t, err)
	var hErr *kmiphttp.Error
	require.ErrorAs(t, err, &hErr)
	require.Equal(t, http.StatusFound, hErr.StatusCode)
}

// TestHTTPTransport_WithClient_PreservesCheckRedirect verifies that when the
// caller supplies their own *http.Client, the transport does NOT override its
// CheckRedirect policy — the caller owns redirect handling. We prove this by
// installing a sentinel CheckRedirect: if the transport had clobbered it with
// noFollowRedirect, the response would surface as a *kmiphttp.Error instead.
func TestHTTPTransport_WithClient_PreservesCheckRedirect(t *testing.T) {
	addr, ca := newHTTPSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://elsewhere.invalid/")
		w.WriteHeader(http.StatusFound)
	}))

	sentinel := errors.New("custom CheckRedirect")
	hc := httpClientWithCA(t, ca, nil)
	hc.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return sentinel }

	_, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/", kmiphttp.WithClient(hc)),
	)
	require.Error(t, err)
	require.ErrorIs(t, err, sentinel)
}

// TestHTTPTransport_AggregatesConfigErrors: a user with several mistakes
// (bad path + bad header + reserved header) sees them all at once.
func TestHTTPTransport_AggregatesConfigErrors(t *testing.T) {
	_, err := kmipclient.Dial("127.0.0.1:1",
		kmiphttp.WithTransport("kmip", // bad path
			kmiphttp.WithHeader("", "v"),             // empty header key
			kmiphttp.WithHeader("Content-Type", "x"), // reserved header
		),
	)
	require.Error(t, err)
	msg := err.Error()
	require.Contains(t, msg, "must start with")
	require.Contains(t, msg, "empty header key")
	require.Contains(t, msg, "reserved")
}

func TestHTTPTransport_RejectsEmptyHeaderKey(t *testing.T) {
	_, err := kmipclient.Dial("127.0.0.1:1",
		kmiphttp.WithTransport("/", kmiphttp.WithHeader("", "v")),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty header key")
}

func TestHTTPTransport_RejectedByDialCluster(t *testing.T) {
	_, err := kmipclient.DialCluster([]string{"127.0.0.1:1", "127.0.0.1:2"},
		kmiphttp.WithTransport("/"),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "DialCluster")
}

func TestHTTPTransport_RejectsAddrWithScheme(t *testing.T) {
	_, err := kmipclient.Dial("https://127.0.0.1:1",
		kmiphttp.WithTransport("/"),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "host:port")
}

func TestHTTPTransport_RejectsMalformedAddr(t *testing.T) {
	_, err := kmipclient.Dial("not-an-address",
		kmiphttp.WithTransport("/"),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid addr")
}

// TestHTTPTransport_RejectsHTTPClientWithTLSOptions ensures every standard TLS
// option triggers the up-front rejection when combined with WithClient,
// matching the documented contract.
func TestHTTPTransport_RejectsHTTPClientWithTLSOptions(t *testing.T) {
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("fake")})

	for name, tlsOpt := range map[string]kmipclient.Option{
		"WithRootCAPem":      kmipclient.WithRootCAPem(pemBlock),
		"WithServerName":     kmipclient.WithServerName("kms.example.com"),
		"WithTlsConfig":      kmipclient.WithTlsConfig(&tls.Config{MinVersion: tls.VersionTLS12}),
		"WithTlsCipherSuite": kmipclient.WithTlsCipherSuites(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := kmipclient.Dial("127.0.0.1:1",
				kmiphttp.WithTransport("/", kmiphttp.WithClient(&http.Client{})),
				tlsOpt,
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), "mutually exclusive")
		})
	}
}

// TestHTTPTransport_RejectsHTTPClientWithDialer ensures that combining
// WithClient and WithDialerUnsafe is rejected up-front: the dialer would
// silently never be invoked because the supplied http.Client is used as-is, and
// failing fast is preferable to that surprise.
func TestHTTPTransport_RejectsHTTPClientWithDialer(t *testing.T) {
	_, err := kmipclient.Dial("127.0.0.1:1",
		kmiphttp.WithTransport("/", kmiphttp.WithClient(&http.Client{})),
		kmipclient.WithDialerUnsafe(func(context.Context, string) (net.Conn, error) {
			return nil, errors.New("should not be called")
		}),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
}

func TestHTTPTransport_MiddlewareRuns(t *testing.T) {
	addr, ca := newKMIPHTTPSServer(t)

	var ran atomic.Bool
	mw := kmipclient.Middleware(func(next kmipclient.Next, ctx context.Context, req *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
		ran.Store(true)
		return next(ctx, req)
	})

	client, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/"),
		kmipclient.WithRootCAPem(ca),
		kmipclient.WithMiddlewares(mw),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Activate("m").Exec()
	require.NoError(t, err)
	require.True(t, ran.Load())
}

// roundTripperFunc adapts a plain function to http.RoundTripper, so tests can
// install a wrapper inline without declaring a struct each time.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestHTTPTransport_RoundTripperWraps(t *testing.T) {
	addr, ca := newKMIPHTTPSServer(t)

	var seenURL atomic.Value
	var calls atomic.Int64
	wrap := func(next http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			calls.Add(1)
			seenURL.Store(req.URL.String())
			return next.RoundTrip(req)
		})
	}

	client, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/", kmiphttp.WrapRoundTripper(wrap)),
		kmipclient.WithRootCAPem(ca),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Activate("rt").Exec()
	require.NoError(t, err)

	require.GreaterOrEqual(t, calls.Load(), int64(1), "wrapper must observe the request")
	require.Equal(t, "https://"+addr+"/", seenURL.Load())
}

func TestHTTPTransport_RoundTripperOrder(t *testing.T) {
	addr, ca := newKMIPHTTPSServer(t)

	var mu sync.Mutex
	var order []string
	record := func(name string) func(http.RoundTripper) http.RoundTripper {
		return func(next http.RoundTripper) http.RoundTripper {
			return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				mu.Lock()
				order = append(order, name+"-in")
				mu.Unlock()
				resp, err := next.RoundTrip(req)
				mu.Lock()
				order = append(order, name+"-out")
				mu.Unlock()
				return resp, err
			})
		}
	}

	client, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/",
			kmiphttp.WrapRoundTripper(record("a")),
			kmiphttp.WrapRoundTripper(record("b")),
		),
		kmipclient.WithRootCAPem(ca),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// Dial performs a protocol-version negotiation roundtrip, which the
	// wrappers see; reset so the assertion covers exactly the Activate call.
	mu.Lock()
	order = order[:0]
	mu.Unlock()

	_, err = client.Activate("ord").Exec()
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"a-in", "b-in", "b-out", "a-out"}, order,
		"first registered wrapper must be outermost")
}

func TestHTTPTransport_RejectsRoundTripperWithHTTPClient(t *testing.T) {
	wrap := func(next http.RoundTripper) http.RoundTripper { return next }
	_, err := kmipclient.Dial("127.0.0.1:1",
		kmiphttp.WithTransport("/",
			kmiphttp.WithClient(&http.Client{}),
			kmiphttp.WrapRoundTripper(wrap),
		),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
}

func TestHTTPTransport_RejectsNilRoundTripper(t *testing.T) {
	_, err := kmipclient.Dial("127.0.0.1:1",
		kmiphttp.WithTransport("/", kmiphttp.WrapRoundTripper(nil)),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil RoundTripper")
}

// TestHTTPTransport_RejectsRoundTripperReturningNil also checks that the error
// names the offending wrapper by index, so multi-wrapper setups are diagnosable.
func TestHTTPTransport_RejectsRoundTripperReturningNil(t *testing.T) {
	identity := func(next http.RoundTripper) http.RoundTripper { return next }
	returnsNil := func(http.RoundTripper) http.RoundTripper { return nil }
	_, err := kmipclient.Dial("127.0.0.1:1",
		kmiphttp.WithTransport("/",
			kmiphttp.WrapRoundTripper(identity),
			kmiphttp.WrapRoundTripper(returnsNil),
		),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "wrapper #1 returned nil")
}

// TestHTTPTransport_ServerCertVerify ensures TLS options actually flow into the
// HTTP transport: pointing at an HTTPS server without supplying the CA must fail
// verification.
func TestHTTPTransport_ServerCertVerify(t *testing.T) {
	addr, _ := newKMIPHTTPSServer(t)

	_, err := kmipclient.Dial(addr, kmiphttp.WithTransport("/"))
	require.Error(t, err)

	var ce *tls.CertificateVerificationError
	var ue x509.UnknownAuthorityError
	require.True(t, errors.As(err, &ce) || errors.As(err, &ue),
		"expected a TLS verification error, got %T: %v", err, err)
}

// TestHTTPTransport_WithDialerUnsafe ensures that a custom DialerFunc is honored:
// the http transport dispatches its TLS dial through the user-supplied dialer
// instead of the default TLS plumbing.
func TestHTTPTransport_WithDialerUnsafe(t *testing.T) {
	addr, ca := newKMIPHTTPSServer(t)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(ca))
	tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

	var dialed atomic.Int64
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		dialed.Add(1)
		td := tls.Dialer{Config: tlsCfg}
		return td.DialContext(ctx, "tcp", addr)
	}

	client, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/"),
		kmipclient.WithDialerUnsafe(dialer),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Activate("dialer").Exec()
	require.NoError(t, err)
	require.GreaterOrEqual(t, dialed.Load(), int64(1),
		"WithDialerUnsafe must be invoked by the HTTP transport")
}

// TestHTTPTransport_CloseRejectsNewRoundTrip locks in the contract that Close
// causes subsequent RoundTrip calls to return net.ErrClosed without reaching
// the network.
func TestHTTPTransport_CloseRejectsNewRoundTrip(t *testing.T) {
	var hits atomic.Int64
	mux := kmipserver.NewBatchExecutor()
	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(
		func(_ context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
			hits.Add(1)
			return &payloads.ActivateResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
		}))
	addr, ca := newHTTPSTestServer(t, kmipserver.NewHTTPHandler(mux))

	client, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/"),
		kmipclient.WithRootCAPem(ca),
	)
	require.NoError(t, err)

	require.NoError(t, client.Close())

	beforeHits := hits.Load()
	_, err = client.Activate("after-close").Exec()
	require.ErrorIs(t, err, net.ErrClosed)
	require.Equal(t, beforeHits, hits.Load(),
		"RoundTrip after Close must short-circuit before reaching the server")

	// Idempotent: a second Close must not panic or change behavior.
	require.NoError(t, client.Close())
}

// TestHTTPTransport_ConcurrentRoundTrip exercises N parallel RoundTrips against
// the same client to verify the documented "safe for concurrent use" contract.
// The shared http.Client provides the synchronization; the transport must not
// add external locking that would serialize requests.
func TestHTTPTransport_ConcurrentRoundTrip(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(
		func(_ context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
			return &payloads.ActivateResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
		}))
	addr, ca := newHTTPSTestServer(t, kmipserver.NewHTTPHandler(mux))

	client, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/"),
		kmipclient.WithRootCAPem(ca),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	const goroutines = 16
	const perGoroutine = 8

	var wg sync.WaitGroup
	errs := make(chan error, goroutines*perGoroutine)
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range perGoroutine {
				uid := strconv.Itoa(g*perGoroutine + i)
				resp, err := client.Activate(uid).Exec()
				if err != nil {
					errs <- err
					return
				}
				if resp.UniqueIdentifier != uid {
					errs <- errors.New("uid mismatch: got " + resp.UniqueIdentifier + " want " + uid)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent roundtrip: %v", err)
	}
}

// TestHTTPTransport_ContextCancelMidRequest ensures that cancelling the request
// context unblocks an in-flight RoundTrip on the client side. Note that
// HTTP/1.1 does not reliably propagate client cancellation to the server's
// r.Context(); the test therefore releases the handler explicitly once the
// client side has been verified, so cleanup does not block on the handler.
func TestHTTPTransport_ContextCancelMidRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})

	addr, ca := newHTTPSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-started:
		default:
			close(started)
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))

	client, err := kmipclient.Dial(addr,
		kmiphttp.WithTransport("/"),
		kmipclient.WithRootCAPem(ca),
		// Skip DiscoverVersions so Dial itself doesn't hit the slow handler.
		kmipclient.EnforceVersion(kmip.V1_4),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client.Close()
		// Drain the handler before httptest.Server.Close runs; client cancel
		// does not necessarily propagate to r.Context() over HTTP/1.1, so
		// without this the cleanup blocks for 5s waiting on an active conn.
		select {
		case <-release:
		default:
			close(release)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.Activate("cancel-me").ExecContext(ctx)
		done <- err
	}()

	<-started
	cancel()

	select {
	case err := <-done:
		require.Error(t, err, "expected an error after cancel")
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("RoundTrip did not return within 2s after context cancel")
	}

	// Release the handler so httptest.Server.Close doesn't have to wait on it.
	close(release)
}
