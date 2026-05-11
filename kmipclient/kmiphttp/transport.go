// Package kmiphttp provides an HTTP(S) transport for [kmipclient]. It is an
// optional sub-package: importing kmipclient alone does not pull in net/http.
//
// Typical usage:
//
//	client, err := kmipclient.Dial("kms.example.com:5696",
//		kmiphttp.WithTransport("/kmip"),
//		kmipclient.WithRootCAFile("ca.crt"),
//	)
//
// HTTPS is unconditional; see [WithTransport] for the details.
package kmiphttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/ttlv"
)

const (
	errorBodyExcerptMax = 4 * 1024
	// errorBodyDrainCap bounds how much extra error-body we read after the
	// excerpt so net/http can recycle the keep-alive connection. Without a cap a
	// hostile server could force us to swallow an arbitrarily large error body.
	errorBodyDrainCap = 64 * 1024
)

// WireFormat selects the on-the-wire encoding used by the HTTP transport when
// exchanging KMIP messages with the server.
type WireFormat int

const (
	// WireTTLV uses application/octet-stream and the TTLV binary encoding (default).
	WireTTLV WireFormat = iota
	// WireXML uses text/xml and the KMIP XML encoding.
	WireXML
	// WireJSON uses application/json and the KMIP JSON encoding.
	WireJSON
)

func (f WireFormat) String() string {
	switch f {
	case WireTTLV:
		return "TTLV"
	case WireXML:
		return "XML"
	case WireJSON:
		return "JSON"
	default:
		return fmt.Sprintf("WireFormat(%d)", int(f))
	}
}

// Error is returned by the HTTP transport when the server replies with a
// non-2xx status code. Body holds an excerpt of the response body (capped at
// errorBodyExcerptMax bytes) for diagnostic purposes.
type Error struct {
	StatusCode int
	Status     string
	Body       []byte
}

func (e *Error) Error() string {
	if len(e.Body) == 0 {
		return fmt.Sprintf("kmip http: %s", e.Status)
	}
	// strconv.Quote so binary/non-printable bodies don't bleed raw bytes into logs.
	return fmt.Sprintf("kmip http: %s: %s", e.Status, strconv.Quote(string(e.Body)))
}

// Option configures the HTTP transport. See [WithTransport].
type Option func(*config) error

// wireCodec bundles the content-type and (un)marshal functions for a single
// WireFormat. Resolved eagerly at option-application time so the runtime path
// never has to map a WireFormat to a codec (and never silently falls back to
// TTLV on an unknown value).
type wireCodec struct {
	contentType string
	marshal     func(any) []byte
	unmarshal   func([]byte, any) error
}

var (
	codecTTLV = wireCodec{"application/octet-stream", ttlv.MarshalTTLV, ttlv.UnmarshalTTLV}
	codecXML  = wireCodec{"text/xml", ttlv.MarshalXML, ttlv.UnmarshalXML}
	codecJSON = wireCodec{"application/json", ttlv.MarshalJSON, ttlv.UnmarshalJSON}
)

type config struct {
	path       string
	codec      wireCodec
	client     *http.Client
	header     http.Header
	rtWrappers []func(http.RoundTripper) http.RoundTripper
}

// WithTransport selects the HTTP transport for the client. KMIP requests will
// be POSTed to https://<addr><path>, where <addr> is the address passed to
// [kmipclient.Dial] and <path> is the argument given here.
//
// HTTPS is unconditional: the URL scheme is hard-coded to "https://" and there
// is no opt-in for plaintext HTTP. If you need to point a test at a non-TLS
// server, supply a custom http.Client via [WithClient] whose RoundTripper
// rewrites or otherwise routes the request.
//
// addr must be a bare host:port (e.g. "kms.example.com:5696"); supplying a
// scheme — for example "https://host:5696" — is rejected at Dial time, since
// concatenating it onto the implicit "https://" produces a confusing
// https://https://… URL.
//
// path must start with "/". An empty string is normalized to "/". Paths may
// not contain a fragment or a query string — both are almost certainly
// copy-paste mistakes (fragments are silently stripped from the request
// line; KMIP-over-HTTPS has no defined query semantics).
//
// TLS settings configured via the standard kmipclient TLS options
// ([kmipclient.WithRootCAFile], [kmipclient.WithRootCAPem],
// [kmipclient.WithClientCertFiles], [kmipclient.WithClientCertPEM],
// [kmipclient.WithTlsConfig], [kmipclient.WithTlsCipherSuites],
// [kmipclient.WithServerName]) are automatically applied to the underlying
// http.Transport.
//
// If [kmipclient.WithDialerUnsafe] is set, the provided
// [kmipclient.DialerFunc] is used to establish the (already-secured)
// connection and the standard TLS configuration is bypassed — the dialer is
// responsible for negotiating TLS itself.
//
// Use [WithClient] to fully override the *http.Client. WithClient is mutually
// exclusive with [kmipclient.WithDialerUnsafe] and with the standard TLS
// options listed above; configure TLS and dialing on the supplied client
// instead.
//
// Errors from kmiphttp options aggregate among themselves (so a misconfigured
// path, header key, and wire format are reported together), but they surface
// only after kmipclient.Option errors have cleared — a misconfigured kmipclient
// option short-circuits Dial before the transport builder runs, so the kmiphttp
// errors won't show up until that's fixed.
func WithTransport(path string, opts ...Option) kmipclient.Option {
	// Build per-Dial so concurrent Dials reusing the same Option value don't
	// share the config (and its header map).
	return kmipclient.WithTransportBuilder(func(_ context.Context, info kmipclient.DialInfo) (kmipclient.Transport, error) {
		cfg, err := newConfig(path, opts)
		if err != nil {
			return nil, err
		}
		return build(cfg, info)
	})
}

// newConfig normalizes path and applies every option, surfacing all errors at
// once via errors.Join.
func newConfig(path string, opts []Option) (*config, error) {
	var errs []error
	if path == "" {
		path = "/"
	}
	// All three checks run independently so a single Dial reports every
	// problem with the path. "/" passes all of them, so the empty-string
	// normalization above is safe.
	if !strings.HasPrefix(path, "/") {
		errs = append(errs, fmt.Errorf("kmip http: invalid path %q: must start with '/'", path))
	}
	// net/http silently strips fragments from the request line, which would
	// mask a copy-paste mistake like "/kmip#frag".
	if strings.Contains(path, "#") {
		errs = append(errs, fmt.Errorf("kmip http: invalid path %q: must not contain a fragment", path))
	}
	// KMIP-over-HTTPS has no query semantics; query strings DO survive on the
	// wire (unlike fragments), so a path like "/kmip?foo=bar" would silently
	// send the query string on every POST. Reject at build time.
	if strings.Contains(path, "?") {
		errs = append(errs, fmt.Errorf("kmip http: invalid path %q: must not contain a query string", path))
	}
	cfg := &config{
		path:   path,
		codec:  codecTTLV,
		header: http.Header{},
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return cfg, nil
}

// WithWireFormat sets the on-the-wire encoding (TTLV binary, XML, or JSON).
// Default is [WireTTLV]. The codec is resolved here, so an invalid value
// fails at option-application time rather than silently degrading at runtime.
func WithWireFormat(f WireFormat) Option {
	return func(c *config) error {
		switch f {
		case WireTTLV:
			c.codec = codecTTLV
		case WireXML:
			c.codec = codecXML
		case WireJSON:
			c.codec = codecJSON
		default:
			return fmt.Errorf("kmip http: invalid wire format %d", f)
		}
		return nil
	}
}

// WithClient overrides the http.Client used by the HTTP transport. When set,
// the supplied client is used as-is, so the standard kmipclient TLS options
// ([kmipclient.WithRootCAFile], [kmipclient.WithRootCAPem],
// [kmipclient.WithClientCertFiles], [kmipclient.WithClientCertPEM],
// [kmipclient.WithTlsConfig], [kmipclient.WithTlsCipherSuites],
// [kmipclient.WithServerName]) and [kmipclient.WithDialerUnsafe] would be
// silently ignored — combining any of them with WithClient therefore returns
// an error at Dial time. Configure TLS, dialing, and transport-level
// pooling/timeouts on the supplied client instead.
//
// The bare-host:port shape check on addr still applies: even if the supplied
// client's RoundTripper rewrites the request URL, addr must not include a
// "scheme://" prefix, since the transport composes the request URL as
// "https://<addr><path>" before invoking the client.
//
// If you only need to wrap the kmipclient-built RoundTripper (for tracing,
// request signing, retries, …) while keeping kmipclient's TLS plumbing, prefer
// [WrapRoundTripper] over a fully custom client.
//
// The supplied client's CheckRedirect policy is preserved as-is; the transport
// does not override it. The kmipclient-built client refuses to follow 3xx
// responses by default, so callers replacing it with WithClient who want the
// same behavior must set [http.ErrUseLastResponse] (or an equivalent) on
// their own client.
func WithClient(client *http.Client) Option {
	return func(c *config) error {
		if client == nil {
			return errors.New("kmip http: nil http.Client")
		}
		c.client = client
		return nil
	}
}

// WrapRoundTripper installs a wrapper around the http.RoundTripper used by
// the HTTP transport. The supplied function receives the kmipclient-built
// RoundTripper (with auto-configured TLS, dialer, and connection pooling) and
// returns a wrapped RoundTripper. This is the recommended way to add tracing,
// request signing, retries, or any other cross-cutting HTTP concern without
// giving up the TLS configuration that the standard kmipclient TLS options
// provide.
//
// Multiple wrappers may be registered by calling WrapRoundTripper more than
// once. They are applied so that the first wrapper registered is the
// outermost: it sees the request first and the response last, mirroring the
// convention used by most Go HTTP middleware libraries.
//
// Mutually exclusive with [WithClient].
func WrapRoundTripper(wrap func(http.RoundTripper) http.RoundTripper) Option {
	return func(c *config) error {
		if wrap == nil {
			return errors.New("kmip http: nil RoundTripper wrapper")
		}
		c.rtWrappers = append(c.rtWrappers, wrap)
		return nil
	}
}

// WithHeader appends an extra header that will be sent on every KMIP request.
// Reserved headers are rejected because the transport sets them itself, or
// because net/http manages them via dedicated fields and would silently drop
// a header-map entry:
//
//   - Content-Type, Accept: set by the transport per wire codec.
//   - Content-Length: net/http writes it from req.ContentLength; a header-map
//     entry is excluded by reqWriteExcludeHeader.
//   - Host: net/http writes it from req.Host; a header-map entry is silently
//     dropped on outbound requests.
//   - Transfer-Encoding, Trailer: managed by net/http (chunked framing,
//     trailing headers); also excluded by reqWriteExcludeHeader.
//
// User-Agent is intentionally NOT reserved: net/http excludes it from generic
// header serialization but still emits it from req.Header["User-Agent"] as a
// dedicated line, so a user-supplied value overrides the default.
func WithHeader(key, value string) Option {
	return func(c *config) error {
		if key == "" {
			return errors.New("kmip http: empty header key")
		}
		switch http.CanonicalHeaderKey(key) {
		case "Content-Type", "Accept", "Content-Length", "Host",
			"Transfer-Encoding", "Trailer":
			return fmt.Errorf("kmip http: header %q is reserved and cannot be set via WithHeader", key)
		}
		c.header.Add(key, value)
		return nil
	}
}

// noFollowRedirect causes [http.Client] to surface a 3xx response as-is,
// which our non-2xx branch then turns into a [*Error]. KMIP-over-HTTPS has no
// redirect semantics in the spec; following a redirect could send credentials
// or request bodies to an unintended host.
func noFollowRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// build returns a [transport] whose *http.Client is shared with any future
// Clone, so cloned Clients reuse the underlying connection pool.
func build(cfg *config, info kmipclient.DialInfo) (kmipclient.Transport, error) {
	if err := validateAddr(info.Addr); err != nil {
		return nil, err
	}
	reqURL, err := buildRequestURL(info.Addr, cfg.path)
	if err != nil {
		return nil, err
	}
	if cfg.client != nil {
		if info.Dialer != nil {
			return nil, errors.New("kmip http: WithClient and WithDialerUnsafe are mutually exclusive; configure the dialer on the supplied http.Client instead")
		}
		if info.TLSConfigured {
			return nil, errors.New("kmip http: WithClient is mutually exclusive with the standard TLS options (WithRootCAFile/Pem, WithClientCertFiles/PEM, WithTlsConfig, WithTlsCipherSuites, WithServerName); configure TLS on the supplied http.Client instead")
		}
		if len(cfg.rtWrappers) > 0 {
			return nil, errors.New("kmip http: WrapRoundTripper and WithClient are mutually exclusive; wrap the supplied client's Transport instead")
		}
	}

	client := cfg.client
	if client == nil {
		var tr *http.Transport
		if base, ok := http.DefaultTransport.(*http.Transport); ok {
			tr = base.Clone()
		} else {
			tr = &http.Transport{}
		}
		if info.Dialer != nil {
			tr.TLSClientConfig = nil
			dialer := info.Dialer
			tr.DialTLSContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer(ctx, addr)
			}
		} else {
			tr.TLSClientConfig = info.TLSConfig
		}
		// Apply wrappers in reverse so the first registered ends up outermost
		// (caller-side first), matching the convention of most Go HTTP
		// middleware libraries.
		var rt http.RoundTripper = tr
		for i := len(cfg.rtWrappers) - 1; i >= 0; i-- {
			rt = cfg.rtWrappers[i](rt)
			if rt == nil {
				return nil, fmt.Errorf("kmip http: WrapRoundTripper wrapper #%d returned nil", i)
			}
		}
		client = &http.Client{
			Transport:     rt,
			CheckRedirect: noFollowRedirect,
		}
	}

	return &transport{
		client:     client,
		url:        reqURL,
		codec:      cfg.codec,
		maxMsgSize: info.MaxMessageSize,
		header:     cfg.header,
	}, nil
}

// buildRequestURL composes "https://<addr><path>" and parses it once so
// malformed paths (e.g. control characters) fail at Dial time instead of at
// the first RoundTrip. Fragment/query rejection lives in newConfig so it
// aggregates with other path/option errors (url.Parse accepts both).
//
// We deliberately return the raw concatenation rather than parsed.String():
// newConfig has already validated the path byte-for-byte, and round-tripping
// through *url.URL could re-encode characters in ways the caller didn't
// write. url.Parse here is used purely as a validator.
func buildRequestURL(addr, path string) (string, error) {
	raw := "https://" + addr + path
	if _, err := url.Parse(raw); err != nil {
		// *url.Error already includes the URL in its message.
		return "", fmt.Errorf("kmip http: %w", err)
	}
	return raw, nil
}

// validateAddr rejects addresses that don't look like a bare host:port, most
// notably anything with a "scheme://" prefix — concatenating that with
// "https://" produces a confusing https://https://… URL whose failure mode is
// hard to diagnose. We use net.SplitHostPort for the host:port shape check,
// which also handles bracketed IPv6 literals correctly.
func validateAddr(addr string) error {
	if strings.Contains(addr, "://") {
		return fmt.Errorf("kmip http: addr %q must be a bare host:port (no scheme); HTTPS is implied", addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("kmip http: invalid addr %q: %w", addr, err)
	}
	if host == "" || port == "" {
		return fmt.Errorf("kmip http: invalid addr %q: host and port are required", addr)
	}
	return nil
}

// transport implements [kmipclient.Transport] over HTTP(S). The shared
// *http.Client is concurrent-safe, so callers can issue parallel requests
// without external serialization.
type transport struct {
	client     *http.Client
	url        string
	codec      wireCodec
	maxMsgSize int
	header     http.Header
	closed     atomic.Bool
}

func (h *transport) RoundTrip(ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
	if h.closed.Load() {
		return nil, net.ErrClosed
	}
	body := h.codec.marshal(msg)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	// Clone (not shallow copy): downstream RoundTrippers may mutate header
	// slices via append, which would race across concurrent requests. When no
	// custom headers are configured, http.NewRequestWithContext has already
	// initialized req.Header.
	if len(h.header) > 0 {
		req.Header = h.header.Clone()
	}
	req.Header.Set("Content-Type", h.codec.contentType)
	req.Header.Set("Accept", h.codec.contentType)
	req.ContentLength = int64(len(body))

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// io.ReadAll returns the partial read alongside any error, so even on
		// a truncated body we surface a typed *Error: callers losing the
		// StatusCode just because the excerpt read failed would be a worse
		// diagnostic than handing them a short Body.
		bodyExcerpt, readErr := io.ReadAll(io.LimitReader(resp.Body, errorBodyExcerptMax))
		hErr := &Error{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       bodyExcerpt,
		}
		if readErr != nil {
			// Skip the drain: if the excerpt read failed, draining is unlikely
			// to succeed either, and the deferred Close() will tear down the
			// connection rather than recycle it.
			return nil, errors.Join(hErr, readErr)
		}
		// Drain bounded so net/http can recycle the keep-alive connection;
		// without a cap a giant error body would block us reading it in full.
		// If overflow remains the deferred Close() simply tears down the conn.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, errorBodyDrainCap))
		return nil, hErr
	}

	respBody, err := readBounded(resp, h.maxMsgSize)
	if err != nil {
		return nil, err
	}

	out := &kmip.ResponseMessage{}
	if err := h.codec.unmarshal(respBody, out); err != nil {
		return nil, fmt.Errorf("kmip http: decode response: %w", err)
	}
	return out, nil
}

// Close marks this transport closed; subsequent RoundTrip calls return
// net.ErrClosed. It does NOT cancel in-flight requests — callers must cancel
// their request contexts to unblock pending roundtrips. The shared
// *http.Client is intentionally not torn down so cloned clients keep pooling
// connections; pass your own client via [WithClient] if you need explicit
// lifecycle control.
func (h *transport) Close() error {
	h.closed.Store(true)
	return nil
}

// Clone returns a fresh transport that shares the underlying *http.Client
// (and therefore the connection pool) with the receiver. The clone has its
// own closed-flag, so closing one does not affect the other. The header map
// is shared too — it is treated as read-only after construction; RoundTrip
// clones it per request before mutating.
func (h *transport) Clone(_ context.Context) (kmipclient.Transport, error) {
	return &transport{
		client:     h.client,
		url:        h.url,
		codec:      h.codec,
		maxMsgSize: h.maxMsgSize,
		header:     h.header,
	}, nil
}

// readBounded reads resp.Body, capping the read at maxSize bytes when maxSize > 0
// (returning [kmipclient.ErrResponseTooLarge] if exceeded). When the server
// sends a usable Content-Length the buffer is pre-sized and read in one shot
// to avoid io.ReadAll's growth churn.
func readBounded(resp *http.Response, maxSize int) ([]byte, error) {
	if cl := resp.ContentLength; cl > 0 && (maxSize <= 0 || cl <= int64(maxSize)) {
		// resp.Body is already capped by Content-Length; ReadFull both
		// pre-sizes the slice and surfaces a short body as ErrUnexpectedEOF
		// instead of silently truncating.
		buf := make([]byte, cl)
		if _, err := io.ReadFull(resp.Body, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	var reader io.Reader = resp.Body
	if maxSize > 0 {
		reader = io.LimitReader(resp.Body, int64(maxSize)+1)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if maxSize > 0 && len(body) > maxSize {
		return nil, kmipclient.ErrResponseTooLarge
	}
	return body, nil
}
