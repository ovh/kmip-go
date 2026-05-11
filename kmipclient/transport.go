package kmipclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"
)

const streamReconnectAttempts = 3

// ErrResponseTooLarge is returned by both transports when the server's
// response exceeds the configured WithMaxMessageSize limit. Use errors.Is
// to detect it.
var ErrResponseTooLarge = errors.New("kmip: response exceeds max message size")

// Transport sends a KMIP request and returns the response. Implementations own
// their own (re)connection lifecycle and must be safe for concurrent use; the
// Client does not serialize RoundTrip externally.
//
// Clone returns an independent transport configured the same way as the
// receiver. The new transport has its own connection state and lifecycle, so
// closing the receiver does not affect the clone (and vice versa). Clone is
// valid on a closed transport.
type Transport interface {
	RoundTrip(ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error)
	Clone(ctx context.Context) (Transport, error)
	Close() error
}

// DialInfo carries the dial-time information a [TransportBuilder] needs to
// construct a [Transport].
//
// When adding a new TLS-affecting [Option], update [opts.hasTLSOptions] so
// TLSConfigured keeps reflecting it, and ensure [buildTransport] populates any
// new DialInfo field that exposes it to builders.
type DialInfo struct {
	// Addr is the bare host:port passed to Dial.
	Addr string
	// TLSConfig is the resolved *tls.Config built from the standard kmipclient
	// TLS options. Nil when Dialer is set, since a custom dialer takes full
	// responsibility for negotiating TLS itself. Treat as read-only — the
	// kmipclient runtime does not defensively copy it, so a builder mutating
	// it would race with any other transport sharing the same config.
	TLSConfig *tls.Config
	// Dialer is the custom dialer set via WithDialerUnsafe, or nil if none.
	Dialer DialerFunc
	// MaxMessageSize is the configured max response size in bytes (see
	// [WithMaxMessageSize]). Never zero when reaching a TransportBuilder: Dial
	// normalizes a zero/unset user value to [ttlv.DefaultMaxMessageSize] (1 MB)
	// before constructing DialInfo. A negative value disables the cap and is
	// passed through to the transport.
	MaxMessageSize int
	// TLSConfigured reports whether any of the standard kmipclient TLS options
	// were set. Used by transports that accept a fully-custom client to enforce
	// mutual exclusivity at Dial time.
	//
	// Note the asymmetry with TLSConfig: when Dialer is set, TLSConfig is
	// nil'd (the dialer takes over) but TLSConfigured still reflects whatever
	// TLS options the user supplied. A transport author deciding whether to
	// reject "TLS option + custom client" must consult TLSConfigured, not
	// TLSConfig != nil.
	TLSConfigured bool
}

// TransportBuilder constructs a [Transport] from the dial-time info. It is
// invoked once during [DialContext] when [WithTransportBuilder] is set.
type TransportBuilder func(ctx context.Context, info DialInfo) (Transport, error)

// streamTransport is the TTLV-over-TCP/TLS transport. The wire protocol is
// single-flight, so all access is serialized via mu.
//
// State machine for s.conn (under s.mu):
//   - non-nil, healthy: normal operation.
//   - nil: previous RoundTrip detected a poisoned conn (ErrMessageTooLarge) and
//     a reconnect attempt failed; the next RoundTrip will lazily redial before
//     sending. Distinguishing nil from "user closed" lets us avoid surfacing a
//     stale ErrMessageTooLarge from conn.ctx as ErrResponseTooLarge on a fresh
//     request that wasn't even oversized.
//   - non-nil, closed: user called Close(); subsequent RoundTrips return
//     net.ErrClosed without dialing.
type streamTransport struct {
	dial    func(ctx context.Context) (net.Conn, error)
	maxSize int

	mu     sync.Mutex
	conn   *conn
	closed bool
}

// reconnect dials a fresh conn and replaces s.conn. On success, the old conn
// is closed after the new dial returns. On dial failure, the old conn is also
// closed and s.conn is set to nil so the next RoundTrip lazily redials rather
// than re-using a poisoned conn whose cached terminate cause would mislead
// error reporting. Must be called with s.mu held.
func (s *streamTransport) reconnect(ctx context.Context) error {
	nc, err := s.dial(ctx)
	if err != nil {
		// Drop the old conn so the next RoundTrip starts from scratch instead
		// of inheriting any cached error state.
		if s.conn != nil {
			_ = s.conn.Close()
			s.conn = nil
		}
		return err
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.conn = newConn(nc, s.maxSize)
	return nil
}

func (s *streamTransport) RoundTrip(ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, net.ErrClosed
	}
	// Lazy redial when a previous run left us without a usable conn (failed
	// reconnect after ErrMessageTooLarge or io.EOF/io.ErrClosedPipe).
	if s.conn == nil {
		if err := s.reconnect(ctx); err != nil {
			return nil, err
		}
	}

	retry := streamReconnectAttempts
	for {
		resp, err := s.conn.roundtrip(ctx, msg)
		if err == nil {
			return resp, nil
		}
		// Oversized responses poison the conn (the readloop terminates the
		// stream on the size trip), and retrying in-loop wouldn't change the
		// response size. Eagerly reconnect so the next RoundTrip doesn't see
		// the cached terminate cause; on reconnect failure, s.conn is left
		// nil and the next call lazily redials.
		if errors.Is(err, ttlv.ErrMessageTooLarge) {
			rtErr := fmt.Errorf("%w: %w", ErrResponseTooLarge, err)
			if rerr := s.reconnect(ctx); rerr != nil {
				return nil, errors.Join(rtErr, rerr)
			}
			return nil, rtErr
		}
		if retry <= 0 || (!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe)) {
			return nil, err
		}
		if rerr := s.reconnect(ctx); rerr != nil {
			return nil, errors.Join(err, rerr)
		}
		retry--
	}
}

// Close blocks until any in-flight RoundTrip releases the mutex; cancel its
// context to abort sooner. Close is idempotent: subsequent calls return nil.
// After Close, RoundTrip returns net.ErrClosed without dialing.
func (s *streamTransport) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

// Clone dials a fresh stream transport reusing the receiver's dial closure
// and size cap. The new transport has its own conn and mutex; the receiver's
// state (including closed-ness) is not consulted.
func (s *streamTransport) Clone(ctx context.Context) (Transport, error) {
	return newStreamTransport(ctx, s.dial, s.maxSize)
}

func newStreamTransport(ctx context.Context, dial func(ctx context.Context) (net.Conn, error), maxSize int) (Transport, error) {
	s := &streamTransport{dial: dial, maxSize: maxSize}
	if err := s.reconnect(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func buildTransport(ctx context.Context, o *opts, tlsCfg *tls.Config, addr string) (Transport, error) {
	if o.transportBuilder != nil {
		// A custom dialer takes full responsibility for TLS, so the
		// kmipclient-built config would be unused — drop it.
		ctxTLS := tlsCfg
		if o.dialer != nil {
			ctxTLS = nil
		}
		return o.transportBuilder(ctx, DialInfo{
			Addr:           addr,
			TLSConfig:      ctxTLS,
			Dialer:         o.dialer,
			MaxMessageSize: o.maxMessageSize,
			TLSConfigured:  o.hasTLSOptions(),
		})
	}
	pa := perAddrStreamDialer(o.dialer, tlsCfg)
	dial := func(ctx context.Context) (net.Conn, error) { return pa(ctx, addr) }
	return newStreamTransport(ctx, dial, o.maxMessageSize)
}

// perAddrStreamDialer falls back to a standard tls.Dialer when no DialerFunc
// is set; with a DialerFunc, the caller is responsible for negotiating TLS.
func perAddrStreamDialer(d DialerFunc, tlsCfg *tls.Config) func(ctx context.Context, addr string) (net.Conn, error) {
	if d != nil {
		return d
	}
	td := &tls.Dialer{Config: tlsCfg}
	return func(ctx context.Context, addr string) (net.Conn, error) {
		return td.DialContext(ctx, "tcp", addr)
	}
}
