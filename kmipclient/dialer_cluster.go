package kmipclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/ovh/kmip-go/ttlv"
)

type connectionEntry struct {
	url       string
	lastError time.Time
	// mu protects concurrent access to lastError only
	mu sync.Mutex
}

func WithRetryTimeout(retryTimeout time.Duration) Option {
	return func(o *opts) error {
		o.retryTimeout = &retryTimeout
		return nil
	}
}

func DialCluster(addrs []string, options ...Option) (*Client, error) {
	return DialClusterContext(context.Background(), addrs, options...)
}

func DialClusterContext(ctx context.Context, addrs []string, options ...Option) (*Client, error) {
	if len(addrs) == 0 {
		return nil, errors.New("at least one server address is required")
	}

	opts := opts{}
	if err := applyOptions(&opts, options); err != nil {
		return nil, err
	}

	// Custom transports have no cluster failover semantics; DialCluster relies
	// on the stream transport's per-address dial loop.
	if opts.transportBuilder != nil {
		return nil, errors.New("custom transports are not supported with DialCluster; use Dial against a single endpoint instead")
	}

	if len(opts.supportedVersions) == 0 {
		opts.supportedVersions = append(opts.supportedVersions, supportedVersions...)
	}
	if opts.maxMessageSize == 0 {
		opts.maxMessageSize = ttlv.DefaultMaxMessageSize
	}

	tlsCfg, err := opts.tlsConfig()
	if err != nil {
		return nil, err
	}

	servers := make([]*connectionEntry, 0, len(addrs))
	for _, url := range addrs {
		slog.Info("Add server to pool", "url", url)
		servers = append(servers, &connectionEntry{
			url: url,
		})
	}

	if opts.retryTimeout == nil {
		timeout := 5 * time.Second
		opts.retryTimeout = &timeout
	}

	dialOne := perAddrStreamDialer(opts.dialer, tlsCfg)

	dialer := func(ctx context.Context) (net.Conn, error) {
		for _, s := range servers {
			// TOCTOU: the lastError snapshot is released before DialContext and
			// re-acquired only for the error write. Two goroutines can therefore
			// dial the same server concurrently. This is intentional, holding the
			// lock across I/O would serialize reconnections across cloned clients,
			// and benign because the write is an idempotent time.Now() and the
			// skip check is advisory.
			s.mu.Lock()
			if time.Since(s.lastError) < *opts.retryTimeout {
				lastErr := s.lastError
				s.mu.Unlock()
				slog.Info("Skipping server because of recent last error", "url", s.url, "last_error", lastErr)
				continue
			}
			s.mu.Unlock()

			conn, err := dialOne(ctx, s.url)
			if err != nil {
				now := time.Now()
				s.mu.Lock()
				s.lastError = now
				s.mu.Unlock()
				slog.Warn("Failed to dial server", "url", s.url, "error", err)
			} else {
				return conn, nil
			}
		}

		// All servers have had an error within retryTimeout
		// Call the first server to check if it went back up
		first := servers[0]
		conn, err := dialOne(ctx, first.url)
		first.mu.Lock()

		if err == nil {
			// reset lastError since we had a success
			first.lastError = time.Time{}
			first.mu.Unlock()
			return conn, nil
		}
		first.lastError = time.Now()
		first.mu.Unlock()
		slog.Warn("Failed to dial server", "url", first.url, "error", err)
		return nil, fmt.Errorf("failed to connect to servers in the connection pool (last attempt %q): %w", first.url, err)
	}

	tr, err := newStreamTransport(ctx, dialer, opts.maxMessageSize)
	if err != nil {
		return nil, err
	}

	c := &Client{
		tr:                tr,
		supportedVersions: opts.supportedVersions,
		version:           opts.enforceVersion,
		middlewares:       opts.middlewares,
		addr:              addrs[0],
	}

	// Negotiate protocol version
	if err := c.negotiateVersion(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}

	return c, nil
}
