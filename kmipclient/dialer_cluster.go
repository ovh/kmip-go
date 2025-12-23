package kmipclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

type connectionEntry struct {
	url       string
	lastError time.Time
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
	opts := opts{}
	for _, o := range options {
		if err := o(&opts); err != nil {
			return nil, err
		}
	}

	if len(opts.supportedVersions) == 0 {
		opts.supportedVersions = append(opts.supportedVersions, supportedVersions...)
	}

	tlsCfg, err := opts.tlsConfig()
	if err != nil {
		return nil, err
	}

	servers := make([]connectionEntry, 0, len(addrs))
	for _, url := range addrs {
		slog.Info("Add server to pool", "url", url)
		servers = append(servers, connectionEntry{
			url: url,
		})
	}

	if opts.retryTimeout == nil {
		*opts.retryTimeout = 5 * time.Second
	}

	dialer := opts.dialer
	if dialer == nil {
		dialer = func(ctx context.Context) (net.Conn, error) {
			tlsDialer := tls.Dialer{
				Config: tlsCfg,
			}
			for _, s := range servers {
				if !time.Now().After(s.lastError.Add(*opts.retryTimeout)) {
					slog.Info("Skipping server because of recent last error", "url", s.url, "last error", s.lastError)
					continue
				}

				conn, err := tlsDialer.DialContext(ctx, "tcp", s.url)
				if err != nil {
					s.lastError = time.Now()
					slog.Warn("TLS session initialization failed", "url", s.url, "error", err)
				} else {
					return conn, nil
				}
			}

			// All server had an error since retryTimeout
			// Call the first server to check if it went back up
			conn, err := tlsDialer.DialContext(ctx, "tcp", servers[0].url)
			if err == nil {
				// reset lastError since we had a success
				servers[0].lastError = time.Date(0, 0, 0, 0, 0, 0, 0, nil)
				return conn, nil
			}
			servers[0].lastError = time.Now()
			slog.Warn("TLS session initialization failed", "url", servers[0].url, "error", err)
			return nil, fmt.Errorf("Failed to connect to servers in the connection pool")
		}
	}

	stream, err := dialer(ctx)
	if err != nil {
		return nil, err
	}

	c := &Client{
		lock:              new(sync.Mutex),
		conn:              newConn(stream),
		dialer:            dialer,
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
