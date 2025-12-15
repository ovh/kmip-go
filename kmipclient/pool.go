package kmipclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"time"
)

type connectionEntry struct {
	url       string
	lastError time.Time
}

func WithDialerPool(retryTimeout time.Duration, addr ...string) Option {
	servers := make([]connectionEntry, 0, len(addr))
	for _, url := range addr {
		slog.Info("Add server to pool", "url", url)
		servers = append(servers, connectionEntry{
			url: url,
		})
	}

	dialerFn := func(ctx context.Context, addr string, tlsCfg *tls.Config) (net.Conn, error) {
		tlsDialer := tls.Dialer{
			Config: tlsCfg,
		}
		for _, s := range servers {
			if !time.Now().After(s.lastError.Add(retryTimeout)) {
				slog.Info("Skipping server because of recent last error", "addr", addr, "url", s.url, "last error", s.lastError)
				continue
			}

			conn, err := tlsDialer.DialContext(ctx, "tcp", s.url)
			if err != nil {
				s.lastError = time.Now()
				slog.Warn("TLS session initialization failed", "addr", addr, "url", s.url, "error", err)
			} else {
				return conn, nil
			}
		}

		return nil, fmt.Errorf("Failed to connect to servers in the connection pool")
	}

	return WithDialerUnsafe(dialerFn)
}
