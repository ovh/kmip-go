package kmipserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"
)

type recvMsg struct {
	msg any
}

func (msg *recvMsg) DecodeTTLV(d *ttlv.Decoder) error {
	switch d.Tag() {
	case kmip.TagRequestMessage:
		msg.msg = new(kmip.RequestMessage)
	case kmip.TagResponseMessage:
		msg.msg = new(kmip.ResponseMessage)
	default:
		return ttlv.Errorf("Unexpected tag %q", ttlv.TagString(d.Tag()))
	}
	return d.Any(&msg.msg)
}

type rxMsg struct {
	msg *kmip.RequestMessage
	// Encoding errors
	err error
}

type txMsg struct {
	msg *kmip.ResponseMessage
	err chan<- error
}

type conn struct {
	stream ttlv.Stream
	rx     chan rxMsg
	tx     atomic.Value
	ctx    context.Context
	cancel func(error)
	closed atomic.Bool
	logger *slog.Logger
}

func newConn(netCon net.Conn, ctx context.Context, logger *slog.Logger) *conn {
	ctx, cancel := context.WithCancelCause(ctx)
	c := &conn{
		//TODO: Make max size configurable
		stream: ttlv.NewStream(netCon, 1*1024*1024), // Max Size is 1 MB
		tx:     atomic.Value{},
		rx:     make(chan rxMsg),
		ctx:    ctx,
		cancel: cancel,
		closed: atomic.Bool{},
		logger: logger,
	}
	c.tx.Store(make(chan txMsg))
	go c.readloop()
	go c.writeloop()
	return c
}

func (c *conn) Close() error {
	return c.terminate(net.ErrClosed)
	// TODO: Wait exit of goroutines
}

func (c *conn) terminate(err error) error {
	if c.closed.Swap(true) {
		// Server is already closed. Nothing to do
		return nil
	}
	c.logger.Debug("Terminating connection")
	c.cancel(err) // Cancel the server context
	if tx := c.tx.Swap((chan txMsg)(nil)); tx != nil && tx != (chan txMsg)(nil) {
		close(tx.(chan txMsg))
	}
	return c.stream.Close() // Close the connection
}

func (c *conn) checkAvailable() error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	select {
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	default:
		return nil
	}
}

func (c *conn) readloop() {
	defer c.logger.Debug("Exittig readloop")
	defer close(c.rx)
	for !c.closed.Load() {
		msg := recvMsg{}
		err := c.stream.Recv(&msg)
		if err != nil && !ttlv.IsErrEncoding(err) {
			c.logger.Debug("read fail:", "err", err)
			if errors.Is(err, net.ErrClosed) {
				err = io.ErrClosedPipe
			}
			// Close the client
			_ = c.terminate(err)
			return
		}
		m, ok := msg.msg.(*kmip.RequestMessage)
		if err == nil && !ok {
			// Ignore client originated responses (for now)
			continue
		}

		resp := rxMsg{
			msg: m,
			err: err,
		}

		select {
		case c.rx <- resp:
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *conn) writeloop() {
	defer c.logger.Debug("Exittig writeloop")
	tx := c.tx.Load().(chan txMsg)
	for !c.closed.Load() {
		select {
		case req, ok := <-tx:
			if !ok {
				return
			}
			if err := c.stream.Send(req.msg); err != nil {
				c.logger.Debug("write fail:", "err", err)
				if errors.Is(err, net.ErrClosed) {
					err = io.ErrClosedPipe
				}
				req.err <- err
				close(req.err)
				// Close the client
				_ = c.terminate(err)
				return
			}
			close(req.err)
		case <-c.ctx.Done():
			// TODO: Drain tx
			return
		}
	}
}

func (c *conn) send(msg *kmip.ResponseMessage) error {
	if err := c.checkAvailable(); err != nil {
		return err
	}
	tx := c.tx.Load().(chan txMsg)
	errCh := make(chan error)
	select {
	case tx <- txMsg{msg: msg, err: errCh}:
		select {
		case err := <-errCh:
			return err
		case <-c.ctx.Done():
			// Close client
			_ = c.terminate(io.ErrClosedPipe)
			return context.Cause(c.ctx)
		}
	case <-c.ctx.Done():
		close(errCh)
		_ = c.terminate(io.ErrClosedPipe)
		return context.Cause(c.ctx)
	}
}

func (c *conn) recv(ctx context.Context) (*kmip.RequestMessage, error) {
	if err := c.checkAvailable(); err != nil {
		return nil, err
	}
	select {
	case resp, ok := <-c.rx:
		if !ok {
			return nil, io.ErrClosedPipe
		}
		return resp.msg, resp.err
	case <-ctx.Done():
		_ = c.terminate(io.ErrClosedPipe)
		return nil, context.Cause(ctx)
	case <-c.ctx.Done():
		// Close the client to cancel the operation on server
		_ = c.terminate(io.ErrClosedPipe)
		return nil, context.Cause(c.ctx)
	}
}
