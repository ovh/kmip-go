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

// newConn initializes and returns a new conn instance for handling KMIP protocol communication.
// It sets up the internal TTLV stream with a maximum size of 1 MB, initializes transmission and
// reception channels, and starts the read and write loops in separate goroutines. The provided
// context is wrapped to support cancellation with cause, and the given logger is used for logging.
// The function is intended to be used for each new network connection.
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

// Close terminates the connection by invoking the terminate method with net.ErrClosed.
// It is intended to close the underlying resources associated with the connection.
// Note: Goroutines associated with the connection are not currently awaited before closure.
func (c *conn) Close() error {
	return c.terminate(net.ErrClosed)
	// TODO: Wait exit of goroutines
}

// terminate gracefully shuts down the connection by performing the following steps:
// 1. Atomically marks the connection as closed. If already closed, it returns immediately.
// 2. Logs the termination event for debugging purposes.
// 3. Cancels the server context with the provided error.
// 4. Closes the transaction channel if it exists and hasn't already been closed.
// 5. Closes the underlying stream associated with the connection.
// It returns any error encountered while closing the stream.
func (c *conn) terminate(err error) error {
	if c.closed.Swap(true) {
		// Server is already closed. Nothing to do
		return nil
	}
	c.logger.Debug("Terminating connection")
	c.cancel(err) // Cancel the server context
	if tx := c.tx.Swap(chan txMsg(nil)); tx != nil && tx != chan txMsg(nil) {
		close(tx.(chan txMsg))
	}
	return c.stream.Close() // Close the connection
}

// checkAvailable checks if the connection is still available for use.
// It returns net.ErrClosed if the connection has been closed, or the context's
// cancellation cause if the context has been canceled. If neither condition is met,
// it returns nil, indicating the connection is available.
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

// readloop continuously reads messages from the connection stream and processes them.
// It listens for incoming messages, handles errors appropriately, and sends received messages
// or errors to the rx channel. If a terminal error occurs or the context is done, it terminates
// the loop and closes the rx channel. This function is intended to run as a goroutine.
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

// writeloop continuously listens for outgoing messages on the tx channel and sends them over the stream.
// It handles errors during sending, propagates them back to the sender via the req.err channel, and terminates
// the connection on failure. The loop exits when the connection is closed or the context is done.
// Any remaining messages in the tx channel are not drained when the context is canceled (see TODO).
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

// send sends a KMIP ResponseMessage to the client over the connection.
// It first checks if the connection is available. If so, it sends the message
// along with an error channel to the transaction channel. It waits for either
// an error response from the transaction handler or for the connection context
// to be done (e.g., due to cancellation or timeout). If the context is done,
// it terminates the connection and returns the context's cause as the error.
//
// Parameters:
//   - msg: Pointer to the KMIP ResponseMessage to be sent.
//
// Returns:
//   - error: An error if sending fails, the connection is unavailable, or the context is done.
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

// recv waits for a message from the connection's receive channel or until the provided context is done.
// It returns a pointer to a kmip.RequestMessage and an error, if any occurred.
// If the receive channel is closed, io.ErrClosedPipe is returned.
// If the context or the connection's internal context is canceled, the connection is terminated and the corresponding error is returned.
//
// Parameters:
//   - ctx: The context to control cancellation and timeout.
//
// Returns:
//   - *kmip.RequestMessage: The received request message, or nil if an error occurred.
//   - error: An error if the context is canceled, the connection is closed, or another issue occurs.
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
