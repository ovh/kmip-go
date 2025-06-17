package kmipclient

import (
	"context"
	"errors"
	"fmt"
	"io"
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
		return fmt.Errorf("Unexpected tag %q", ttlv.TagString(d.Tag()))
	}
	return d.Any(&msg.msg)
}

type rxMsg struct {
	msg *kmip.ResponseMessage
}

type txMsg struct {
	msg *kmip.RequestMessage
	err chan<- error
}

type conn struct {
	stream ttlv.Stream
	rx     chan rxMsg
	tx     atomic.Value
	ctx    context.Context
	cancel func(error)
	closed atomic.Bool
}

// newConn initializes and returns a new conn instance using the provided net.Conn.
// It sets up the internal context with cancellation support, initializes the transmit (tx)
// and receive (rx) channels, and starts the read and write goroutines for handling
// communication. The returned conn is ready for use in sending and receiving messages.
//
// Parameters:
//   - netCon: The underlying network connection to use for KMIP communication.
//
// Returns:
//   - *conn: A pointer to the initialized connection object.
//
// Errors:
//   - This function does not return errors directly. Errors may be encountered asynchronously
//     in the readloop or writeloop goroutines if the network connection fails.
func newConn(netCon net.Conn) *conn {
	ctx, cancel := context.WithCancelCause(context.Background())
	c := &conn{
		stream: ttlv.NewStream(netCon, -1),
		tx:     atomic.Value{},
		rx:     make(chan rxMsg),
		ctx:    ctx,
		cancel: cancel,
		closed: atomic.Bool{},
	}
	c.tx.Store(make(chan txMsg))
	go c.readloop()
	go c.writeloop()
	return c
}

// Close safely closes the connection. If the connection is already closed,
// it returns nil immediately. Otherwise, it marks the connection as closed
// and terminates it, returning any error encountered during termination.
func (c *conn) Close() error {
	if c.closed.Swap(true) {
		// Server is already closed. Nothing to do
		return nil
	}
	// println("Closing connection")
	// TODO: Wait exit of goroutines
	return c.terminate(net.ErrClosed)
}

// terminate gracefully shuts down the connection by canceling the server context,
// closing the transaction channel if it exists, and closing the underlying stream.
// It accepts an error parameter to provide context for the cancellation.
// Returns any error encountered while closing the stream.
func (c *conn) terminate(err error) error {
	c.cancel(err) // Cancel the server context
	if tx := c.tx.Swap(chan txMsg(nil)); tx != nil && tx != chan txMsg(nil) {
		close(tx.(chan txMsg))
	}
	return c.stream.Close() // Close the connection
}

// checkAvailable checks if the connection is available for use.
// It returns net.ErrClosed if the connection has been closed.
// If the provided context or the connection's internal context is done,
// it returns the corresponding context error.
// Otherwise, it returns nil indicating the connection is available.
func (c *conn) checkAvailable(ctx context.Context) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	default:
		return nil
	}
}

// readloop continuously reads messages from the underlying stream and sends them to the rx channel.
// It listens for incoming messages until the connection is closed or the context is done.
// If a message is received and is of type *kmip.ResponseMessage, it is forwarded to the rx channel.
// If an error occurs during reading, the connection is terminated and the loop exits.
// The rx channel is closed when the loop exits.
func (c *conn) readloop() {
	// defer println("Exittig readloop")
	defer close(c.rx)
	for !c.closed.Load() {
		msg := recvMsg{}
		resp := rxMsg{}
		if err := c.stream.Recv(&msg); err != nil {
			// println("read fail:", resp.err.Error())
			if errors.Is(err, net.ErrClosed) {
				err = io.ErrClosedPipe
			}
			// Close the client
			_ = c.terminate(err)
			return
		}
		m, ok := msg.msg.(*kmip.ResponseMessage)
		if !ok {
			// Ignore server originated requests (for now)
			continue
		}
		resp.msg = m

		select {
		case c.rx <- resp:
		case <-c.ctx.Done():
			return
		}
	}
}

// writeloop continuously reads messages from the transmission channel (tx) and sends them over the stream.
// It handles errors during sending, propagates them back to the requester, and terminates the connection if necessary.
// The loop exits if the connection is closed, the context is done, or the transmission channel is closed.
func (c *conn) writeloop() {
	// defer println("Exittig writeloop")
	tx := c.tx.Load().(chan txMsg)
	for !c.closed.Load() {
		select {
		case req, ok := <-tx:
			if !ok {
				return
			}
			if err := c.stream.Send(req.msg); err != nil {
				// println("write fail:", err.Error())
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

// send sends a KMIP request message over the connection, handling context cancellation and connection availability.
//
// It first checks if the connection is available. If not, it returns the corresponding error.
// The request message is sent asynchronously via a channel, and the function waits for either:
//   - an error response from the handler,
//   - the connection context being canceled (indicating the client is closed), or
//   - the provided context being canceled (indicating the request should be aborted).
//
// If the provided context is canceled after the message is sent, the client is terminated to prevent further use.
// The function ensures proper error propagation and resource cleanup in all cases.
//
// Parameters:
//   - ctx - The context for controlling cancellation and timeout of the send operation.
//   - msg - The KMIP request message to be sent.
//
// Returns:
//   - An error if the connection is unavailable, the send operation fails, or the context is canceled.
func (c *conn) send(ctx context.Context, msg *kmip.RequestMessage) error {
	if err := c.checkAvailable(ctx); err != nil {
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
			// No need to close the client as c.ctx is canceled only when client is closed
			return context.Cause(c.ctx)
		case <-ctx.Done():
			// Close client as the request may have been sent already
			_ = c.terminate(io.ErrClosedPipe)
			return ctx.Err()
		}
	case <-c.ctx.Done():
		close(errCh)
		// No need to close the client as c.ctx is canceled only when client is closed
		return context.Cause(c.ctx)
	case <-ctx.Done():
		close(errCh)
		// No need to close the client as the request has not been sent yet
		return ctx.Err()
	}
}

// recv waits for a response message from the connection's receive channel or until the provided context is done.
// It returns the received *kmip.ResponseMessage or an error if the context is canceled, the connection is closed,
// or if there is an issue with the connection's availability.
//
// Parameters:
//   - ctx: The context to control cancellation and timeout.
//
// Returns:
//   - *kmip.ResponseMessage: The received response message, or nil if an error occurred.
//   - error: An error if the context is canceled, the connection is closed, or another issue occurs.
func (c *conn) recv(ctx context.Context) (*kmip.ResponseMessage, error) {
	if err := c.checkAvailable(ctx); err != nil {
		return nil, err
	}
	select {
	case resp, ok := <-c.rx:
		if !ok {
			return nil, io.ErrClosedPipe
		}
		return resp.msg, nil
	case <-c.ctx.Done():
		// No need to close the client as c.ctx is canceled only when client is closed
		return nil, context.Cause(c.ctx)
	case <-ctx.Done():
		// Close the client to cancel the operation on server
		_ = c.terminate(io.ErrClosedPipe)
		return nil, ctx.Err()
	}
}

// roundtrip sends a KMIP request message over the connection and waits for the corresponding response.
// It first transmits the provided RequestMessage using the send method, and if successful, receives
// the ResponseMessage using the recv method. If an error occurs during sending or receiving, it returns
// the error. The context parameter allows for cancellation and timeout control of the operation.
func (c *conn) roundtrip(ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
	if err := c.send(ctx, msg); err != nil {
		return nil, err
	}
	return c.recv(ctx)
}
