package kmipserver

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"
)

var ErrShutdown = errors.New("Server is shutting down")

// RequestHandler defines an interface for handling KMIP request messages.
// Implementations of this interface should process the provided RequestMessage
// and return an appropriate ResponseMessage. The context.Context parameter
// allows for request-scoped values, cancellation, and timeouts.
type RequestHandler interface {
	HandleRequest(ctx context.Context, req *kmip.RequestMessage) *kmip.ResponseMessage
}

// Server represents a KMIP server instance that manages incoming network connections,
// handles KMIP requests, and coordinates server lifecycle operations. It encapsulates
// the network listener, request handler, logging, context management for graceful
// shutdown, and a wait group for synchronizing goroutines.
type Server struct {
	listener   net.Listener
	handler    RequestHandler
	logger     *slog.Logger
	ctx        context.Context
	cancel     func()
	recvCtx    context.Context
	recvCancel func()
	wg         *sync.WaitGroup
}

// NewServer creates and returns a new Server instance using the provided net.Listener and RequestHandler.
// It panics if the handler is nil. The function initializes internal contexts for server control and
// request reception, as well as a WaitGroup for managing goroutines.
//
// Parameters:
//   - listener: The net.Listener to accept incoming connections.
//   - handler:  The RequestHandler to process KMIP requests.
//
// Returns:
//   - A pointer to the initialized Server.
func NewServer(listener net.Listener, handler RequestHandler) *Server {
	if handler == nil {
		panic("KMIP request handler cannot be null")
	}
	ctx, cancel := context.WithCancel(context.Background())
	recvCtx, recvCancel := context.WithCancel(context.Background())
	return &Server{
		listener,
		handler,
		slog.Default(),
		ctx,
		cancel,
		recvCtx,
		recvCancel,
		new(sync.WaitGroup),
	}
}

// Serve starts the KMIP server and listens for incoming client connections.
// It accepts connections in a loop, spawning a new goroutine to handle each connection.
// If the listener is closed, it returns ErrShutdown. Any other error encountered
// during Accept is returned immediately. The method blocks until the server is shut down.
func (srv *Server) Serve() error {
	srv.logger.Info("Running KMIP server", "bind", srv.listener.Addr())
	for {
		conn, err := srv.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return ErrShutdown
			}
			//TODO: Return a shutdown error if shutdown has been requested
			return err
		}
		srv.wg.Add(1)
		go srv.handleConn(conn)
	}
}

// Shutdown gracefully shuts down the server by performing the following steps:
// 1. Logs a warning message indicating shutdown initiation.
// 2. Closes the listener to prevent new incoming connections.
// 3. Cancels the receive context to stop processing new requests.
// 4. Sets a timeout to force server context cancellation after 3 seconds.
// 5. Waits for all running requests to complete.
// 6. Cancels the server's root context.
// Returns any error encountered while closing the listener.
func (srv *Server) Shutdown() error {
	srv.logger.Warn("Shutting down")
	// 1. Close listener to prevent new incoming conections
	err := srv.listener.Close()
	// 2. Cancel recvCtx to stop receiving new requests
	srv.recvCancel()
	// 3. Set a timeout to force server context cancellation after 3 seconds.
	tm := time.AfterFunc(3*time.Second, func() {
		srv.cancel()
	})
	// 4. Wait for running requests completion
	srv.wg.Wait()
	tm.Stop()
	// 5. Cancel server root context
	srv.cancel()
	return err
}

func (srv *Server) handleConn(conn net.Conn) {
	defer srv.wg.Done()
	logger := srv.logger.With("addr", conn.RemoteAddr())
	logger.Info("New connection")
	var tlsState *tls.ConnectionState
	if tcon, ok := conn.(*tls.Conn); ok {
		if err := tcon.Handshake(); err != nil {
			_ = tcon.Close()
			logger.Warn("TLS handshake failure. Closing client connection", "err", err)
			return
		}
		tlsState = new(tls.ConnectionState)
		*tlsState = tcon.ConnectionState()
	}
	stream := newConn(conn, srv.ctx, logger)
	// TODO: Save ref in server
	// TODO: Remove ref on connection termination
	defer stream.Close()

	// Create a client connection state aware context
	ctx := newConnContext(stream.ctx, conn.RemoteAddr().String(), tlsState)
	for {
		msg, err := stream.recv(srv.recvCtx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				logger.Info("Client connection closed")
				break
			}
			logger.Error("Failed to read data from client", "err", err)

			if ttlv.IsErrEncoding(err) {
				resp := srv.handleMessageError(ctx, msg, kmip.ResultReasonInvalidMessage, err.Error())
				if err := stream.send(resp); err != nil {
					logger.Warn("Fail to write data", "err", err)
				}
			}
			break
		}
		// go func() {
		// 	select {
		// 	case <-srv.recvCtx.Done():
		// 		TODO: cancel running task
		// 	case <-stream.ctx.Done():
		// 	}
		// }()
		resp := srv.handleRequest(ctx, msg)
		if ctx.Err() != nil {
			logger.Warn("Request processing aborted", "err", ctx.Err())
			break
		}

		if err := stream.send(resp); err != nil {
			logger.Warn("Fail to write data. Closing client connection", "err", err)
			break
		}
	}
}

func (srv *Server) handleMessageError(ctx context.Context, req *kmip.RequestMessage, reason kmip.ResultReason, message string) *kmip.ResponseMessage {
	return handleMessageError(ctx, req, Errorf(reason, "%s", message))
}

func (srv *Server) handleRequest(ctx context.Context, req *kmip.RequestMessage) (resp *kmip.ResponseMessage) {
	// srv.reqWg.Add(1)
	// defer srv.reqWg.Done()
	//TODO: Catch panics
	resp = srv.handler.HandleRequest(ctx, req)
	return resp
}
