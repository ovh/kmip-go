package kmipserver

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"
)

func NewHTTPHandler(hdl RequestHandler) http.Handler {
	return httpHandler{inner: hdl}
}

type httpHandler struct {
	inner RequestHandler
}

func (hdl httpHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if body := req.Body; body != nil {
		defer body.Close()
	}
	if req.Method != http.MethodPost {
		rw.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = io.WriteString(rw, "Only POST method are allowed")
		return
	}

	var unmarshaller func(data []byte, ptr any) error
	var marshaller func(data any) []byte
	switch req.Header.Get("Content-Type") {
	case "text/xml":
		unmarshaller = ttlv.UnmarshalXML
		marshaller = ttlv.MarshalXML
	case "application/json":
		unmarshaller = ttlv.UnmarshalJSON
		marshaller = ttlv.MarshalJSON
	case "application/octet-stream":
		unmarshaller = ttlv.UnmarshalTTLV
		marshaller = ttlv.MarshalTTLV
	default:
		rw.WriteHeader(http.StatusNotAcceptable)
		_, _ = io.WriteString(rw, "Unsupported Content-Type header")
		return
	}

	//TODO: Check the Accept header if present

	contentLen, err := strconv.Atoi(req.Header.Get("Content-Length"))
	if err != nil || contentLen <= 0 {
		rw.WriteHeader(http.StatusLengthRequired)
		return
	}

	buf := make([]byte, contentLen)
	if _, err := io.ReadFull(req.Body, buf); err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(rw, "Amount of data is lower than Content-Length")
		return
	}

	msg := kmip.RequestMessage{}
	var resp *kmip.ResponseMessage
	if err := unmarshaller(buf, &msg); err != nil {
		// If encoding error, send back the kmip error response
		resp = hdl.handleError(req.Context(), err, &msg)
	} else {
		ctx := newConnContext(req.Context(), req.RemoteAddr, req.TLS)
		resp = hdl.inner.HandleRequest(ctx, &msg)
	}

	buf = marshaller(resp)
	if _, err := rw.Write(buf); err != nil {
		//TODO: Use user provided logger maybe ?
		slog.Error("Failed to write HTTP response", "err", err)
	}
}

func (hdl httpHandler) handleError(ctx context.Context, err error, req *kmip.RequestMessage) *kmip.ResponseMessage {
	return handleMessageError(ctx, req, err)
}
