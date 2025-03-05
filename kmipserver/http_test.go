package kmipserver_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"

	"github.com/stretchr/testify/require"
)

func TestHttpHandler_TTLV(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()

	mux.Route(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		require.NotEmpty(t, kmipserver.RemoteAddr(ctx))
		// require.NotEmpty(t, kmipserver.PeerCertificates(ctx))
		return &payloads.ActivateResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
	}))

	hdl := kmipserver.NewHTTPHandler(mux)

	for _, tc := range []struct {
		name      string
		marshal   func(data any) []byte
		unmarshal func(data []byte, ptr any) error
		mime      string
	}{
		{"TTLV", ttlv.MarshalTTLV, ttlv.UnmarshalTTLV, "application/octet-stream"},
		{"XML", ttlv.MarshalXML, ttlv.UnmarshalXML, "text/xml"},
		{"JSON", ttlv.MarshalJSON, ttlv.UnmarshalJSON, "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uid := "foobar"
			req := kmip.NewRequestMessage(kmip.V1_4, &payloads.ActivateRequestPayload{
				UniqueIdentifier: uid,
			})
			body := tc.marshal(req)
			httpReq := httptest.NewRequest(http.MethodPost, "/kmip", bytes.NewReader(body))
			httpReq.Header.Set("Content-Type", tc.mime)
			httpReq.Header.Set("Content-Length", strconv.Itoa(len(body)))
			rec := httptest.NewRecorder()
			hdl.ServeHTTP(rec, httpReq)

			require.Equal(t, http.StatusOK, rec.Code)
			resp := kmip.ResponseMessage{}
			err := tc.unmarshal(rec.Body.Bytes(), &resp)
			require.NoError(t, err)
			require.Len(t, resp.BatchItem, 1)
			require.Equal(t, uid, resp.BatchItem[0].ResponsePayload.(*payloads.ActivateResponsePayload).UniqueIdentifier)
		})
	}

}
