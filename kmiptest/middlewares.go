package kmiptest

import (
	"context"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/ttlv"

	"github.com/stretchr/testify/require"
)

func TestingMiddleware(t TestingT) kmipclient.Middleware {
	return func(next kmipclient.Next, ctx context.Context, rm *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
		resp, err := next(ctx, rm)
		if err != nil {
			return resp, err
		}

		rq := &kmip.RequestMessage{}
		err = ttlv.UnmarshalXML(ttlv.MarshalXML(rm), &rq)
		require.NoError(t, err, "Could not unmarshal XML request")
		require.EqualValues(t, ttlv.MarshalTTLV(rm), ttlv.MarshalTTLV(rq), "XML requests not equal")

		rq = &kmip.RequestMessage{}
		err = ttlv.UnmarshalJSON(ttlv.MarshalJSON(rm), &rq)
		require.NoError(t, err, "Could not unmarshal JSON request")
		require.EqualValues(t, ttlv.MarshalTTLV(rm), ttlv.MarshalTTLV(rq), "JSON requests not equal")

		rr := &kmip.ResponseMessage{}
		err = ttlv.UnmarshalXML(ttlv.MarshalXML(resp), &rr)
		require.NoError(t, err, "Could not unmarshal XML response")
		require.EqualValues(t, ttlv.MarshalTTLV(resp), ttlv.MarshalTTLV(rr), "XML responses not equal")

		rr = &kmip.ResponseMessage{}
		err = ttlv.UnmarshalJSON(ttlv.MarshalJSON(resp), &rr)
		require.NoError(t, err, "Could not unmarshal JSON responses")
		require.EqualValues(t, ttlv.MarshalTTLV(resp), ttlv.MarshalTTLV(rr), "JSON responses not equal")

		return resp, nil
	}
}
