package kmip_test

import (
	"encoding/hex"
	"slices"
	"testing"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeRequest(t *testing.T) {
	msg := kmip.NewRequestMessage(kmip.V1_4, &payloads.DiscoverVersionsRequestPayload{
		ProtocolVersion: []kmip.ProtocolVersion{kmip.V1_4, kmip.V1_0},
	}, &payloads.DiscoverVersionsRequestPayload{})

	for _, tc := range []struct {
		name      string
		marshal   func(any) []byte
		unmarshal func([]byte, any) error
	}{
		{"TTLV", ttlv.MarshalTTLV, ttlv.UnmarshalTTLV},
		{"XML", ttlv.MarshalXML, ttlv.UnmarshalXML},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bytes := tc.marshal(&msg)

			nmsg := kmip.RequestMessage{}
			err := tc.unmarshal(bytes, &nmsg)
			require.NoError(t, err)

			assert.Equal(t, msg, nmsg)
		})
	}

}

func TestEncodeDecodeResponse(t *testing.T) {
	msg := kmip.ResponseMessage{
		Header: kmip.ResponseHeader{
			ProtocolVersion: kmip.V1_2,
			TimeStamp:       time.Now().Round(time.Second),
			BatchCount:      1,
		},
		BatchItem: []kmip.ResponseBatchItem{
			{
				Operation: kmip.OperationDiscoverVersions,
				ResponsePayload: &payloads.DiscoverVersionsResponsePayload{
					ProtocolVersion: []kmip.ProtocolVersion{
						kmip.V1_4, kmip.V1_0,
					},
				},
			},
		},
	}
	for _, tc := range []struct {
		name      string
		marshal   func(any) []byte
		unmarshal func([]byte, any) error
	}{
		{"TTLV", ttlv.MarshalTTLV, ttlv.UnmarshalTTLV},
		{"XML", ttlv.MarshalXML, ttlv.UnmarshalXML},
	} {
		bytes := tc.marshal(&msg)

		nmsg := kmip.ResponseMessage{}
		err := tc.unmarshal(bytes, &nmsg)
		require.NoError(t, err)

		assert.Equal(t, msg, nmsg)
	}
}

func BenchmarkKmipEncode(b *testing.B) {
	msg := kmip.NewRequestMessage(kmip.V1_4, &payloads.DiscoverVersionsRequestPayload{
		ProtocolVersion: []kmip.ProtocolVersion{kmip.V1_4, kmip.V1_0},
	}, &payloads.DiscoverVersionsRequestPayload{
		ProtocolVersion: []kmip.ProtocolVersion{kmip.V1_4, kmip.V1_0},
	})
	enc := ttlv.NewTTLVEncoder()
	enc.Any(&msg)
	b.ResetTimer()
	for range b.N {
		enc.Clear()
		enc.Any(&msg)
	}
}

func BenchmarkKmipDecode(b *testing.B) {
	data, _ := hex.DecodeString("42007801000000A04200770100000038420069010000002042006A0200000004000000010000000042006B0200000004000000040000000042000D0200000004000000010000000042000F010000005842005C05000000040000001E000000004200930800000010B28CED4885814A6AAFF3CB1552FF0A524200790100000028420069010000002042006A0200000004000000010000000042006B02000000040000000400000000")
	d := kmip.RequestMessage{}
	for range b.N {
		dec, _ := ttlv.NewTTLVDecoder(data)
		_ = dec.Any(&d)
	}
}

func TestParseAndMarshalOasisTests(t *testing.T) {
	for _, vers := range kmiptest.TestCaseVersions {
		suites := kmiptest.ListTestSuites(t, "kmiptest/testdata", vers)

		for _, e := range suites {
			name := vers + "/" + e
			t.Run(name, func(t *testing.T) {
				if slices.Contains(kmiptest.UnsupportedTestCases, name) {
					t.Skip("Test case not supported")
				}

				ts := kmiptest.LoadTestSuite(t, "kmiptest/testdata", vers, e)

				var err error
				for _, tc := range ts.TestCases {
					{
						raw := ttlv.MarshalTTLV(tc.RequestMessage)
						msg := kmip.RequestMessage{}
						err = ttlv.UnmarshalTTLV(raw, &msg)
						require.NoError(t, err)
						require.EqualValues(t, tc.RequestMessage, msg)
					}
					{
						raw := ttlv.MarshalTTLV(tc.ResponseMessage)
						msg := kmip.ResponseMessage{}
						err = ttlv.UnmarshalTTLV(raw, &msg)
						require.NoError(t, err)
						require.EqualValues(t, tc.ResponseMessage, msg)
					}
					{
						raw := ttlv.MarshalXML(tc.RequestMessage)
						msg := kmip.RequestMessage{}
						err = ttlv.UnmarshalXML(raw, &msg)
						require.NoError(t, err)
						require.EqualValues(t, tc.RequestMessage, msg)
					}
					{
						raw := ttlv.MarshalXML(tc.ResponseMessage)
						msg := kmip.ResponseMessage{}
						err = ttlv.UnmarshalXML(raw, &msg)
						require.NoError(t, err)
						require.EqualValues(t, tc.ResponseMessage, msg)
					}
					{
						raw := ttlv.MarshalJSON(tc.RequestMessage)
						msg := kmip.RequestMessage{}
						err = ttlv.UnmarshalJSON(raw, &msg)
						require.NoError(t, err)
						require.EqualValues(t, tc.RequestMessage, msg)
					}
					{
						raw := ttlv.MarshalJSON(tc.ResponseMessage)
						msg := kmip.ResponseMessage{}
						err = ttlv.UnmarshalJSON(raw, &msg)
						require.NoError(t, err)
						require.EqualValues(t, tc.ResponseMessage, msg)
					}
				}
			})
		}
	}
}
