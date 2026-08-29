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

// RequestHeader Benchmarks

func makeRequestHeader() kmip.RequestHeader {
	batchOrder := true
	async := true
	return kmip.RequestHeader{
		ProtocolVersion:             kmip.V1_4,
		MaximumResponseSize:         1048576,
		ClientCorrelationValue:      "client-12345",
		ServerCorrelationValue:      "server-67890",
		AsynchronousIndicator:       &async,
		AttestationCapableIndicator: &async,
		AttestationType: []kmip.AttestationType{
			kmip.AttestationTypeTPMQuote,
			kmip.AttestationTypeTCGIntegrityReport,
		},
		Authentication: &kmip.Authentication{
			Credential: kmip.Credential{
				CredentialType: kmip.CredentialTypeUsernameAndPassword,
			},
		},
		BatchErrorContinuationOption: kmip.BatchErrorContinuationOptionUndo,
		BatchOrderOption:             &batchOrder,
		TimeStamp:                    func() *time.Time { t := time.Now().Truncate(time.Second); return &t }(),
		BatchCount:                   1,
	}
}

// BenchmarkRequestHeaderEncode_TTLV_Pooled benchmarks encoding RequestHeader using pooled MarshalTTLV
func BenchmarkRequestHeaderEncode_TTLV_Pooled(b *testing.B) {
	header := makeRequestHeader()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = ttlv.MarshalTTLV(header)
	}
}

// BenchmarkRequestHeaderEncode_TTLV_PoolReuse benchmarks encoding using pooled encoder with per-iteration reuse
// This simulates the ideal pooling pattern: get from pool, reuse, return
func BenchmarkRequestHeaderEncode_TTLV_PoolReuse(b *testing.B) {
	header := makeRequestHeader()

	// Simulate pooling pattern: get encoder once, reuse across all iterations
	enc := ttlv.NewTTLVEncoder()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		enc.Clear()
		enc.Any(header)
		// 模拟池化：编码后准备归还（实际不归还以便复用）
	}
}

// BenchmarkRequestHeaderEncode_TTLV_NonPooled benchmarks encoding RequestHeader creating a new encoder per call
func BenchmarkRequestHeaderEncode_TTLV_NonPooled(b *testing.B) {
	header := makeRequestHeader()

	b.ReportAllocs()
	for b.Loop() {
		enc := ttlv.NewTTLVEncoder()
		enc.Any(header)
	}
}

// BenchmarkRequestHeaderEncode_TTLV_Reuse benchmarks encoding RequestHeader reusing the same encoder instance
func BenchmarkRequestHeaderEncode_TTLV_Reuse(b *testing.B) {
	header := makeRequestHeader()
	enc := ttlv.NewTTLVEncoder()

	b.ReportAllocs()
	for b.Loop() {
		enc.Clear()
		enc.Any(header)
	}
}

// BenchmarkRequestHeaderDecode_TTLV_Pooled benchmarks decoding RequestHeader using pooled UnmarshalTTLV
func BenchmarkRequestHeaderDecode_TTLV_Pooled(b *testing.B) {
	header := makeRequestHeader()
	data := ttlv.MarshalTTLV(header)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		var h kmip.RequestHeader
		_ = ttlv.UnmarshalTTLV(data, &h)
	}
}

// BenchmarkRequestHeaderDecode_TTLV_NonPooled benchmarks decoding RequestHeader using non-pooled NewTTLVDecoder
func BenchmarkRequestHeaderDecode_TTLV_NonPooled(b *testing.B) {
	header := makeRequestHeader()
	data := ttlv.MarshalTTLV(header)

	b.ReportAllocs()
	for b.Loop() {
		dec, _ := ttlv.NewTTLVDecoder(data)
		var h kmip.RequestHeader
		_ = dec.Any(&h)
	}
}

// BenchmarkRequestHeaderEncodeDecode_TTLV benchmarks full encode/decode cycle using pooled functions
func BenchmarkRequestHeaderEncodeDecode_TTLV(b *testing.B) {
	header := makeRequestHeader()

	b.ReportAllocs()
	for b.Loop() {
		data := ttlv.MarshalTTLV(header)
		var h kmip.RequestHeader
		_ = ttlv.UnmarshalTTLV(data, &h)
	}
}

// BenchmarkRequestHeaderEncode_XML benchmarks encoding RequestHeader to XML format
func BenchmarkRequestHeaderEncode_XML(b *testing.B) {
	header := makeRequestHeader()
	enc := ttlv.NewXMLEncoder()

	b.ReportAllocs()
	for b.Loop() {
		enc.Clear()
		enc.Any(header)
	}
}

// BenchmarkRequestHeaderEncode_JSON benchmarks encoding RequestHeader to JSON format
func BenchmarkRequestHeaderEncode_JSON(b *testing.B) {
	header := makeRequestHeader()
	enc := ttlv.NewJSONEncoder()

	b.ReportAllocs()
	for b.Loop() {
		enc.Clear()
		enc.Any(header)
	}
}

// BenchmarkRequestHeaderEncode_Text benchmarks encoding RequestHeader to text format
func BenchmarkRequestHeaderEncode_Text(b *testing.B) {
	header := makeRequestHeader()
	enc := ttlv.NewTextEncoder()

	b.ReportAllocs()
	for b.Loop() {
		enc.Clear()
		enc.Any(header)
	}
}

// BenchmarkRequestHeaderEncode_Size reports the encoded size of RequestHeader in different formats
func BenchmarkRequestHeaderEncode_Size(b *testing.B) {
	header := makeRequestHeader()

	// Run once to get sizes
	ttlvData := ttlv.MarshalTTLV(header)
	b.ReportMetric(float64(len(ttlvData)), "bytes/ttlv")

	xmlData := ttlv.MarshalXML(header)
	b.ReportMetric(float64(len(xmlData)), "bytes/xml")

	jsonData := ttlv.MarshalJSON(header)
	b.ReportMetric(float64(len(jsonData)), "bytes/json")

	textData := ttlv.MarshalText(header)
	b.ReportMetric(float64(len(textData)), "bytes/text")
}
