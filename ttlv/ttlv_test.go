package ttlv_test

import (
	"testing"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

func BenchmarkMarshalRequestMessage(b *testing.B) {
	msg := kmip.NewRequestMessage(kmip.V1_4, &payloads.DiscoverVersionsRequestPayload{
		ProtocolVersion: []kmip.ProtocolVersion{kmip.V1_4, kmip.V1_0},
	}, &payloads.DiscoverVersionsRequestPayload{})

	b.ReportAllocs()

	for b.Loop() {
		_ = ttlv.MarshalTTLV(&msg)
	}
}

func BenchmarkUnmarshalRequestMessage(b *testing.B) {
	raw := ttlv.MarshalTTLV(&kmip.RequestMessage{
		Header: kmip.RequestHeader{
			ProtocolVersion: kmip.V1_4,
			TimeStamp:       func() *time.Time { t := time.Now().Truncate(time.Second); return &t }(),
			BatchCount:      2,
		},
		BatchItem: []kmip.RequestBatchItem{
			{
				Operation: kmip.OperationDiscoverVersions,
				RequestPayload: &payloads.DiscoverVersionsRequestPayload{
					ProtocolVersion: []kmip.ProtocolVersion{kmip.V1_4, kmip.V1_0},
				},
			},
			{
				Operation:      kmip.OperationDiscoverVersions,
				RequestPayload: &payloads.DiscoverVersionsRequestPayload{},
			},
		},
	})

	b.ReportAllocs()

	for b.Loop() {
		var msg kmip.RequestMessage
		_ = ttlv.UnmarshalTTLV(raw, &msg)
	}
}
