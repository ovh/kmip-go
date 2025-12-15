package payloads_test

import (
	"testing"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"

	_ "unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPayloadsTypes(t *testing.T) {
	for op := range ttlv.EnumValues[kmip.Operation]() {
		assert.Equal(t, op, newRequestPayload(op).Operation())
		assert.Equal(t, op, newResponsePayload(op).Operation())
	}
}

//go:linkname newRequestPayload github.com/ovh/kmip-go.newRequestPayload
func newRequestPayload(op kmip.Operation) kmip.OperationPayload

//go:linkname newResponsePayload github.com/ovh/kmip-go.newResponsePayload
func newResponsePayload(op kmip.Operation) kmip.OperationPayload

func TestRegisterRequestPayload_Encode_Decode(t *testing.T) {
	secret := []byte("foobar")
	req := &payloads.RegisterRequestPayload{
		ObjectType:        kmip.ObjectTypeSecretData,
		TemplateAttribute: kmip.TemplateAttribute{},
		Object: &kmip.SecretData{
			SecretDataType: kmip.SecretDataTypePassword,
			KeyBlock:       kmip.KeyBlock{KeyFormatType: kmip.KeyFormatTypeRaw, KeyValue: &kmip.KeyValue{Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{Bytes: &secret}}}},
		},
	}

	enc := ttlv.NewTTLVEncoder()
	enc.TagAny(kmip.TagRequestPayload, req)
	ttlvReq := enc.Bytes()
	decodedReq := &payloads.RegisterRequestPayload{}
	dec, err := ttlv.NewTTLVDecoder(ttlvReq)
	require.NoError(t, err)
	err = dec.TagAny(kmip.TagRequestPayload, decodedReq)
	require.NoError(t, err)
	require.EqualValues(t, req, decodedReq)
}

func TestImportRequestPayload_Encode_Decode(t *testing.T) {
	secret := []byte("foobar")
	req := &payloads.ImportRequestPayload{
		UniqueIdentifier: "foo",
		Attribute: []kmip.Attribute{
			{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "bar", NameType: kmip.NameTypeUninterpretedTextString}},
			{AttributeName: kmip.AttributeNameObjectType, AttributeValue: kmip.ObjectTypeSecretData},
		},
		Object: &kmip.SecretData{
			SecretDataType: kmip.SecretDataTypePassword,
			KeyBlock:       kmip.KeyBlock{KeyFormatType: kmip.KeyFormatTypeRaw, KeyValue: &kmip.KeyValue{Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{Bytes: &secret}}}},
		},
	}

	enc := ttlv.NewTTLVEncoder()
	enc.TagAny(kmip.TagRequestPayload, req)
	ttlvReq := enc.Bytes()
	decodedReq := &payloads.ImportRequestPayload{}
	dec, err := ttlv.NewTTLVDecoder(ttlvReq)
	require.NoError(t, err)
	err = dec.TagAny(kmip.TagRequestPayload, decodedReq)
	require.NoError(t, err)
	require.EqualValues(t, req, decodedReq)
}

func TestExportResponsePayload_Encode_Decode(t *testing.T) {
	secret := []byte("foobar")
	req := &payloads.ExportResponsePayload{
		ObjectType:       kmip.ObjectTypeSecretData,
		UniqueIdentifier: "foo",
		Attribute: []kmip.Attribute{
			{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "bar", NameType: kmip.NameTypeUninterpretedTextString}},
			{AttributeName: kmip.AttributeNameObjectType, AttributeValue: kmip.ObjectTypeSecretData},
		},
		Object: &kmip.SecretData{
			SecretDataType: kmip.SecretDataTypePassword,
			KeyBlock:       kmip.KeyBlock{KeyFormatType: kmip.KeyFormatTypeRaw, KeyValue: &kmip.KeyValue{Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{Bytes: &secret}}}},
		},
	}

	enc := ttlv.NewTTLVEncoder()
	enc.TagAny(kmip.TagRequestPayload, req)
	ttlvReq := enc.Bytes()
	decodedReq := &payloads.ExportResponsePayload{}
	dec, err := ttlv.NewTTLVDecoder(ttlvReq)
	require.NoError(t, err)
	err = dec.TagAny(kmip.TagRequestPayload, decodedReq)
	require.NoError(t, err)
	require.EqualValues(t, req, decodedReq)
}
