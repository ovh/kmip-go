package payloads_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

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

var timeType = reflect.TypeOf(time.Time{})

// normalizeTimesToUTC recursively converts all time.Time fields to UTC
// so that reflect.DeepEqual works regardless of timezone differences in TTLV decoding.
func normalizeTimesToUTC(v reflect.Value) {
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			normalizeTimesToUTC(v.Elem())
		}
	case reflect.Struct:
		if v.Type() == timeType {
			if v.CanSet() {
				v.Set(reflect.ValueOf(v.Interface().(time.Time).UTC()))
			}
			return
		}
		for i := range v.NumField() {
			if f := v.Field(i); f.CanSet() {
				normalizeTimesToUTC(f)
			}
		}
	case reflect.Slice:
		for i := range v.Len() {
			normalizeTimesToUTC(v.Index(i))
		}
	case reflect.Interface:
		if !v.IsNil() {
			normalizeTimesToUTC(v.Elem())
		}
	}
}

func TestPayloads_Encode_Decode(t *testing.T) {
	secret := []byte("foobar")
	newSecretData := func() *kmip.SecretData {
		return &kmip.SecretData{
			SecretDataType: kmip.SecretDataTypePassword,
			KeyBlock: kmip.KeyBlock{
				KeyFormatType: kmip.KeyFormatTypeRaw,
				KeyValue:      &kmip.KeyValue{Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{Bytes: &secret}}},
			},
		}
	}

	boolPtr := func(b bool) *bool { return &b }
	int32Ptr := func(i int32) *int32 { return &i }
	durationPtr := func(d time.Duration) *time.Duration { return &d }
	compromiseDate := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	newTemplateAttr := func() *kmip.TemplateAttribute {
		return &kmip.TemplateAttribute{
			Name: []kmip.Name{{NameValue: "tpl-name", NameType: kmip.NameTypeUninterpretedTextString}},
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameObjectType, AttributeValue: kmip.ObjectTypeSymmetricKey},
			},
		}
	}

	tests := []struct {
		name    string
		payload any
	}{
		// Register
		{"RegisterRequest", &payloads.RegisterRequestPayload{
			ObjectType:        kmip.ObjectTypeSecretData,
			TemplateAttribute: *newTemplateAttr(),
			Object:            newSecretData(),
		}},
		{"RegisterResponse", &payloads.RegisterResponsePayload{
			UniqueIdentifier:  "obj-registered",
			TemplateAttribute: newTemplateAttr(),
		}},

		// Import / Export
		{"ImportRequest", &payloads.ImportRequestPayload{
			UniqueIdentifier: "foo",
			ReplaceExisting:  true,
			KeyWrapType:      kmip.NotWrapped,
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "bar", NameType: kmip.NameTypeUninterpretedTextString}},
				{AttributeName: kmip.AttributeNameObjectType, AttributeValue: kmip.ObjectTypeSecretData},
			},
			Object: newSecretData(),
		}},
		{"ImportResponse", &payloads.ImportResponsePayload{
			UniqueIdentifier: "obj-imported",
		}},
		{"ExportRequest", &payloads.ExportRequestPayload{
			UniqueIdentifier:   "obj-export",
			KeyFormatType:      kmip.KeyFormatTypeRaw,
			KeyWrapType:        kmip.NotWrapped,
			KeyCompressionType: kmip.KeyCompressionTypeECPublicKeyTypeX9_62CompressedPrime,
			KeyWrappingSpecification: &kmip.KeyWrappingSpecification{
				WrappingMethod: kmip.WrappingMethodEncryptThenMACSign,
			},
		}},
		{"ExportResponse", &payloads.ExportResponsePayload{
			ObjectType:       kmip.ObjectTypeSecretData,
			UniqueIdentifier: "foo",
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "bar", NameType: kmip.NameTypeUninterpretedTextString}},
				{AttributeName: kmip.AttributeNameObjectType, AttributeValue: kmip.ObjectTypeSecretData},
			},
			Object: newSecretData(),
		}},

		// Create
		{"CreateRequest", &payloads.CreateRequestPayload{
			ObjectType:        kmip.ObjectTypeSymmetricKey,
			TemplateAttribute: *newTemplateAttr(),
		}},
		{"CreateResponse", &payloads.CreateResponsePayload{
			ObjectType:       kmip.ObjectTypeSymmetricKey,
			UniqueIdentifier: "key-1",
			Attributes:       newTemplateAttr(),
		}},

		// CreateKeyPair
		{"CreateKeyPairRequest", &payloads.CreateKeyPairRequestPayload{
			CommonTemplateAttribute:     newTemplateAttr(),
			PrivateKeyTemplateAttribute: newTemplateAttr(),
			PublicKeyTemplateAttribute:  newTemplateAttr(),
		}},
		{"CreateKeyPairResponse", &payloads.CreateKeyPairResponsePayload{
			PrivateKeyUniqueIdentifier:  "priv-1",
			PublicKeyUniqueIdentifier:   "pub-1",
			PrivateKeyTemplateAttribute: newTemplateAttr(),
			PublicKeyTemplateAttribute:  newTemplateAttr(),
		}},

		// Encrypt / Decrypt
		{"EncryptRequest", &payloads.EncryptRequestPayload{
			UniqueIdentifier:                      "key-1",
			CryptographicParameters:               &kmip.CryptographicParameters{BlockCipherMode: kmip.BlockCipherModeCBC},
			Data:                                  []byte("plaintext"),
			IVCounterNonce:                        []byte("nonce123456"),
			CorrelationValue:                      []byte("corr-1"),
			InitIndicator:                         boolPtr(true),
			FinalIndicator:                        boolPtr(false),
			AuthenticatedEncryptionAdditionalData: []byte("aad"),
		}},
		{"EncryptResponse", &payloads.EncryptResponsePayload{
			UniqueIdentifier:           "key-1",
			Data:                       []byte("ciphertext"),
			IVCounterNonce:             []byte("nonce123456"),
			CorrelationValue:           []byte("corr-1"),
			AuthenticatedEncryptionTag: []byte("tag"),
		}},
		{"DecryptRequest", &payloads.DecryptRequestPayload{
			UniqueIdentifier:                      "key-1",
			CryptographicParameters:               &kmip.CryptographicParameters{BlockCipherMode: kmip.BlockCipherModeGCM},
			Data:                                  []byte("ciphertext"),
			IVCounterNonce:                        []byte("nonce123456"),
			CorrelationValue:                      []byte("corr-2"),
			InitIndicator:                         boolPtr(false),
			FinalIndicator:                        boolPtr(true),
			AuthenticatedEncryptionAdditionalData: []byte("aad"),
			AuthenticatedEncryptionTag:            []byte("tag"),
		}},
		{"DecryptResponse", &payloads.DecryptResponsePayload{
			UniqueIdentifier: "key-1",
			Data:             []byte("plaintext"),
			CorrelationValue: []byte("corr-2"),
		}},

		// Sign / Verify
		{"SignRequest", &payloads.SignRequestPayload{
			UniqueIdentifier:        "key-sign",
			CryptographicParameters: &kmip.CryptographicParameters{HashingAlgorithm: kmip.HashingAlgorithmSHA_256},
			Data:                    []byte("data to sign"),
			DigestedData:            []byte("digested"),
			CorrelationValue:        []byte("corr-3"),
			InitIndicator:           boolPtr(true),
			FinalIndicator:          boolPtr(true),
		}},
		{"SignResponse", &payloads.SignResponsePayload{
			UniqueIdentifier: "key-sign",
			SignatureData:    []byte("signature"),
			CorrelationValue: []byte("corr-3"),
		}},
		{"SignatureVerifyRequest", &payloads.SignatureVerifyRequestPayload{
			UniqueIdentifier:        "key-verify",
			CryptographicParameters: &kmip.CryptographicParameters{HashingAlgorithm: kmip.HashingAlgorithmSHA_256},
			Data:                    []byte("data to verify"),
			DigestedData:            []byte("digested"),
			SignatureData:           []byte("signature"),
			CorrelationValue:        []byte("corr-4"),
			InitIndicator:           boolPtr(false),
			FinalIndicator:          boolPtr(false),
		}},
		{"SignatureVerifyResponse", &payloads.SignatureVerifyResponsePayload{
			UniqueIdentifier:  "key-verify",
			ValidityIndicator: kmip.ValidityIndicatorValid,
			Data:              []byte("recovered data"),
			CorrelationValue:  []byte("corr-4"),
		}},

		// Locate
		{"LocateRequest", &payloads.LocateRequestPayload{
			MaximumItems:      10,
			OffsetItems:       5,
			StorageStatusMask: kmip.StorageStatusOnlineStorage,
			ObjectGroupMember: kmip.ObjectGroupMemberFresh,
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameObjectType, AttributeValue: kmip.ObjectTypeSymmetricKey},
			},
		}},
		{"LocateResponse", &payloads.LocateResponsePayload{
			LocatedItems:     int32Ptr(3),
			UniqueIdentifier: []string{"id-1", "id-2", "id-3"},
		}},

		// Query
		{"QueryRequest", &payloads.QueryRequestPayload{
			QueryFunction: []kmip.QueryFunction{kmip.QueryFunctionOperations, kmip.QueryFunctionObjects},
		}},
		{"QueryResponse", &payloads.QueryResponsePayload{
			Operations:           []kmip.Operation{kmip.OperationCreate, kmip.OperationGet},
			ObjectType:           []kmip.ObjectType{kmip.ObjectTypeSymmetricKey},
			VendorIdentification: "test-vendor",
			// ServerInformation intentionally omitted — vendor-specific opaque ttlv.Value
			ApplicationNamespace: []string{"ns1"},
			ExtensionInformation: []kmip.ExtensionInformation{{ExtensionName: "ext1"}},
			AttestationType:      []kmip.AttestationType{kmip.AttestationTypeTCGIntegrityReport},
			RNGParameters:        []kmip.RNGParameters{{RNGAlgorithm: kmip.RNGAlgorithmUnspecified}},
			ProfileInformation:   []kmip.ProfileInformation{{ProfileName: kmip.ProfileNameBaselineServerBasicKMIPV1_2}},
			ValidationInformation: []kmip.ValidationInformation{{
				ValidationAuthorityType: kmip.ValidationAuthorityTypeUnspecified,
				ValidationVersionMajor:  1,
				ValidationType:          kmip.ValidationTypeUnspecified,
			}},
			CapabilityInformation:    []kmip.CapabilityInformation{{StreamingCapability: boolPtr(true)}},
			ClientRegistrationMethod: []kmip.ClientRegistrationMethod{kmip.ClientRegistrationMethodClientGenerated},
		}},

		// DiscoverVersions
		{"DiscoverVersionsRequest", &payloads.DiscoverVersionsRequestPayload{
			ProtocolVersion: []kmip.ProtocolVersion{
				{ProtocolVersionMajor: 1, ProtocolVersionMinor: 4},
				{ProtocolVersionMajor: 1, ProtocolVersionMinor: 3},
			},
		}},
		{"DiscoverVersionsResponse", &payloads.DiscoverVersionsResponsePayload{
			ProtocolVersion: []kmip.ProtocolVersion{
				{ProtocolVersionMajor: 1, ProtocolVersionMinor: 4},
			},
		}},

		// Activate
		{"ActivateRequest", &payloads.ActivateRequestPayload{UniqueIdentifier: "obj-activate"}},
		{"ActivateResponse", &payloads.ActivateResponsePayload{UniqueIdentifier: "obj-activate"}},

		// Revoke
		{"RevokeRequest", &payloads.RevokeRequestPayload{
			UniqueIdentifier: "obj-revoke",
			RevocationReason: kmip.RevocationReason{
				RevocationReasonCode: kmip.RevocationReasonCodeCessationOfOperation,
				RevocationMessage:    "key retired",
			},
			CompromiseOccurrenceDate: &compromiseDate,
		}},
		{"RevokeResponse", &payloads.RevokeResponsePayload{UniqueIdentifier: "obj-revoke"}},

		// Destroy
		{"DestroyRequest", &payloads.DestroyRequestPayload{UniqueIdentifier: "obj-destroy"}},
		{"DestroyResponse", &payloads.DestroyResponsePayload{UniqueIdentifier: "obj-destroy"}},

		// Archive / Recover
		{"ArchiveRequest", &payloads.ArchiveRequestPayload{UniqueIdentifier: "obj-archive"}},
		{"ArchiveResponse", &payloads.ArchiveResponsePayload{UniqueIdentifier: "obj-archive"}},
		{"RecoverRequest", &payloads.RecoverRequestPayload{UniqueIdentifier: "obj-recover"}},
		{"RecoverResponse", &payloads.RecoverResponsePayload{UniqueIdentifier: "obj-recover"}},

		// GetAttributes
		{"GetAttributesRequest", &payloads.GetAttributesRequestPayload{
			UniqueIdentifier: "obj-attrs",
			AttributeName:    []kmip.AttributeName{kmip.AttributeNameName, kmip.AttributeNameObjectType},
		}},
		{"GetAttributesResponse", &payloads.GetAttributesResponsePayload{
			UniqueIdentifier: "obj-attrs",
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "mykey", NameType: kmip.NameTypeUninterpretedTextString}},
			},
		}},

		// GetAttributeList
		{"GetAttributeListRequest", &payloads.GetAttributeListRequestPayload{UniqueIdentifier: "obj-attrlist"}},
		{"GetAttributeListResponse", &payloads.GetAttributeListResponsePayload{
			UniqueIdentifier: "obj-attrlist",
			AttributeName:    []kmip.AttributeName{kmip.AttributeNameName, kmip.AttributeNameObjectType, kmip.AttributeNameState},
		}},

		// AddAttribute
		{"AddAttributeRequest", &payloads.AddAttributeRequestPayload{
			UniqueIdentifier: "obj-addattr",
			Attribute:        kmip.Attribute{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "alias", NameType: kmip.NameTypeUninterpretedTextString}},
		}},
		{"AddAttributeResponse", &payloads.AddAttributeResponsePayload{
			UniqueIdentifier: "obj-addattr",
			Attribute:        kmip.Attribute{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "alias", NameType: kmip.NameTypeUninterpretedTextString}},
		}},

		// ModifyAttribute
		{"ModifyAttributeRequest", &payloads.ModifyAttributeRequestPayload{
			UniqueIdentifier: "obj-modattr",
			Attribute:        kmip.Attribute{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "renamed", NameType: kmip.NameTypeUninterpretedTextString}},
		}},
		{"ModifyAttributeResponse", &payloads.ModifyAttributeResponsePayload{
			UniqueIdentifier: "obj-modattr",
			Attribute:        kmip.Attribute{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "renamed", NameType: kmip.NameTypeUninterpretedTextString}},
		}},

		// DeleteAttribute
		{"DeleteAttributeRequest", &payloads.DeleteAttributeRequestPayload{
			UniqueIdentifier: "obj-delattr",
			AttributeName:    kmip.AttributeNameName,
			AttributeIndex:   int32Ptr(0),
		}},
		{"DeleteAttributeResponse", &payloads.DeleteAttributeResponsePayload{
			UniqueIdentifier: "obj-delattr",
			Attribute:        kmip.Attribute{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "deleted", NameType: kmip.NameTypeUninterpretedTextString}},
		}},

		// ObtainLease
		{"ObtainLeaseRequest", &payloads.ObtainLeaseRequestPayload{UniqueIdentifier: "obj-lease"}},
		{"ObtainLeaseResponse", &payloads.ObtainLeaseResponsePayload{
			UniqueIdentifier: "obj-lease",
			LeaseTime:        3600 * time.Second,
			LastChangeDate:   time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		}},

		// GetUsageAllocation
		{"GetUsageAllocationRequest", &payloads.GetUsageAllocationRequestPayload{
			UniqueIdentifier: "obj-usage",
			UsageLimitsCount: 1000,
		}},
		{"GetUsageAllocationResponse", &payloads.GetUsageAllocationResponsePayload{UniqueIdentifier: "obj-usage"}},

		// Rekey
		{"RekeyRequest", &payloads.RekeyRequestPayload{
			UniqueIdentifier:  "key-rekey",
			Offset:            durationPtr(24 * time.Hour),
			TemplateAttribute: newTemplateAttr(),
		}},
		{"RekeyResponse", &payloads.RekeyResponsePayload{
			UniqueIdentifier:  "key-rekey-new",
			TemplateAttribute: newTemplateAttr(),
		}},

		// RekeyKeyPair
		{"RekeyKeyPairRequest", &payloads.RekeyKeyPairRequestPayload{
			PrivateKeyUniqueIdentifier:  "priv-rekey",
			Offset:                      durationPtr(48 * time.Hour),
			CommonTemplateAttribute:     newTemplateAttr(),
			PrivateKeyTemplateAttribute: newTemplateAttr(),
			PublicKeyTemplateAttribute:  newTemplateAttr(),
		}},
		{"RekeyKeyPairResponse", &payloads.RekeyKeyPairResponsePayload{
			PrivateKeyUniqueIdentifier:  "priv-rekey-new",
			PublicKeyUniqueIdentifier:   "pub-rekey-new",
			PrivateKeyTemplateAttribute: newTemplateAttr(),
			PublicKeyTemplateAttribute:  newTemplateAttr(),
		}},

		// Get
		{"GetRequest", &payloads.GetRequestPayload{
			UniqueIdentifier:   "obj-get",
			KeyFormatType:      kmip.KeyFormatTypeRaw,
			KeyWrapType:        kmip.AsRegistered,
			KeyCompressionType: kmip.KeyCompressionTypeECPublicKeyTypeX9_62CompressedPrime,
			KeyWrappingSpecification: &kmip.KeyWrappingSpecification{
				WrappingMethod: kmip.WrappingMethodMACSignThenEncrypt,
			},
		}},
		{"GetResponse", &payloads.GetResponsePayload{
			ObjectType:       kmip.ObjectTypeSecretData,
			UniqueIdentifier: "obj-get",
			Object:           newSecretData(),
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tag := kmip.TagRequestPayload
			if strings.HasSuffix(tt.name, "Response") {
				tag = kmip.TagResponsePayload
			}

			enc := ttlv.NewTTLVEncoder()
			enc.TagAny(tag, tt.payload)

			decoded := reflect.New(reflect.TypeOf(tt.payload).Elem()).Interface()
			dec, err := ttlv.NewTTLVDecoder(enc.Bytes())
			require.NoError(t, err)
			err = dec.TagAny(tag, decoded)
			require.NoError(t, err)

			normalizeTimesToUTC(reflect.ValueOf(decoded))
			require.EqualValues(t, tt.payload, decoded)
		})
	}
}
