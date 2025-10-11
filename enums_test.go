package kmip

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ovh/kmip-go/ttlv"
)

func TestEnums(t *testing.T) {

	t.Run("CredentialType", func(t *testing.T) { testEnum[CredentialType](t) })

	t.Run("KeyCompressionType", func(t *testing.T) { testEnum[KeyCompressionType](t) })

	t.Run("KeyFormatType", func(t *testing.T) { testEnum[KeyFormatType](t) })

	t.Run("WrappingMethod", func(t *testing.T) { testEnum[WrappingMethod](t) })

	t.Run("RecommendedCurve", func(t *testing.T) { testEnum[RecommendedCurve](t) })

	t.Run("CertificateType", func(t *testing.T) { testEnum[CertificateType](t) })

	t.Run("DigitalSignatureAlgorithm", func(t *testing.T) { testEnum[DigitalSignatureAlgorithm](t) })

	t.Run("SplitKeyMethod", func(t *testing.T) { testEnum[SplitKeyMethod](t) })

	t.Run("SecretDataType", func(t *testing.T) { testEnum[SecretDataType](t) })

	t.Run("OpaqueDataType", func(t *testing.T) { testEnum[OpaqueDataType](t) })

	t.Run("NameType", func(t *testing.T) { testEnum[NameType](t) })

	t.Run("ObjectType", func(t *testing.T) { testEnum[ObjectType](t) })

	t.Run("CryptographicAlgorithm", func(t *testing.T) { testEnum[CryptographicAlgorithm](t) })

	t.Run("BlockCipherMode", func(t *testing.T) { testEnum[BlockCipherMode](t) })

	t.Run("PaddingMethod", func(t *testing.T) { testEnum[PaddingMethod](t) })

	t.Run("HashingAlgorithm", func(t *testing.T) { testEnum[HashingAlgorithm](t) })

	t.Run("KeyRoleType", func(t *testing.T) { testEnum[KeyRoleType](t) })

	t.Run("State", func(t *testing.T) { testEnum[State](t) })

	t.Run("RevocationReasonCode", func(t *testing.T) { testEnum[RevocationReasonCode](t) })

	t.Run("LinkType", func(t *testing.T) { testEnum[LinkType](t) })

	t.Run("CertificateRequestType", func(t *testing.T) { testEnum[CertificateRequestType](t) })

	t.Run("ValidityIndicator", func(t *testing.T) { testEnum[ValidityIndicator](t) })

	t.Run("QueryFunction", func(t *testing.T) { testEnum[QueryFunction](t) })

	t.Run("CancellationResult", func(t *testing.T) { testEnum[CancellationResult](t) })

	t.Run("PutFunction", func(t *testing.T) { testEnum[PutFunction](t) })

	t.Run("Operation", func(t *testing.T) { testEnum[Operation](t) })

	t.Run("ResultStatus", func(t *testing.T) { testEnum[ResultStatus](t) })

	t.Run("ResultReason", func(t *testing.T) { testEnum[ResultReason](t) })

	t.Run("BatchErrorContinuationOption", func(t *testing.T) { testEnum[BatchErrorContinuationOption](t) })

	t.Run("UsageLimitsUnit", func(t *testing.T) { testEnum[UsageLimitsUnit](t) })

	t.Run("EncodingOption", func(t *testing.T) { testEnum[EncodingOption](t) })

	t.Run("ObjectGroupMember", func(t *testing.T) { testEnum[ObjectGroupMember](t) })

	t.Run("AlternativeNameType", func(t *testing.T) { testEnum[AlternativeNameType](t) })

	t.Run("KeyValueLocationType", func(t *testing.T) { testEnum[KeyValueLocationType](t) })

	t.Run("AttestationType", func(t *testing.T) { testEnum[AttestationType](t) })

	t.Run("RNGAlgorithm", func(t *testing.T) { testEnum[RNGAlgorithm](t) })

	t.Run("DRBGAlgorithm", func(t *testing.T) { testEnum[DRBGAlgorithm](t) })

	t.Run("FIPS186Variation", func(t *testing.T) { testEnum[FIPS186Variation](t) })

	t.Run("ValidationAuthorityType", func(t *testing.T) { testEnum[ValidationAuthorityType](t) })

	t.Run("ValidationType", func(t *testing.T) { testEnum[ValidationType](t) })

	t.Run("ProfileName", func(t *testing.T) { testEnum[ProfileName](t) })

	t.Run("UnwrapMode", func(t *testing.T) { testEnum[UnwrapMode](t) })

	t.Run("DestroyAction", func(t *testing.T) { testEnum[DestroyAction](t) })

	t.Run("ShreddingAlgorithm", func(t *testing.T) { testEnum[ShreddingAlgorithm](t) })

	t.Run("RNGMode", func(t *testing.T) { testEnum[RNGMode](t) })

	t.Run("ClientRegistrationMethod", func(t *testing.T) { testEnum[ClientRegistrationMethod](t) })

	t.Run("MaskGenerator", func(t *testing.T) { testEnum[MaskGenerator](t) })
}

func testEnum[T ~uint32](t *testing.T) {
	test := func(name string, val T) {
		gotName, err := json.Marshal(val)
		if err != nil {
			t.Errorf("Marshal(%d) error: %v", val, err)
			return
		}

		wantName := `"` + name + `"`
		if strings.ContainsRune(wantName, ' ') {
			wantName = strings.ReplaceAll(wantName, " ", "")
		}

		if string(gotName) != wantName && wantName != "\"UnknownValue\"" {
			t.Errorf("Marshal(%d) = %s, want %s", val, gotName, wantName)
			return
		}

		var enum T
		err = json.Unmarshal(gotName, &enum)
		if err != nil {
			t.Fatalf("Unmarshal(%s) error: %v", gotName, err)
		}

		if enum != T(val) {
			t.Errorf("Unmarshal(%s) got %d, want %d", gotName, enum, val)
			return
		}

		err = json.Unmarshal(fmt.Appendf(nil, `"%d"`, val), &enum)
		if err != nil {
			t.Fatalf("Unmarshal(%s) error: %v", gotName, err)
		}

		if enum != T(val) {
			t.Errorf("Unmarshal(%s) got %d, want %d", gotName, enum, val)
			return
		}
	}

	// normal enum
	for val, name := range ttlv.EnumValues[T]() {
		test(name, val)
		test(name+" ", val)
	}

	// abnormal enum
	test("0xFFFFFFFF", T(0xFFFFFFFF))
	test("0xEFFFFFFF", T(0xEFFFFFFF))
	test(" 0xFFFFFFFF ", T(0xFFFFFFFF))
	test("UnknownValue", T(0))
}
