package kmip

import (
	"fmt"

	"github.com/ovh/kmip-go/ttlv"
)

var (
	V1_0 = ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 0}
	V1_1 = ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 1}
	V1_2 = ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 2}
	V1_3 = ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 3}
	V1_4 = ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 4}
	V2_0 = ProtocolVersion{ProtocolVersionMajor: 2, ProtocolVersionMinor: 0}
	V2_1 = ProtocolVersion{ProtocolVersionMajor: 2, ProtocolVersionMinor: 1}
	V2_2 = ProtocolVersion{ProtocolVersionMajor: 2, ProtocolVersionMinor: 2}
)

type ProtocolVersion struct {
	ProtocolVersionMajor int32
	ProtocolVersionMinor int32
}

func (v ProtocolVersion) Major() int {
	return int(v.ProtocolVersionMajor)
}

func (v ProtocolVersion) Minor() int {
	return int(v.ProtocolVersionMinor)
}

func (pv ProtocolVersion) String() string {
	return fmt.Sprintf("%d.%d", pv.ProtocolVersionMajor, pv.ProtocolVersionMinor)
}

type CredentialValue struct {
	UserPassword *CredentialValueUserPassword
	Device       *CredentialValueDevice
	Attestation  *CredentialValueAttestation
}

func (cred *CredentialValue) TagEncodeTTLV(e *ttlv.Encoder, tag int) {
	e.TagAny(tag, cred.UserPassword)
	e.TagAny(tag, cred.Device)
	e.TagAny(tag, cred.Attestation)
}

func (cred *CredentialValue) decode(d *ttlv.Decoder, tag int, cType CredentialType) error {
	switch cType {
	case CredentialUsernameAndPassword:
		return d.TagAny(tag, &cred.UserPassword)
	case CredentialDevice:
		return d.TagAny(tag, &cred.Device)
	case CredentialAttestation:
		return d.TagAny(tag, &cred.Attestation)
	}
	return fmt.Errorf("Unsupported credential type %X", cType)
}

type CredentialValueUserPassword struct {
	Username string
	Password *string
}

type CredentialValueDevice struct {
	DeviceSerialNumber *string
	Password           *string
	DeviceIdentifier   *string
	NetworkIdentifier  *string
	MachineIdentifier  *string
	MediaIdentifier    *string
}

type CredentialValueAttestation struct {
	Nonce                  Nonce
	AttestationType        AttestationType
	AttestationMeasurement *[]byte
	AttestationAssertion   *[]byte
}

type Credential struct {
	CredentialType  CredentialType
	CredentialValue CredentialValue
}

func (kb *Credential) TagDecodeTTLV(d *ttlv.Decoder, tag int) error {
	return d.Struct(tag, func(d *ttlv.Decoder) error {
		if err := d.Any(&kb.CredentialType); err != nil {
			return err
		}
		return kb.CredentialValue.decode(d, TagCredentialValue, kb.CredentialType)
	})
}

type Authentication struct {
	Credential Credential
	// Starting from KMIP 1.2, Credential can be repeated
	AdditionalCredential []Credential `ttlv:",version=v1.2.."`
}

type RevocationReason struct {
	RevocationReasonCode RevocationReasonCode `ttlv:",omitempty"`
	RevocationMessage    *string
}

type MessageExtension struct {
	VendorIdentification string
	CriticalityIndicator bool
	VendorExtension      ttlv.Struct
}

type CryptographicParameters struct {
	BlockCipherMode  *BlockCipherMode
	PaddingMethod    *PaddingMethod
	HashingAlgorithm *HashingAlgorithm
	KeyRoleType      *KeyRoleType

	DigitalSignatureAlgorithm *DigitalSignatureAlgorithm `ttlv:",version=v1.2.."`
	CryptographicAlgorithm    *CryptographicAlgorithm    `ttlv:",version=v1.2.."`
	RandomIV                  *bool                      `ttlv:",version=v1.2.."`
	IVLength                  *int32                     `ttlv:",version=v1.2.."`
	TagLength                 *int32                     `ttlv:",version=v1.2.."`
	FixedFieldLength          *int32                     `ttlv:",version=v1.2.."`
	InvocationFieldLength     *int32                     `ttlv:",version=v1.2.."`
	CounterLength             *int32                     `ttlv:",version=v1.2.."`
	InitialCounterValue       *int32                     `ttlv:",version=v1.2.."`

	SaltLength                    *int32            `ttlv:",version=v1.4.."`
	MaskGenerator                 *MaskGenerator    `ttlv:",version=v1.4.."`
	MaskGeneratorHashingAlgorithm *HashingAlgorithm `ttlv:",version=v1.4.."`
	PSource                       *[]byte           `ttlv:",version=v1.4.."`
	TrailerField                  *int32            `ttlv:",version=v1.4.."`
}

type CryptographicDomainParameters struct {
	Qlength          *int32
	RecommendedCurve *RecommendedCurve
}

type KeyWrappingSpecification struct {
	WrappingMethod             WrappingMethod
	EncryptionKeyInformation   *EncryptionKeyInformation
	MACSignatureKeyInformation *MACSignatureKeyInformation
	AttributeName              []AttributeName
	EncodingOption             *EncodingOption `ttlv:",version=v1.1.."`
}

type Link struct {
	LinkType               LinkType `ttlv:",omitempty"`
	LinkedObjectIdentifier string   `ttlv:",omitempty"`
}

type Digest struct {
	HashingAlgorithm HashingAlgorithm
	DigestValue      []byte
	KeyFormatType    *KeyFormatType `ttlv:",version=1.1.."`
}

// Deprecated: deprecated as of kmip 1.1
type CertificateIdentifier struct {
	Issuer       string `ttlv:",omitempty"`
	SerialNumber *string
}

// Deprecated: deprecated as of kmip 1.1
type CertificateSubject struct {
	CertificateSubjectDistinguishedName string `ttlv:",omitempty"`
	CertificateSubjectAlternativeName   []string
}

// Deprecated: deprecated as of kmip 1.1
type CertificateIssuer struct {
	CertificateIssuerDistinguishedName string `ttlv:",omitempty"`
	CertificateIssuerAlternativeName   []string
}

type ApplicationSpecificInformation struct {
	ApplicationNamespace string `ttlv:",omitempty"`
	ApplicationData      string `ttlv:",omitempty"` //TODO: Optional since kmip 1.3, not before
}

type UsageLimits struct {
	UsageLimitsTotal int64
	UsageLimitsCount *int64
	UsageLimitsUnit  UsageLimitsUnit `ttlv:",omitempty"`
}

func (ul UsageLimits) Equals(other *UsageLimits) bool {
	return other != nil &&
		other.UsageLimitsTotal == ul.UsageLimitsTotal &&
		other.UsageLimitsUnit == ul.UsageLimitsUnit &&
		(other.UsageLimitsCount == nil && ul.UsageLimitsCount == nil ||
			*other.UsageLimitsCount == *ul.UsageLimitsCount)
}

// KMIP 1.1

type ExtensionInformation struct {
	ExtensionName string
	ExtensionTag  *int32
	ExtensionType *int32
}

type X_509CertificateIdentifier struct {
	IssuerDistinguishedName []byte `ttlv:",omitempty"`
	CertificateSerialNumber []byte `ttlv:",omitempty"`
}

type X_509CertificateSubject struct {
	SubjectDistinguishedName []byte `ttlv:",omitempty"`
	SubjectAlternativeName   [][]byte
}

type X_509CertificateIssuer struct {
	IssuerDistinguishedName []byte `ttlv:",omitempty"`
	IssuerAlternativeName   [][]byte
}

//KMIP 1.2

type Nonce struct {
	NonceID    []byte
	NonceValue []byte
}

type AlternativeName struct {
	AlternativeNameValue string              `ttlv:",omitempty"`
	AlternativeNameType  AlternativeNameType `ttlv:",omitempty"`
}

type KeyValueLocation struct {
	KeyValueLocationValue string               `ttlv:",omitempty"`
	KeyValueLocationType  KeyValueLocationType `ttlv:",omitempty"`
}

// KMIP 1.3

type RNGParameters struct {
	RNGAlgorithm           RNGAlgorithm `ttlv:",omitempty"`
	CryptographicAlgorithm *CryptographicAlgorithm
	CryptographicLength    *int32
	HashingAlgorithm       *HashingAlgorithm
	DRBGAlgorithm          *DRBGAlgorithm
	RecommendedCurve       *RecommendedCurve
	FIPS186Variation       *FIPS186Variation
	PredictionResistance   *bool
}

type ProfileInformation struct {
	ProfileName ProfileName
	ServerURI   *string
	ServerPort  *int32
}

type ValidationInformation struct {
	ValidationAuthorityType         ValidationAuthorityType
	ValidationAuthorityCountry      *string
	ValidationAuthorityURI          *string
	ValidationVersionMajor          int32
	ValidationVersionMinor          *int32
	ValidationType                  ValidationType
	ValidationLevel                 int32
	ValidationCertificateIdentifier *string
	ValidationCertificateURI        *string
	ValidationVendorURI             *string
	ValidationProfile               []string
}

type CapabilityInformation struct {
	StreamingCapability     *bool
	AsynchronousCapability  *bool
	AttestationCapability   *bool
	BatchUndoCapability     *bool `ttlv:",version=v1.4.."`
	BatchContinueCapability *bool `ttlv:",version=v1.4.."`
	UnwrapMode              *UnwrapMode
	DestroyAction           *DestroyAction
	ShreddingAlgorithm      *ShreddingAlgorithm
	RNGMode                 *RNGMode
}
