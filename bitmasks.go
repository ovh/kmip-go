package kmip

import (
	"strconv"
	"strings"

	"github.com/ovh/kmip-go/ttlv"
)

// init registers the bitmask string representations for CryptographicUsageMask and StorageStatusMask
// with the KMIP TTLV package. This enables human-readable string formatting and parsing for these bitmask types.
func init() {
	ttlv.RegisterBitmask[CryptographicUsageMask](
		TagCryptographicUsageMask,
		"Sign",
		"Verify",
		"Encrypt",
		"Decrypt",
		"WrapKey",
		"UnwrapKey",
		"Export",
		"MACGenerate",
		"MACVerify",
		"DeriveKey",
		"ContentCommitment",
		"KeyAgreement",
		"CertificateSign",
		"CRLSign",
		"GenerateCryptogram",
		"ValidateCryptogram",
		"TranslateEncrypt",
		"TranslateDecrypt",
		"TranslateWrap",
		"TranslateUnwrap",
	)
	ttlv.RegisterBitmask[StorageStatusMask](
		TagStorageStatusMask,
		"OnLineStorage",
		"ArchivalStorage",
	)
}

// CryptographicUsageMask represents a set of bitmask flags indicating the permitted cryptographic operations
// that can be performed with a cryptographic object, such as encrypt, decrypt, sign, or verify.
// Each bit in the mask corresponds to a specific usage permission as defined by the KMIP specification.
// This type is used to restrict or allow certain cryptographic operations on keys and other objects.
type CryptographicUsageMask int32

const (
	// CryptographicUsageSign allows the object to be used for signing operations.
	CryptographicUsageSign CryptographicUsageMask = 1 << iota
	// CryptographicUsageVerify allows the object to be used for signature verification.
	CryptographicUsageVerify
	// CryptographicUsageEncrypt allows the object to be used for encryption.
	CryptographicUsageEncrypt
	// CryptographicUsageDecrypt allows the object to be used for decryption.
	CryptographicUsageDecrypt
	// CryptographicUsageWrapKey allows the object to be used for key wrapping.
	CryptographicUsageWrapKey
	// CryptographicUsageUnwrapKey allows the object to be used for key unwrapping.
	CryptographicUsageUnwrapKey
	// CryptographicUsageExport allows the object to be exported.
	CryptographicUsageExport
	// CryptographicUsageMACGenerate allows the object to be used for MAC generation.
	CryptographicUsageMACGenerate
	// CryptographicUsageMACVerify allows the object to be used for verifying MAC.
	CryptographicUsageMACVerify
	// CryptographicUsageDeriveKey allows the object to be used for key derivation.
	CryptographicUsageDeriveKey
	// CryptographicUsageContentCommitment allows the object to be used for content commitment (non-repudiation).
	CryptographicUsageContentCommitment
	// CryptographicUsageKeyAgreement allows the object to be used for key agreement.
	CryptographicUsageKeyAgreement
	// CryptographicUsageCertificateSign allows the object to be used for certificate signing.
	CryptographicUsageCertificateSign
	// CryptographicUsageCRLSign allows the object to be used for CRL signing.
	CryptographicUsageCRLSign
	// CryptographicUsageGenerateCryptogram allows the object to be used for cryptogram generation.
	CryptographicUsageGenerateCryptogram
	// CryptographicUsageValidateCryptogram allows the object to be used for cryptogram validation.
	CryptographicUsageValidateCryptogram
	// CryptographicUsageTranslateEncrypt allows the object to be used for translation encryption.
	CryptographicUsageTranslateEncrypt
	// CryptographicUsageTranslateDecrypt allows the object to be used for translation decryption.
	CryptographicUsageTranslateDecrypt
	// CryptographicUsageTranslateWrap allows the object to be used for translation wrapping.
	CryptographicUsageTranslateWrap
	// CryptographicUsageTranslateUnwrap allows the object to be used for translation unwrapping.
	CryptographicUsageTranslateUnwrap
)

// MarshalText returns a human-readable string representation of the CryptographicUsageMask.
// The string is a bitwise OR ("|") separated list of enabled usage flags.
// This method never returns an error.
func (mask CryptographicUsageMask) MarshalText() ([]byte, error) {
	return []byte(ttlv.BitmaskStr(mask, " | ")), nil
}

func (mask *CryptographicUsageMask) UnmarshalText(text []byte) error {
	return maskUnmarshalText(mask, TagCryptographicUsageMask, string(text))
}

// StorageStatusMask represents a bitmask for storage status flags.
// It is used to indicate various storage states using bitwise operations.
// Each bit corresponds to a specific storage status as defined by the KMIP specification.
type StorageStatusMask int32

const (
	// StorageStatusOnlineStorage indicates the object is in online storage.
	StorageStatusOnlineStorage StorageStatusMask = 1 << iota
	// StorageStatusArchivalStorage indicates the object is in archival storage.
	StorageStatusArchivalStorage
)

// MarshalText returns a human-readable string representation of the StorageStatusMask.
// The string is a bitwise OR ("|") separated list of enabled storage status flags.
// This method never returns an error.
func (mask StorageStatusMask) MarshalText() ([]byte, error) {
	return []byte(ttlv.BitmaskStr(mask, " | ")), nil
}

func (mask *StorageStatusMask) UnmarshalText(text []byte) error {
	return maskUnmarshalText(mask, TagStorageStatusMask, string(text))
}

func maskUnmarshalText[T ~int32](mask *T, tag int, text string) error {
	var parts []string
	if strings.ContainsRune(text, '|') {
		parts = strings.Split(text, "|")
	} else {
		parts = strings.Fields(text)
	}

	*mask = 0
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var parsed int64
		var err error
		if strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X") {
			parsed, err = strconv.ParseInt(part[2:], 16, 32)
		} else {
			parsed, err = strconv.ParseInt(part, 10, 32)
			if err != nil {
				// Look for the name
				var p int32
				p, err = ttlv.BitmaskByStr(tag, part)
				parsed = int64(p)
			}
		}
		if err != nil {
			return err
		}
		*mask |= T(parsed)
	}
	return nil
}
