package kmip

import "github.com/ovh/kmip-go/ttlv"

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
		"OnlineStorage",
		"ArchivalStorage",
	)
}

// CryptographicUsageMask represents a set of bitmask flags indicating the permitted cryptographic operations
// that can be performed with a cryptographic object, such as encrypt, decrypt, sign, or verify.
// Each bit in the mask corresponds to a specific usage permission as defined by the KMIP specification.
type CryptographicUsageMask int32

const (
	CryptographicUsageSign CryptographicUsageMask = 1 << iota
	CryptographicUsageVerify
	CryptographicUsageEncrypt
	CryptographicUsageDecrypt
	CryptographicUsageWrapKey
	CryptographicUsageUnwrapKey
	CryptographicUsageExport
	CryptographicUsageMACGenerate
	CryptographicUsageDeriveKey
	CryptographicUsageContentCommitment
	CryptographicUsageKeyAgreement
	CryptographicUsageCertificateSign
	CryptographicUsageCRLSign
	CryptographicUsageGenerateCryptogram
	CryptographicUsageValidateCryptogram
	CryptographicUsageTranslateEncrypt
	CryptographicUsageTranslateDecrypt
	CryptographicUsageTranslateWrap
	CryptographicUsageTranslateUnwrap
)

func (mask CryptographicUsageMask) MarshalText() ([]byte, error) {
	return []byte(ttlv.BitmaskStr(mask, " | ")), nil
}

// StorageStatusMask represents a bitmask for storage status flags.
// It is used to indicate various storage states using bitwise operations.
type StorageStatusMask int32

const (
	StorageStatusOnlineStorage StorageStatusMask = 1 << iota
	StorageStatusArchivalStorage
)

func (mask StorageStatusMask) MarshalText() ([]byte, error) {
	return []byte(ttlv.BitmaskStr(mask, " | ")), nil
}
