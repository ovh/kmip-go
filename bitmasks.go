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

type CryptographicUsageMask int32

const (
	Sign CryptographicUsageMask = 1 << iota
	Verify
	Encrypt
	Decrypt
	WrapKey
	UnwrapKey
	Export
	MACGenerate
	DeriveKey
	ContentCommitment
	KeyAgreement
	CertificateSign
	CRLSign
	GenerateCryptogram
	ValidateCryptogram
	TranslateEncrypt
	TranslateDecrypt
	TranslateWrap
	TranslateUnwrap
)

// func (mask CryptographicUsageMask) MarshalText() ([]byte, error) {
// 	return []byte(ttlv.BitmaskString(mask)), nil
// }

type StorageStatusMask int32

const (
	OnlineStorage StorageStatusMask = 1 << iota
	ArchivalStorage
)

// func (mask StorageStatusMask) MarshalText() ([]byte, error) {
// 	return []byte(ttlv.BitmaskString(mask)), nil
// }
