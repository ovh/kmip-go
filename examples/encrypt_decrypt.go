package main

import (
	"context"
	"crypto/rand"
	"slices"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
)

func test_encrypt_decrypt_aes(client *kmipclient.Client) {
	iv := []byte("abcdefghijkl")
	plain := []byte("Hello World!")
	aad := []byte("toto")

	keyId := client.Create().
		AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		MustExec().
		UniqueIdentifier

	client.Activate(keyId).MustExec()

	resp := client.Encrypt(keyId).
		WithIvCounterNonce(iv).
		WithAAD(aad).
		WithCryptographicParameters(kmip.CryptographicParameters{
			CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
			BlockCipherMode:        kmip.BlockCipherModeGCM,
		}).
		Data(plain).
		MustExec()

	client.Decrypt(keyId).
		WithIvCounterNonce(iv).
		WithAAD(aad).
		WithCryptographicParameters(kmip.CryptographicParameters{
			CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
			BlockCipherMode:        kmip.BlockCipherModeGCM,
		}).
		WithAuthTag(resp.AuthenticatedEncryptionTag).
		Data(resp.Data).
		MustExec()
}

func test_encrypt_decrypt_aes_default(client *kmipclient.Client) {
	plain := []byte("Hello World!")
	aad := []byte("toto")

	keyId := client.Create().
		AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		WithAttribute(kmip.AttributeNameCryptographicParameters, kmip.CryptographicParameters{
			CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
			BlockCipherMode:        kmip.BlockCipherModeGCM,
			RandomIV:               ptrTo(true),
		}).
		MustExec().
		UniqueIdentifier

	client.Activate(keyId).MustExec()

	resp := client.Encrypt(keyId).
		WithAAD(aad).
		Data(plain).
		MustExec()

	client.Decrypt(keyId).
		WithIvCounterNonce(resp.IVCounterNonce).
		WithAAD(aad).
		WithAuthTag(resp.AuthenticatedEncryptionTag).
		Data(resp.Data).
		MustExec()
}

func test_encrypt_encrypt_aes_cbc_pkcs5(client *kmipclient.Client) {
	keyId := client.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		WithName("Test-Encrypt-CBC").
		MustExec().
		UniqueIdentifier

	client.Activate(keyId).MustExec()

	iv := make([]byte, 16)
	_, _ = rand.Reader.Read(iv)

	respPl, err := client.Request(context.Background(), &payloads.EncryptRequestPayload{
		UniqueIdentifier: keyId,
		Data:             []byte("Hello World!"),
		CryptographicParameters: &kmip.CryptographicParameters{
			CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
			BlockCipherMode:        kmip.BlockCipherModeCBC,
			PaddingMethod:          kmip.PaddingMethodPKCS5,
		},
		IVCounterNonce: iv,
	})
	if err != nil {
		panic(err)
	}
	resp := respPl.(*payloads.EncryptResponsePayload)

	respD, err := client.Request(context.Background(), &payloads.DecryptRequestPayload{
		UniqueIdentifier: keyId,
		Data:             resp.Data,
		CryptographicParameters: &kmip.CryptographicParameters{
			CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
			BlockCipherMode:        kmip.BlockCipherModeCBC,
			PaddingMethod:          kmip.PaddingMethodPKCS5,
		},
		IVCounterNonce: resp.IVCounterNonce,
	})
	if err != nil {
		panic(err)
	}
	if !slices.Equal(respD.(*payloads.DecryptResponsePayload).Data, []byte("Hello World!")) {
		panic("unexpected decryption output")
	}
}

func test_encrypt_decrypt_rsa_oaep(client *kmipclient.Client) {
	key := client.CreateKeyPair().RSA(2048, kmip.CryptographicUsageDecrypt, kmip.CryptographicUsageEncrypt).
		Common().
		WithAttribute(kmip.AttributeNameState, kmip.StateActive).
		MustExec()

	respPl, err := client.Request(context.Background(), &payloads.EncryptRequestPayload{
		UniqueIdentifier: key.PublicKeyUniqueIdentifier,
		Data:             []byte("Hello World!"),
		CryptographicParameters: &kmip.CryptographicParameters{
			CryptographicAlgorithm: kmip.CryptographicAlgorithmRSA,
			PaddingMethod:          kmip.PaddingMethodOAEP,
			HashingAlgorithm:       kmip.HashingAlgorithmSHA_256,
		},
	})
	if err != nil {
		panic(err)
	}
	resp := respPl.(*payloads.EncryptResponsePayload)

	_, err = client.Request(context.Background(), &payloads.DecryptRequestPayload{
		UniqueIdentifier: key.PrivateKeyUniqueIdentifier,
		Data:             resp.Data,
		CryptographicParameters: &kmip.CryptographicParameters{
			CryptographicAlgorithm: kmip.CryptographicAlgorithmRSA,
			PaddingMethod:          kmip.PaddingMethodOAEP,
			HashingAlgorithm:       kmip.HashingAlgorithmSHA_256,
		},
	})
	if err != nil {
		panic(err)
	}
}

func test_encrypt_decrypt_rsa_pkcs1(client *kmipclient.Client) {
	key := client.CreateKeyPair().RSA(2048, kmip.CryptographicUsageDecrypt, kmip.CryptographicUsageEncrypt).
		Common().
		WithAttribute(kmip.AttributeNameState, kmip.StateActive).
		MustExec()

	respPl, err := client.Request(context.Background(), &payloads.EncryptRequestPayload{
		UniqueIdentifier: key.PublicKeyUniqueIdentifier,
		Data:             []byte("Hello World!"),
		CryptographicParameters: &kmip.CryptographicParameters{
			CryptographicAlgorithm: kmip.CryptographicAlgorithmRSA,
			PaddingMethod:          kmip.PaddingMethodPKCS1V1_5,
		},
	})
	if err != nil {
		panic(err)
	}
	resp := respPl.(*payloads.EncryptResponsePayload)

	_, err = client.Request(context.Background(), &payloads.DecryptRequestPayload{
		UniqueIdentifier: key.PrivateKeyUniqueIdentifier,
		Data:             resp.Data,
		CryptographicParameters: &kmip.CryptographicParameters{
			CryptographicAlgorithm: kmip.CryptographicAlgorithmRSA,
			PaddingMethod:          kmip.PaddingMethodPKCS1V1_5,
		},
	})
	if err != nil {
		panic(err)
	}
}

func test_encrypt_decrypt_aes_with_usage(client *kmipclient.Client) {
	keyId := client.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		WithUsageLimit(1, kmip.UsageLimitsUnitByte).
		MustExec().
		UniqueIdentifier

	client.Activate(keyId).MustExec()

	respPl, err := client.Request(context.Background(), &payloads.EncryptRequestPayload{
		UniqueIdentifier: keyId,
		Data:             []byte("Hello World!"),
		CryptographicParameters: &kmip.CryptographicParameters{
			CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
			BlockCipherMode:        kmip.BlockCipherModeGCM,
		},
		IVCounterNonce:                        []byte("abcdefghijkl"),
		AuthenticatedEncryptionAdditionalData: []byte("toto"),
	})
	if err != nil {
		panic(err)
	}
	resp := respPl.(*payloads.EncryptResponsePayload)

	_, err = client.Request(context.Background(), &payloads.DecryptRequestPayload{
		UniqueIdentifier: keyId,
		Data:             resp.Data,
		CryptographicParameters: &kmip.CryptographicParameters{
			CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
			BlockCipherMode:        kmip.BlockCipherModeGCM,
		},
		IVCounterNonce:                        resp.IVCounterNonce,
		AuthenticatedEncryptionTag:            resp.AuthenticatedEncryptionTag,
		AuthenticatedEncryptionAdditionalData: []byte("toto"),
	})
	if err != nil {
		panic(err)
	}
}
