package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
)

func test_sign_verify_rsa_pkcs1_15(client *kmipclient.Client) {
	data := []byte("foobarbaz")
	cparams := kmip.CryptographicParameters{
		DigitalSignatureAlgorithm: kmip.DigitalSignatureAlgorithmSHA_256WithRSAEncryptionPKCS_1v1_5,
		// CryptographicAlgorithm: kmip.CryptographicAlgorithmRSA,
		// HashingAlgorithm:       kmip.HashingAlgorithmSHA_256,
		// PaddingMethod:          kmip.PaddingMethodPKCS1V1_5,
	}

	key := client.CreateKeyPair().RSA(2048, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).
		Common().WithName("Test-Sign-RSA-2").
		WithAttribute(kmip.AttributeNameState, kmip.StateActive).
		MustExec()

	resp := client.Sign(key.PrivateKeyUniqueIdentifier).
		WithCryptographicParameters(cparams).
		Data(data).
		MustExec()

	client.SignatureVerify(key.PublicKeyUniqueIdentifier).
		WithCryptographicParameters(cparams).
		Data(data).
		Signature(resp.SignatureData).
		MustExec()
}

func test_sign_verify_rsa_pss(client *kmipclient.Client) {
	data := []byte("foobarbaz")
	cparams := kmip.CryptographicParameters{
		DigitalSignatureAlgorithm: kmip.DigitalSignatureAlgorithmRSASSA_PSSPKCS_1v2_1,
		// CryptographicAlgorithm: kmip.CryptographicAlgorithmRSA,
		HashingAlgorithm: kmip.HashingAlgorithmSHA_256,
		// PaddingMethod:          kmip.PaddingMethodPSS,
	}

	key := client.CreateKeyPair().RSA(2048, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).
		Common().WithName("Test-Sign-RSA-3").
		WithAttribute(kmip.AttributeNameState, kmip.StateActive).
		MustExec()

	resp := client.Sign(key.PrivateKeyUniqueIdentifier).
		WithCryptographicParameters(cparams).
		Data(data).
		MustExec()

	client.SignatureVerify(key.PublicKeyUniqueIdentifier).
		WithCryptographicParameters(cparams).
		Data(data).
		Signature(resp.SignatureData).
		MustExec()
}

func test_sign_verify_ecdsa(client *kmipclient.Client) {
	data := []byte("foobarbaz")
	cparams := kmip.CryptographicParameters{
		DigitalSignatureAlgorithm: kmip.DigitalSignatureAlgorithmECDSAWithSHA256,
	}

	key := client.CreateKeyPair().ECDSA(kmip.RecommendedCurveP_256, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).
		Common().WithName("Test-Sign-ECDSA").
		WithAttribute(kmip.AttributeNameState, kmip.StateActive).
		MustExec()

	resp := client.Sign(key.PrivateKeyUniqueIdentifier).
		WithCryptographicParameters(cparams).
		Data(data).
		MustExec()

	client.SignatureVerify(key.PublicKeyUniqueIdentifier).
		WithCryptographicParameters(cparams).
		Data(data).
		Signature(resp.SignatureData).
		MustExec()
}

func test_crypto_signer_rsa_pkcs1_15(client *kmipclient.Client) {
	key := client.CreateKeyPair().RSA(2048, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).
		Common().WithName("Test-Sign-RSA-4").
		WithAttribute(kmip.AttributeNameState, kmip.StateActive).
		MustExec()

	signer, err := client.Signer(context.Background(), key.PrivateKeyUniqueIdentifier, "")
	if err != nil {
		panic(err)
	}
	data := []byte("hello world")
	digest := sha256.Sum256(data)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		panic(err)
	}
	err = rsa.VerifyPKCS1v15(signer.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], sig)
	if err != nil {
		panic(err)
	}
}

func test_crypto_signer_rsa_pss(client *kmipclient.Client) {
	key := client.CreateKeyPair().RSA(2048, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).
		Common().WithName("Test-Sign-RSA-4").
		WithAttribute(kmip.AttributeNameState, kmip.StateActive).
		MustExec()

	signer, err := client.Signer(context.Background(), "", key.PublicKeyUniqueIdentifier)
	if err != nil {
		panic(err)
	}
	data := []byte("hello world")
	digest := sha256.Sum256(data)
	sig, err := signer.Sign(rand.Reader, digest[:], &rsa.PSSOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}
	err = rsa.VerifyPSS(signer.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], sig, &rsa.PSSOptions{})
	if err != nil {
		panic(err)
	}
}

func test_crypto_signer_ecdsa(client *kmipclient.Client) {
	key := client.CreateKeyPair().ECDSA(kmip.RecommendedCurveP_256, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).
		Common().WithName("Test-Sign-ECDSA").
		WithAttribute(kmip.AttributeNameState, kmip.StateActive).
		MustExec()

	signer, err := client.Signer(context.Background(), key.PrivateKeyUniqueIdentifier, key.PublicKeyUniqueIdentifier)
	if err != nil {
		panic(err)
	}
	data := []byte("hello world")
	digest := sha256.Sum256(data)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		panic(err)
	}
	ok := ecdsa.VerifyASN1(signer.Public().(*ecdsa.PublicKey), digest[:], sig)
	if !ok {
		panic("invalid signature")
	}
}
