package main

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
)

func test_sign_verify_rsa(client *kmipclient.Client) {
	data := []byte("foobarbaz")
	cparams := kmip.CryptographicParameters{
		DigitalSignatureAlgorithm: ptrTo(kmip.SHA_256WithRSAEncryptionPKCS_1v1_5),
	}

	key := client.CreateKeyPair().RSA(2048, kmip.Sign, kmip.Verify).
		Common().WithName("Test-Encrypt-RSA").
		WithAttribute(kmip.AttributeNameState, kmip.StateActive).
		MustExec()

	resp := client.Sign(key.PrivateKeyUniqueIdentifier).
		WithCryptographicParameters(cparams).
		Data(data).
		MustExec()

	client.SignatureVerify(key.PublicKeyUniqueIdentifier).
		WithCryptographicParameters(cparams).
		Data(data).
		Signature(*resp.SignatureData).
		MustExec()
}
