package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
)

func test_batch_helper(client kmipclient.Client) {
	resp := client.Create().
		AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		Then(func(client kmipclient.Client) kmipclient.PayloadBuilder {
			return client.Activate("")
		}).
		Then(func(client kmipclient.Client) kmipclient.PayloadBuilder {
			return client.Revoke("").
				WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation)
		}).
		Then(func(client kmipclient.Client) kmipclient.PayloadBuilder {
			return client.Destroy("")
		}).MustExec().
		MustUnwrap()

	fmt.Println(resp[3].(*payloads.DestroyResponsePayload).UniqueIdentifier)
}

func test_encrypt_by_name(client kmipclient.Client) {
	iv := make([]byte, kmip.AES_GCM.IVLength)
	_, _ = rand.Read(iv)

	res := client.Locate().
		WithName("my-encryption-AES-key").
		Then(func(client kmipclient.Client) kmipclient.PayloadBuilder {
			return client.Encrypt("").
				WithCryptographicParameters(kmip.AES_GCM).
				WithIvCounterNonce(iv).
				Data([]byte("My Secret Data"))
		}).
		MustExec(kmipclient.OnBatchErr(kmip.BatchErrorContinuationOptionStop)).
		MustUnwrap()

	pl := res[1].(*payloads.EncryptResponsePayload)
	cipher := append([]byte{}, pl.IVCounterNonce...)
	cipher = append(cipher, pl.Data...)
	cipher = append(cipher, pl.AuthenticatedEncryptionTag...)

	fmt.Println("Key ID:", pl.UniqueIdentifier)
	fmt.Println("Cipher:", base64.StdEncoding.EncodeToString(cipher))

	client.Decrypt(pl.UniqueIdentifier).
		WithCryptographicParameters(kmip.AES_GCM).
		WithAuthTag(pl.AuthenticatedEncryptionTag).
		WithIvCounterNonce(pl.IVCounterNonce).
		Data(pl.Data).
		MustExec()
}
