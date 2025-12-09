package kmip_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
)

// Example demonstrates how to establish a connection to a KMIP server,
// create a symmetric key, and use it to encrypt data.
// This shows the basic client setup with TLS certificates.
func Example() {
	// Connect to KMIP server with client certificates
	netExec, err := kmipclient.Dial(
		"your-kmip-server.example.com:5696",
		kmipclient.WithClientCertFiles("client-cert.pem", "client-key.pem"),
		// Optionally specify root CA if needed
		// kmipclient.WithRootCAFile("ca.pem"),
	)
	if err != nil {
		log.Fatal(err)
	}
	client, err := kmipclient.NewClient(
		kmipclient.WithClientNetworkExecutor(netExec),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	fmt.Printf("Connected using KMIP version %s\n", client.Version())

	// Create an AES key
	resp, err := client.Create().
		AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		WithName("My-Encryption-Key").
		ExecContext(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// Create a random Nonce / IV
	iv := make([]byte, kmip.AES_GCM.IVLength)
	_, _ = rand.Read(iv)

	// Build and send an encryption request
	resp2, err := client.Encrypt(resp.UniqueIdentifier).
		WithCryptographicParameters(kmip.AES_GCM).
		WithIvCounterNonce(iv).
		Data([]byte("My secret data")).
		ExecContext(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// Concatenate IV, ciphertext and tag, then display the result
	cipher := append(resp2.IVCounterNonce, resp2.Data...)
	cipher = append(cipher, resp2.AuthenticatedEncryptionTag...)
	fmt.Println("Cipher text:", hex.EncodeToString(cipher))
}
