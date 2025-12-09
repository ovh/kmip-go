package kmipclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
)

// Example demonstrates how to establish a connection to a KMIP server.
// This shows the basic client setup with TLS certificates.
func Example() {
	// Connect to KMIP server with client certificates
	client, err := kmipclient.Dial(
		"your-kmip-server.example.com:5696",
		kmipclient.WithClientCertFiles("client-cert.pem", "client-key.pem"),
		// Optionally specify root CA if needed
		// kmipclient.WithRootCAFile("ca.pem"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	fmt.Printf("Connected using KMIP version %s\n", client.Version())
}

// ExampleClient_Create demonstrates creating an AES symmetric key.
// This is the most common operation for creating encryption keys.
func ExampleClient_Create() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Create a 256-bit AES key for encryption and decryption
	resp, err := client.Create().
		AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		WithName("my-aes-key").
		Exec()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Created AES key with ID: %s\n", resp.UniqueIdentifier)
}

// ExampleClient_Create_withAttributes demonstrates creating a key with custom attributes.
func ExampleClient_Create_withAttributes() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Create an AES key with additional security attributes
	resp, err := client.Create().
		AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		WithName("secure-key").
		WithAttribute(kmip.AttributeNameSensitive, true).
		WithAttribute(kmip.AttributeNameExtractable, false).
		WithAttribute(kmip.AttributeNameComment, "Production encryption key").
		WithAttribute("x-custom", "random value").
		Exec()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Created secure AES key with ID: %s\n", resp.UniqueIdentifier)
}

// ExampleClient_Get demonstrates retrieving a symmetric key from the server.
func ExampleClient_Get() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Get a key by its unique identifier
	resp, err := client.Get("key-12345").Exec()
	if err != nil {
		log.Fatal(err)
	}

	key, err := resp.SymmetricKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Key Material:", hex.EncodeToString(key))
}

// ExampleClient_Locate demonstrates searching for keys by attributes.
func ExampleClient_Locate() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Find all AES keys with a specific name
	resp, err := client.Locate().
		WithName("my-aes-key").
		WithAttribute(kmip.AttributeNameCryptographicAlgorithm, kmip.CryptographicAlgorithmAES).
		WithMaxItems(10).
		Exec()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d matching keys\n", len(resp.UniqueIdentifier))
	for _, id := range resp.UniqueIdentifier {
		fmt.Printf("  - %s\n", id)
	}
}

// ExampleClient_Encrypt demonstrates encrypting data with a key.
func ExampleClient_Encrypt() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Create a random Nonce / IV
	iv := make([]byte, kmip.AES_GCM.IVLength)
	_, _ = rand.Read(iv)

	// Encrypt data using an existing key
	plaintext := []byte("Hello, KMIP!")
	resp, err := client.Encrypt("key-12345").
		WithCryptographicParameters(kmip.AES_GCM).
		WithIvCounterNonce(iv). // May be optional depending on the cryptographic parameters used
		Data(plaintext).
		Exec()
	if err != nil {
		log.Fatal(err)
	}

	// Concatenate IV, ciphertext and tag, then display the result
	cipher := append(resp.IVCounterNonce, resp.Data...)
	cipher = append(cipher, resp.AuthenticatedEncryptionTag...)
	fmt.Println("Cipher text:", hex.EncodeToString(cipher))
}

// ExampleClient_Decrypt demonstrates decrypting data with a key.
func ExampleClient_Decrypt() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Decrypt data using an existing key
	resp, err := client.Decrypt("key-12345").
		WithCryptographicParameters(kmip.AES_GCM).
		WithIvCounterNonce([]byte{ /* IV / Nonce data */ }). // May be optional depending on the encryption algorithm used
		WithAuthTag([]byte{ /* Authentication tag */ }).     // May be optional depending on the encryption algorithm used
		Data([]byte{ /* Ciphertext data */ }).
		Exec()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted data: %s\n", string(resp.Data))
}

// ExampleClient_Batch demonstrates executing multiple operations in a single request.
func ExampleClient_Batch() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Create two keys in a single batch request
	resp, err := client.Create().AES(256, kmip.CryptographicUsageEncrypt).WithName("batch-key-1").
		Then(func(client kmipclient.Client) kmipclient.PayloadBuilder {
			return client.Create().AES(256, kmip.CryptographicUsageEncrypt).WithName("batch-key-2")
		}).Then(func(client kmipclient.Client) kmipclient.PayloadBuilder {
		return client.Create().AES(256, kmip.CryptographicUsageEncrypt).WithName("batch-key-3")
	}).
		Exec(kmipclient.OnBatchErr(kmip.BatchErrorContinuationOptionStop))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Created %d keys in batch:\n", len(resp))
	for i, resp := range resp {
		if err := resp.Err(); err != nil {
			log.Fatal(err)
		}
		if createResp, ok := resp.ResponsePayload.(*payloads.CreateResponsePayload); ok {
			fmt.Printf("  Key %d: %s\n", i+1, createResp.UniqueIdentifier)
		}
	}
}

// ExampleClient_CreateKeyPair demonstrates creating an asymmetric key pair.
func ExampleClient_CreateKeyPair() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Create an RSA key pair with separate usage masks for private and public keys
	resp, err := client.CreateKeyPair().
		RSA(2048, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).
		PrivateKey().WithName("rsa-private-key").
		PublicKey().WithName("rsa-public-key").
		Exec()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Created RSA key pair:\n")
	fmt.Printf("  Private Key ID: %s\n", resp.PrivateKeyUniqueIdentifier)
	fmt.Printf("  Public Key ID: %s\n", resp.PublicKeyUniqueIdentifier)
}

// ExampleClient_GetAttributes demonstrates retrieving object attributes.
func ExampleClient_GetAttributes() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Get specific attributes for a key
	resp, err := client.GetAttributes("key-12345",
		kmip.AttributeNameCryptographicAlgorithm,
		kmip.AttributeNameCryptographicLength,
		kmip.AttributeNameState,
	).Exec()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Key attributes:\n")
	for _, attr := range resp.Attribute {
		fmt.Printf("  %s: %v\n", attr.AttributeName, attr.AttributeValue)
	}
}

// ExampleClient_contextUsage demonstrates using context for request cancellation.
func ExampleClient_contextUsage() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Use context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Create().
		AES(256, kmip.CryptographicUsageEncrypt).
		WithName("timeout-key").
		ExecContext(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Created key with timeout: %s\n", resp.UniqueIdentifier)
}

// ExampleClient_Destroy demonstrates destroying a key from the server.
func ExampleClient_Destroy() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Destroy a key by its unique identifier
	resp, err := client.Destroy("key-12345").Exec()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Destroyed key: %s\n", resp.UniqueIdentifier)
}

// ExampleClient_Revoke demonstrates revoking a key.
func ExampleClient_Revoke() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Revoke a key with a specific reason
	resp, err := client.Revoke("key-12345").
		WithRevocationReasonCode(kmip.RevocationReasonCodeKeyCompromise).
		WithRevocationMessage("Key may have been compromised").
		Exec()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Revoked key: %s\n", resp.UniqueIdentifier)
}

// ExampleClient_Locate_byState demonstrates searching for keys by their state.
func ExampleClient_Locate_byState() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Find all active AES keys
	resp, err := client.Locate().
		WithAttribute(kmip.AttributeNameCryptographicAlgorithm, kmip.CryptographicAlgorithmAES).
		WithAttribute(kmip.AttributeNameState, kmip.StateActive).
		WithMaxItems(5).
		Exec()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d active AES keys\n", len(resp.UniqueIdentifier))
}

// ExampleClient_Register_raw demonstrates registering an existing key using low level kmip object
func ExampleClient_Register_raw() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Create a symmetric key object to register
	keyBytes := make([]byte, 32) // 256-bit key
	// In practice, you would fill this with actual key material

	symKey := &kmip.SymmetricKey{
		KeyBlock: kmip.KeyBlock{
			KeyFormatType: kmip.KeyFormatTypeRaw,
			KeyValue: &kmip.KeyValue{
				Plain: &kmip.PlainKeyValue{
					KeyMaterial: kmip.KeyMaterial{
						Bytes: &keyBytes,
					},
				},
			},
			CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
			CryptographicLength:    256,
		},
	}

	// Register the key with attributes
	resp, err := client.Register().
		Object(symKey).
		WithName("imported-key").
		WithAttribute(kmip.AttributeNameCryptographicUsageMask,
			kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		Exec()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Registered key with ID: %s\n", resp.UniqueIdentifier)
}

// ExampleClient_Register_highlevel demonstrates registering an existing key using high-level API
func ExampleClient_Register_highlevel() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Create a symmetric key object to register
	keyBytes := make([]byte, 32) // 256-bit key
	// In practice, you would fill this with actual key material

	// Register the key with attributes
	resp, err := client.Register().
		SymmetricKey(kmip.CryptographicAlgorithmAES, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt, keyBytes).
		WithName("imported-key").
		Exec()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Registered key with ID: %s\n", resp.UniqueIdentifier)
}

// ExampleClient_Register_highlevel demonstrates registering an existing and ECDSA keypair from go's stdlib.
func ExampleClient_Register_ecdsa_keypair() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Create a symmetric key object to register
	pkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	// Register the private key with attributes
	resp, err := client.Register().
		EcdsaPrivateKey(pkey, kmip.CryptographicUsageSign).
		WithName("imported-key").
		Exec()
	if err != nil {
		log.Fatal(err)
	}

	// Register the public key with attributes and a link to the private key
	resp2, err := client.Register().
		EcdsaPublicKey(&pkey.PublicKey, kmip.CryptographicUsageVerify).
		WithName("imported-key").
		WithLink(kmip.LinkTypePrivateKeyLink, resp.UniqueIdentifier).
		Exec()
	if err != nil {
		log.Fatal(err)
	}

	// Link the public key into the private key
	_, err = client.AddAttribute(resp.UniqueIdentifier, kmip.AttributeNameLink, kmip.Link{
		LinkType:               kmip.LinkTypePublicKeyLink,
		LinkedObjectIdentifier: resp2.UniqueIdentifier,
	}).Exec()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Registered key-pair")
}

// ExampleClient_GetAttributeList demonstrates getting all available attributes for a key.
func ExampleClient_GetAttributeList() {
	client, err := kmipclient.Dial("your-kmip-server.example.com:5696")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Get list of all attributes for a key
	resp, err := client.GetAttributeList("key-12345").Exec()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Key has %d attributes:\n", len(resp.AttributeName))
	for _, attrName := range resp.AttributeName {
		fmt.Printf("  - %s\n", attrName)
	}
}
