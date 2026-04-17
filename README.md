# kmip-go
[![Go Reference](https://pkg.go.dev/badge/github.com/ovh/kmip-go.svg)](https://pkg.go.dev/github.com/ovh/kmip-go) [![license](https://img.shields.io/badge/license-Apache%202.0-red.svg?style=flat)](https://raw.githubusercontent.com/ovh/kmip-go/master/LICENSE) [![test](https://github.com/ovh/kmip-go/actions/workflows/test.yaml/badge.svg)](https://github.com/ovh/kmip-go/actions/workflows/test.yaml) [![Go Report Card](https://goreportcard.com/badge/github.com/ovh/kmip-go)](https://goreportcard.com/report/github.com/ovh/kmip-go)

A comprehensive Go implementation of the Key Management Interoperability Protocol (KMIP), supporting KMIP versions 1.0 through 1.4. This library provides both client and server implementations with full support for cryptographic operations, key lifecycle management, and secure communication.
See [KMIP v1.4 protocol specification](https://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.pdf).

## 🚀 Features

- **Full KMIP Protocol Support**: Implements KMIP v1.0 to v1.4 specifications
- **Complete Client Library**: High-level fluent API with comprehensive operation support
- **Server Implementation**: Production-ready KMIP server components
- **Multiple Encoding Formats**: Binary TTLV, XML, JSON, and human-readable text formats
- **Extensible**: Easily declare user defined KMIP types and extensions
- **Comprehensive Cryptographic Operations**: Key generation, encryption, decryption, signing, verification
- **Flexible Authentication**: Mutual TLS, username/password, device, and attestation-based authentication
- **TLS Security**: Built-in TLS support with client certificate authentication
- **Batch Operations**: Support for batching multiple operations in a single request
- **Middleware System**: Extensible middleware for logging, debugging, and custom functionality
- **Go standard crypto compatible**: Implements crypto.Signer interface and support cryptographic key types from the standard library
- **Production Ready**: Developed and tested against [OVHcloud KMS](https://help.ovhcloud.com/csm/en-ie-kms-quick-start?id=kb_article_view&sysparm_article=KB0063362)

## 📚 Table of Contents

- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Client API](#-client-api)
- [Server API](#️-server-api)
- [Advanced Features](#-advanced-features)
- [Authentication](#-authentication)
- [Examples](#-examples)
- [Implementation Status](#-implementation-status)
- [Contributing](#️-contributing)
- [Troubleshooting](#-troubleshooting)
- [Development](#️-development)
- [License](#-license)
- [Support](#-support)
- [Acknowledgments](#-acknowledgments)

## 📦 Installation

```bash
go get github.com/ovh/kmip-go@latest
```

## 🏃 Quick Start

```go
package main

import (
	"fmt"
	"log"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
)

func main() {
	// Connect to KMIP server
	client, err := kmipclient.Dial(
		"your-kmip-server:5696",
		kmipclient.WithClientCertFiles("cert.pem", "key.pem"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Create an AES key
	resp := client.Create().
		AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		WithName("my-encryption-key").
		MustExec()

	fmt.Printf("Created AES key: %s\n", resp.UniqueIdentifier)

	// Activate the key
	client.Activate(resp.UniqueIdentifier).MustExec()

	// Encrypt some data
	plaintext := []byte("Hello, KMIP!")
	encrypted := client.Encrypt(resp.UniqueIdentifier).
		WithCryptographicParameters(kmip.AES_GCM).
		Data(plaintext).
		MustExec()

	fmt.Printf("Encrypted data length: %d bytes\n", len(encrypted.Data))
}
```

## 🔧 Client API

### Connection and Configuration

```go
import (
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/ttlv"
)

// Connect with comprehensive options
client, err := kmipclient.Dial(
	"eu-west-rbx.okms.ovh.net:5696",

	// TLS Configuration
	kmipclient.WithRootCAFile("ca.pem"),                    // Custom CA certificate
	kmipclient.WithClientCertFiles("cert.pem", "key.pem"), // Client certificates
	kmipclient.WithClientCertPEM(certPEM, keyPEM),         // Client certs from PEM data
	kmipclient.WithServerName("kmip.example.com"),         // Server name for TLS
	kmipclient.WithTlsConfig(tlsConfig),                   // Custom TLS config

	// Protocol Version Configuration
	kmipclient.WithKmipVersions(kmip.V1_4, kmip.V1_3),     // Supported versions
	kmipclient.EnforceVersion(kmip.V1_4),                   // Enforce specific version

	// Message size limit (default: 1 MB, < 0 disables)
	kmipclient.WithMaxMessageSize(2 * 1024 * 1024),         // 2 MB limit

	// Middleware
	kmipclient.WithMiddlewares(
		kmipclient.CorrelationValueMiddleware(uuid.NewString),
		kmipclient.DebugMiddleware(os.Stdout, ttlv.MarshalXML),
		kmipclient.TimeoutMiddleware(30*time.Second),
	),
)
```

### Key Creation and Management

#### Symmetric Keys
```go
// AES Keys
aes128 := client.Create().AES(128, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt)
aes256 := client.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt)

// Other symmetric algorithms
tdes := client.Create().TDES(192, kmip.CryptographicUsageEncrypt)
skipjack := client.Create().Skipjack(kmip.CryptographicUsageEncrypt) // 80-bit key

// With attributes
key := client.Create().
	AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
	WithName("my-encryption-key").
	WithAttribute(kmip.AttributeNameDescription, "Production encryption key").
	WithUsageLimit(1000000, kmip.UsageLimitsUnitByte).
	MustExec()
```

#### Asymmetric Key Pairs
```go
// RSA Key Pairs
rsaKeyPair := client.CreateKeyPair().
	RSA(2048, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).
	WithName("my-rsa-keypair").
	MustExec()

// ECDSA Key Pairs
ecdsaKeyPair := client.CreateKeyPair().
	ECDSA(kmip.RecommendedCurveP_256, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).
	WithName("my-ecdsa-keypair").
	MustExec()

// Access individual keys
fmt.Printf("Private Key ID: %s\n", ecdsaKeyPair.PrivateKeyUniqueIdentifier)
fmt.Printf("Public Key ID: %s\n", ecdsaKeyPair.PublicKeyUniqueIdentifier
```

#### Object Registration
```go
// Register existing cryptographic material
registered := client.Register().
	Object(existingKeyObject).
	WithName("imported-object").
	MustExec()

// Register with specific attributes
cert := client.Register().
	Certificate(kmip.CertificateTypeX_509, x509Cert).
	WithName("server-certificate").
	WithAttribute(kmip.AttributeNameCertificateType, kmip.CertificateTypeX_509).
	MustExec()
```

### Cryptographic Operations

#### Encryption and Decryption
```go
// Basic encryption
plaintext := []byte("sensitive data")
encrypted := client.Encrypt(keyID).
	WithCryptographicParameters(kmip.CryptographicParameters{ /* parameters */ }).
	Data(plaintext).
	MustExec()

// Encryption with specific parameters
encrypted := client.Encrypt(keyID).
	WithCryptographicParameters(kmip.AES_GCM).
	WithIvCounterNonce(iv).
	WithAAD(additionalData).
	Data(plaintext).
	MustExec()

// Decryption
decrypted := client.Decrypt(keyID).
	WithCryptographicParameters(kmip.AES_GCM).
	WithIvCounterNonce(encrypted.IVCounterNonce).
	WithAAD(additionalData).
	WithAuthTag(encrypted.AuthenticatedEncryptionTag).
	Data(encrypted.Data).
	MustExec()

fmt.Printf("Decrypted: %s\n", decrypted.Data)
```

#### Digital Signatures
```go
// Sign data
data := []byte("document to sign")
signature := client.Sign(privateKeyID).
	WithCryptographicParameters(kmip.CryptographicParameters{ /* parameters */ }).
	Data(data).
	MustExec()

// Sign pre-hashed data
hashedData := sha256.Sum256(data)
signature = client.Sign(privateKeyID).
	WithCryptographicParameters(kmip.CryptographicParameters{ /* parameters */ }).
	DigestedData(hashedData[:]).
	MustExec()

// Verify signature
verified := client.SignatureVerify(publicKeyID).
	WithCryptographicParameters(kmip.CryptographicParameters{ /* parameters */ }).
	Data(data).
	Signature(signature.SignatureData).
	MustExec()

fmt.Printf("Signature valid: %t\n", verified.ValidityIndicator == kmip.ValidityIndicatorValid)
```

#### Go crypto.Signer Interface
```go
// Get a crypto.Signer for use with standard Go crypto packages
signer, err := client.Signer(ctx, privateKeyID, publicKeyID)
if err != nil {
	log.Fatal(err)
}

// Use with crypto packages
hash := sha256.Sum256(data)
signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
if err != nil {
	log.Fatal(err)
}

// Use with x509 certificate signing
template := &x509.Certificate{/*...*/}
certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, signer.Public(), signer)
```

### Key Lifecycle Management

#### Key States and Activation
```go
// Activate a key
client.Activate(keyID).MustExec()

// Check key state
attrs := client.GetAttributes(keyID, kmip.AttributeNameState).MustExec()
for _, attr := range attrs.Attribute {
	if attr.AttributeName == kmip.AttributeNameState {
		fmt.Printf("Key state: %v\n", attr.AttributeValue)
	}
}

// Revoke a key
client.Revoke(keyID).
	WithRevocationReasonCode(kmip.RevocationReasonCodeKeyCompromise).
	WithRevocationMessage("Security incident detected").
	MustExec()

// Archive and recover
client.Archive(keyID).MustExec()
client.Recover(keyID).MustExec()

// Destroy key (irreversible)
client.Destroy(keyID).MustExec()
```

#### Attribute Management
```go
// Get all attributes
allAttrs := client.GetAttributes(keyID).MustExec()

// Get specific attributes
specificAttrs := client.GetAttributes(keyID,
	kmip.AttributeNameState,
	kmip.AttributeNameCryptographicUsageMask,
	kmip.AttributeNameCryptographicLength,
).MustExec()

// Get attribute list (names only)
attrList := client.GetAttributeList(keyID).MustExec()

// Add attributes
client.AddAttribute(keyID, kmip.AttributeNameDescription, "Updated description").MustExec()

// Modify attributes
client.ModifyAttribute(keyID, kmip.AttributeNameName, kmip.Name{
	NameType:  kmip.NameTypeUninterpretedTextString,
	NameValue: "updated-key-name",
}).MustExec()

// Delete attributes
client.DeleteAttribute(keyID, kmip.AttributeNameDescription).MustExec()
```

#### Key Discovery
```go
// Find keys by name
keys := client.Locate().
	WithName("production-key").
	MustExec()

// Complex search criteria
keys = client.Locate().
	WithObjectType(kmip.ObjectTypeSymmetricKey).
	WithAttribute(kmip.AttributeNameCryptographicAlgorithm, kmip.CryptographicAlgorithmAES).
	WithAttribute(kmip.AttributeNameCryptographicLength, int32(256)).
	WithUsageLimit(1000000, kmip.UsageLimitsUnitByte).
	MustExec()

for _, keyID := range keys.UniqueIdentifier {
	fmt.Printf("Found key: %s\n", keyID)
}
```

### Batch Operations

```go
// Hight-Level batch builder
result := client.Create().
	AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
	WithName("batch-key").
	Then(func(client *kmipclient.Client) kmipclient.PayloadBuilder {
		// Use ID returned from previous operation
		return client.Activate("")
	}).
	Then(func(client *kmipclient.Client) kmipclient.PayloadBuilder {
		// Use ID returned from previous operation
		return client.GetAttributes("", kmip.AttributeNameState)
	}).
	MustExec()

// Manual batch creation
createReq1 := &payloads.CreateRequestPayload{ /* ... */ }
createReq2 := &payloads.ActivateRequestPayload{ /* ... */ }
activateReq := &payloads.GetAttributesRequestPayload{ /* ... */ }

result, err = client.Batch(ctx, createReq1, createReq2, activateReq)
if err != nil {
	log.Fatal(err)
}

// Process batch results
for i, resp := range result {
	if err := resp.Err(); err != nil {
		fmt.Printf("Operation %d failed: %s - %s\n", i+1, resp.ResultStatus, resp.ResultReason)
		continue
	}
	switch payload := resp.ResponsePayload.(type) {
	case *payloads.CreateResponsePayload:
		fmt.Printf("Created key %d: %s\n", i+1, payload.UniqueIdentifier)
	case *payloads.ActivateResponsePayload:
		fmt.Printf("Activated key: %s\n", payload.UniqueIdentifier)
	}
}
```

### Low-Level Operations

```go
// Direct payload construction for maximum control
request := payloads.CreateRequestPayload{
	ObjectType: kmip.ObjectTypeSymmetricKey,
	TemplateAttribute: kmip.TemplateAttribute{
		Attribute: []kmip.Attribute{
			{
				AttributeName:  kmip.AttributeNameCryptographicAlgorithm,
				AttributeValue: kmip.CryptographicAlgorithmAES,
			},
			{
				AttributeName:  kmip.AttributeNameCryptographicLength,
				AttributeValue: int32(256),
			},
			{
				AttributeName:  kmip.AttributeNameCryptographicUsageMask,
				AttributeValue: kmip.CryptographicUsageEncrypt | kmip.CryptographicUsageDecrypt,
			},
		},
	},
}

// Send request
response, err := client.Request(ctx, &request)
if err != nil {
	log.Fatal(err)
}

keyID := response.(*payloads.CreateResponsePayload).UniqueIdentifier
```

## 🖥️ Server API

```go
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
)

// Implement the RequestHandler interface
type MyKMIPHandler struct {
	// Your key management backend
}

func (h *MyKMIPHandler) HandleRequest(ctx context.Context, req *kmip.RequestMessage) *kmip.ResponseMessage {
	// Process KMIP request and return response
	// Implement your key management logic here
	return &kmip.ResponseMessage{
		Header: kmip.ResponseHeader{
			ProtocolVersion: req.Header.ProtocolVersion,
			BatchCount:      req.Header.BatchCount,
		},
		BatchItem: []kmip.ResponseBatchItem{
			// Process each batch item
		},
	}
}

func main() {
	// Setup TLS
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// Create listener
	listener, err := tls.Listen("tcp", ":5696", tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	// Create and start server
	handler := &MyKMIPHandler{}
	server := kmipserver.NewServer(listener, handler).
		WithMaxMessageSize(2 * 1024 * 1024) // 2 MB limit (default: 1 MB, < 0 disables limit)

	log.Println("Starting KMIP server on :5696")
	if err := server.Serve(); err != nil {
		log.Fatal(err)
	}
}
```

## 🚀 Advanced Features

### Custom Middleware

```go
// Rate limiting middleware
func RateLimitMiddleware(limiter *rate.Limiter) kmipclient.Middleware {
	return func(next kmipclient.Next, ctx context.Context, req *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
		// Wait for rate limit
		if err := limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit exceeded: %w", err)
		}
		return next(ctx, req)
	}
}

// Retry middleware
func RetryMiddleware(maxRetries int) kmipclient.Middleware {
	return func(next kmipclient.Next, ctx context.Context, req *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
		var lastErr error
		for i := 0; i <= maxRetries; i++ {
			resp, err := next(ctx, req)
			if err == nil {
				return resp, nil
			}
			lastErr = err

			// Exponential backoff
			if i < maxRetries {
				backoff := time.Duration(1<<uint(i)) * time.Second
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		}
		return nil, fmt.Errorf("request failed after %d retries: %w", maxRetries, lastErr)
	}
}

// Use middleware
client, err := kmipclient.Dial(
	"server:5696",
	kmipclient.WithMiddlewares(
		RateLimitMiddleware(rate.NewLimiter(10, 1)),
		RetryMiddleware(3),
	),
)
```

### Error Handling Patterns

```go
// Comprehensive error handling
resp, err := client.Create().AES(256, kmip.CryptographicUsageEncrypt).Exec()
if err != nil {
	// Network or connection errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		log.Printf("Network error: %v (timeout: %t, temp: %t)",
			netErr, netErr.Timeout(), netErr.Temporary())
		return
	}

	// TLS errors
	var tlsErr tls.RecordHeaderError
	if errors.As(err, &tlsErr) {
		log.Printf("TLS error: %v", tlsErr)
		return
	}

	// KMIP protocol errors
	log.Printf("KMIP operation failed: %v", err)
	return
}

// Batch operation error handling
results, err := client.Batch(ctx, req1, req2, req3)
if err != nil {
	log.Printf("Batch request failed: %v", err)
	return
}

// Check individual results
for i, result := range results {
	if err := result.Err(); err != nil {
		log.Printf("Operation %d failed: %v", i, err)
		continue
	}

	// Process successful result
	switch payload := result.ResponsePayload.(type) {
	case *payloads.CreateResponsePayload:
		log.Printf("Created key: %s", payload.UniqueIdentifier)
	case *payloads.GetResponsePayload:
		log.Printf("Retrieved object type: %s", payload.ObjectType)
	}
}

// Or check all the batch item responses for error at once
responses, err := results.Unwrap()
if err != nil {
	log.Printf("Batch response has some errors: %v", err)
	return
}

```

### Working with TTLV Encoding

```go
// Marshal to different formats
request := &payloads.CreateRequestPayload{...}

// Binary TTLV (native KMIP format)
binaryData := ttlv.MarshalTTLV(request)

// XML format (human-readable)
xmlData := ttlv.MarshalXML(request)

// JSON format
jsonData := ttlv.MarshalJSON(request)

// Text format (debugging)
textData := ttlv.MarshalText(request)

// Unmarshal from TTLV
var decoded payloads.CreateRequestPayload
err := ttlv.UnmarshalTTLV(binaryData, &decoded)
if err != nil {
	log.Fatal(err)
}
```

## 🔐 Authentication

### Client Certificate Authentication
```go
// From files
client, err := kmipclient.Dial(
	"server:5696",
	kmipclient.WithClientCertFiles("cert.pem", "key.pem"),
)

// From PEM data
client, err := kmipclient.Dial(
	"server:5696",
	kmipclient.WithClientCertPEM(certPEM, keyPEM),
)

// Multiple certificates
client, err := kmipclient.Dial(
	"server:5696",
	kmipclient.WithClientCertFiles("cert1.pem", "key1.pem"),
	kmipclient.WithClientCertFiles("cert2.pem", "key2.pem"),
)
```

### Username/Password Authentication
Can be handled with a custom client middleware which inserts the credentials in the requests headers.

```go
// Basic authentication
auth := kmip.Authentication{
	Credential: kmip.Credential{
		CredentialType: kmip.CredentialTypeUsernameAndPassword,
		CredentialValue: kmip.CredentialValue{
			UserPassword: &kmip.CredentialValueUserPassword{
				Username: "admin",
				Password: "secret",
			},
		},
	},
}

// Add to request headers manually or use middleware
```

### Device Authentication
Can be handled with a custom client middleware which inserts the credentials in the requests headers.

```go
// Device-based authentication
deviceAuth := kmip.Authentication{
	Credential: kmip.Credential{
		CredentialType: kmip.CredentialTypeDevice,
		CredentialValue: kmip.CredentialValue{
			Device: &kmip.CredentialValueDevice{
				DeviceSerialNumber: "SN123456789",
				DeviceIdentifier:   "device-001",
				NetworkIdentifier:  "192.168.1.100",
			},
		},
	},
}
```

## 💡 Examples

For comprehensive examples, see the [examples](./examples) directory:

- **[examples/encrypt_decrypt.go](examples/encrypt_decrypt.go)** - Encryption/decryption workflows
- **[examples/sign_verify.go](examples/sign_verify.go)** - Digital signature operations
- **[examples/batches.go](examples/batches.go)** - Batch processing examples

## 📋 Implementation Status

This library implements the OASIS KMIP (Key Management Interoperability Protocol) specifications:

- [KMIP v1.4 Specification](https://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.pdf)
- [KMIP v1.4 Profiles](https://docs.oasis-open.org/kmip/profiles/v1.4/os/kmip-profiles-v1.4-os.pdf)

> **Legend:**
> * N/A : Not Applicable 
> * ✅ : Fully compatible
> * ❌ : Not implemented
> * 🚧 : Work in progress / Partially compatible
> * 💀 : Deprecated

### Messages
|                      | v1.0 | v1.1 | v1.2 | v1.3 | v1.4 |
| -------------------- | ---- | ---- | ---- | ---- | ---- |
| Request Message      |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Response Message     |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |

### Operations
| Operation            | v1.0 | v1.1 | v1.2 | v1.3 | v1.4 |
| -------------------- | ---- | ---- | ---- | ---- | ---- |
| Create               |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Create Key Pair      |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Register             |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Re-key               |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| DeriveKey            |  ❌  |  ❌  |  ❌  |  ❌  |  ❌  |
| Certify              |  ❌  |  ❌  |  ❌  |  ❌  |  ❌  |
| Re-certify           |  ❌  |  ❌  |  ❌  |  ❌  |  ❌  |
| Locate               |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Check                |  ❌  |  ❌  |  ❌  |  ❌  |  ❌  |
| Get                  |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Get Attributes       |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Get Attribute List   |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Add Attribute        |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Modify Attribute     |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Delete Attribute     |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Obtain Lease         |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Get Usage Allocation |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Activate             |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Revoke               |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Destroy              |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Archive              |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Recover              |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Validate             |  ❌  |  ❌  |  ❌  |  ❌  |  ❌  |
| Query                |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Cancel               |  ❌  |  ❌  |  ❌  |  ❌  |  ❌  |
| Poll                 |  ❌  |  ❌  |  ❌  |  ❌  |  ❌  |
| Notify               |  ❌  |  ❌  |  ❌  |  ❌  |  ❌  |
| Put                  |  ❌  |  ❌  |  ❌  |  ❌  |  ❌  |
| Discover             |  N/A |  ✅  |  ✅  |  ✅  |  ✅  |
| Re-key Key Pair      |  N/A |  ✅  |  ✅  |  ✅  |  ✅  |
| Encrypt              |  N/A |  N/A |  ✅  |  ✅  |  ✅  |
| Decrypt              |  N/A |  N/A |  ✅  |  ✅  |  ✅  |
| Sign                 |  N/A |  N/A |  ✅  |  ✅  |  ✅  |
| Signature Verify     |  N/A |  N/A |  ✅  |  ✅  |  ✅  |
| MAC                  |  N/A |  N/A |  ❌  |  ❌  |  ❌  |
| MAC Verify           |  N/A |  N/A |  ❌  |  ❌  |  ❌  |
| RNG Retrieve         |  N/A |  N/A |  ❌  |  ❌  |  ❌  |
| RNG Seed             |  N/A |  N/A |  ❌  |  ❌  |  ❌  |
| Hash                 |  N/A |  N/A |  ❌  |  ❌  |  ❌  |
| Create Split Key     |  N/A |  N/A |  ❌  |  ❌  |  ❌  |
| Join Split Key       |  N/A |  N/A |  ❌  |  ❌  |  ❌  |
| Export               |  N/A |  N/A |  N/A |  N/A |  ✅  |
| Import               |  N/A |  N/A |  N/A |  N/A |  ✅  |

### Managed Objects
| Object        | v1.0 | v1.1 | v1.2 | v1.3 | v1.4 |
| ------------- | ---- | ---- | ---- | ---- | ---- |
| Certificate   |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Symmetric Key |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Public Key    |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Private Key   |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Split Key     |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Template      |  ✅  |  ✅  |  ✅  |  💀  |  💀  |
| Secret Data   |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Opaque Object |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| PGP Key       |  N/A |  N/A |  ✅  |  ✅  |  ✅  |

### Base Objects
| Object                                   | v1.0 | v1.1 | v1.2 | v1.3 | v1.4 |
| ---------------------------------------- | ---- | ---- | ---- | ---- | ---- |
| Attribute                                |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Credential                               |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Key Block                                |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Key Value                                |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Key Wrapping Data                        |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Key Wrapping Specification               |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Transparent Key Structures               |  🚧  |  🚧  |  🚧  |  🚧  |  🚧  |
| Template-Attribute Structures            |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Extension Information                    |  N/A |  ✅  |  ✅  |  ✅  |  ✅  |
| Data                                     |  N/A |  N/A |  ✅  |  ✅  |  ✅  |
| Data Length                              |  N/A |  N/A |  ❌  |  ❌  |  ❌  |
| Signature Data                           |  N/A |  N/A |  ✅  |  ✅  |  ✅  |
| MAC Data                                 |  N/A |  N/A |  ❌  |  ❌  |  ❌  |
| Nonce                                    |  N/A |  N/A |  ✅  |  ✅  |  ✅  |
| Correlation Value                        |  N/A |  N/A |  N/A |  ✅  |  ✅  |
| Init Indicator                           |  N/A |  N/A |  N/A |  ✅  |  ✅  |
| Final Indicator                          |  N/A |  N/A |  N/A |  ✅  |  ✅  |
| RNG Parameter                            |  N/A |  N/A |  N/A |  ✅  |  ✅  |
| Profile Information                      |  N/A |  N/A |  N/A |  ✅  |  ✅  |
| Validation Information                   |  N/A |  N/A |  N/A |  ✅  |  ✅  |
| Capability Information                   |  N/A |  N/A |  N/A |  ✅  |  ✅  |
| Authenticated Encryption Additional Data |  N/A |  N/A |  N/A |  N/A |  ✅  |
| Authenticated Encryption Tag             |  N/A |  N/A |  N/A |  N/A |  ✅  |

#### Transparent Key Structures
| Object                   | v1.0 | v1.1 | v1.2 | v1.3 | v1.4 |
| ------------------------ | ---- | ---- | ---- | ---- | ---- |
| Symmetric Key            |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| DSA Private/Public Key   |  ❌  |  ❌  |  ❌  |  ❌  |  ❌  |
| RSA Private/Public Key   |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| DH Private/Public Key    |  ❌  |  ❌  |  ❌  |  ❌  |  ❌  |
| ECDSA Private/Public Key |  ✅  |  ✅  |  ✅  |  💀  |  💀  |
| ECDH Private/Public Key  |  ❌  |  ❌  |  ❌  |  💀  |  💀  |
| ECMQV Private/Public     |  ❌  |  ❌  |  ❌  |  💀  |  💀  |
| EC Private/Public        |  N/A |  N/A |  N/A |  ✅  |  ✅  |

### Attributes
| Attribute                        | v1.0 | v1.1 | v1.2 | v1.3 | v1.4 |
| -------------------------------- | ---- | ---- | ---- | ---- | ---- |
| Unique Identifier                |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Name                             |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Object Type                      |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Cryptographic Algorithm          |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Cryptographic Length             |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Cryptographic Parameters         |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Cryptographic Domain Parameters  |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Certificate Type                 |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Certificate Identifier           |  ✅  |  💀  |  💀  |  💀  |  💀  |
| Certificate Subject              |  ✅  |  💀  |  💀  |  💀  |  💀  |
| Certificate Issuer               |  ✅  |  💀  |  💀  |  💀  |  💀  |
| Digest                           |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Operation Policy Name            |  ✅  |  ✅  |  ✅  |  💀  |  💀  |
| Cryptographic Usage Mask         |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Lease Time                       |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Usage Limits                     |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| State                            |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Initial Date                     |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Activation Date                  |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Process Start Date               |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Protect Stop Date                |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Deactivation Date                |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Destroy Date                     |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Compromise Occurrence Date       |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Compromise Date                  |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Revocation Reason                |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Archive Date                     |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Object Group                     |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Link                             |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Application Specific Information |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Contact Information              |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Last Change Date                 |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Custom Attribute                 |  ✅  |  ✅  |  ✅  |  ✅  |  ✅  |
| Certificate Length               |  N/A |  ✅  |  ✅  |  ✅  |  ✅  |
| X.509 Certificate Identifier     |  N/A |  ✅  |  ✅  |  ✅  |  ✅  |
| X.509 Certificate Subject        |  N/A |  ✅  |  ✅  |  ✅  |  ✅  |
| X.509 Certificate Issuer         |  N/A |  ✅  |  ✅  |  ✅  |  ✅  |
| Digital Signature Algorithm      |  N/A |  ✅  |  ✅  |  ✅  |  ✅  |
| Fresh                            |  N/A |  ✅  |  ✅  |  ✅  |  ✅  |
| Alternative Name                 |  N/A |  N/A |  ✅  |  ✅  |  ✅  |
| Key Value Present                |  N/A |  N/A |  ✅  |  ✅  |  ✅  |
| Key Value Location               |  N/A |  N/A |  ✅  |  ✅  |  ✅  |
| Original Creation Date           |  N/A |  N/A |  ✅  |  ✅  |  ✅  |
| Random Number Generator          |  N/A |  N/A |  N/A |  ✅  |  ✅  |
| PKCS#12 Friendly Name            |  N/A |  N/A |  N/A |  N/A |  ✅  |
| Description                      |  N/A |  N/A |  N/A |  N/A |  ✅  |
| Comment                          |  N/A |  N/A |  N/A |  N/A |  ✅  |
| Sensitive                        |  N/A |  N/A |  N/A |  N/A |  ✅  |
| Always Sensitive                 |  N/A |  N/A |  N/A |  N/A |  ✅  |
| Extractable                      |  N/A |  N/A |  N/A |  N/A |  ✅  |
| Never Extractable                |  N/A |  N/A |  N/A |  N/A |  ✅  |

## 🛠️ Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.
In any case, please follow [Contribution Guidelines](CONTRIBUTING.md)

## 🔧 Troubleshooting

### Common Issues

**Connection Problems**
```bash
# Verify server connectivity
telnet your-kmip-server 5696

# Check TLS certificate issues
openssl s_client -connect your-kmip-server:5696 -cert cert.pem -key key.pem
```

**Authentication Failures**
- Ensure client certificates are valid and not expired
- Verify the server accepts your certificate chain
- Check that the username/password credentials are correct, if used
- Verify the certificate key usage allows client authentication

**Protocol Version Issues**
```go
// Force a specific KMIP version
client, err := kmipclient.Dial(
	"server:5696",
	kmipclient.EnforceVersion(kmip.V1_4),
)
```

**Debug Logging**
```go
// Enable debug logging to see TTLV messages
client, err := kmipclient.Dial(
	"server:5696",
	kmipclient.WithMiddlewares(
		kmipclient.DebugMiddleware(os.Stdout, ttlv.MarshalXML),
	),
)
```

## 🛠️ Development

### Building and Testing

```bash
# Clone repository
git clone https://github.com/ovh/kmip-go.git
cd kmip-go

# Install dependencies
go mod download

# Run all tests
go test -race ./...

# Run integration tests (requires KMIP server)
go test -race -tags=integration ./...
```

### Code Quality

```bash
# Format code
go fmt ./...

# Run linter (requires golangci-lint)
golangci-lint run

# Build examples
go build ./examples/...
```

## 📄 License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Go Reference](https://pkg.go.dev/github.com/ovh/kmip-go)
- **Issues**: [GitHub Issues](https://github.com/ovh/kmip-go/issues)
- **OVHcloud KMS**: [Documentation](https://help.ovhcloud.com/csm/en-ie-kms-quick-start?id=kb_article_view&sysparm_article=KB0063362)
- **KMIP Standard**:
	- [KMIP v1.4 Specification](https://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.pdf)
	- [KMIP v1.4 Profiles](https://docs.oasis-open.org/kmip/profiles/v1.4/os/kmip-profiles-v1.4-os.pdf)

## 🙏 Acknowledgments

This library is developed and maintained by **OVHcloud**, with contributions from the open source community. It is designed to work seamlessly with OVHcloud KMS but is compatible with any KMIP-compliant key management system.

---

**Note**: This library is primarily developed and tested against **OVHcloud KMS**. While it aims for full KMIP compliance, some features may work differently with other KMIP implementations. Please report any compatibility issues.
