package kmipclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"

	"github.com/stretchr/testify/require"
)

func TestRegister_SecretString(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	secret := "hello world !!!"

	mux.Route(kmip.OperationRegister, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
		require.Equal(t, kmip.ObjectTypeSecretData, pl.ObjectType)
		sec, ok := pl.Object.(*kmip.SecretData)
		require.True(t, ok, "Object is not a secret")
		require.Equal(t, kmip.SecretDataTypePassword, sec.SecretDataType)
		data, err := sec.Data()
		require.NoError(t, err)
		require.EqualValues(t, secret, string(data))
		return &payloads.RegisterResponsePayload{UniqueIdentifier: "foobar"}, nil
	}))

	client.Register().SecretString(kmip.SecretDataTypePassword, secret).MustExec()
}

func TestRegister_PemCertificate(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	client := kmiptest.NewClientAndServer(t, mux)

	caTpl := x509.Certificate{
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SerialNumber: big.NewInt(2),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, &caTpl, &caTpl, k.Public(), k)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	mux.Route(kmip.OperationRegister, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
		require.Equal(t, kmip.ObjectTypeCertificate, pl.ObjectType)
		cert, ok := pl.Object.(*kmip.Certificate)
		require.True(t, ok, "Object is not a certificate")
		require.Equal(t, kmip.CertificateTypeX_509, cert.CertificateType)
		require.EqualValues(t, der, cert.CertificateValue)
		return &payloads.RegisterResponsePayload{UniqueIdentifier: "foobar"}, nil
	}))

	client.Register().PemCertificate(pemBytes).MustExec()
}

func TestRegister_Symmetric(t *testing.T) {
	for _, tc := range []struct {
		kmipFmt kmip.KeyFormatType
		fmt     kmipclient.KeyFormat
	}{
		{kmip.KeyFormatTypeRaw, kmipclient.RAW},
		{kmip.KeyFormatTypeTransparentSymmetricKey, kmipclient.Transparent},
	} {
		t.Run(ttlv.EnumStr(tc.kmipFmt), func(t *testing.T) {
			mux := kmipserver.NewBatchExecutor()
			client := kmiptest.NewClientAndServer(t, mux)

			secret := "hello world !!!"

			mux.Route(kmip.OperationRegister, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
				require.Equal(t, kmip.ObjectTypeSymmetricKey, pl.ObjectType)
				k, ok := pl.Object.(*kmip.SymmetricKey)
				require.True(t, ok, "Object is not a symmetric key")
				require.Equal(t, kmip.CryptographicAlgorithmAES, k.KeyBlock.CryptographicAlgorithm)
				require.Equal(t, tc.kmipFmt, k.KeyBlock.KeyFormatType)
				// pl.TemplateAttribute.
				//TODO: Check attributes name and cryptographic usage mask
				data, err := k.KeyMaterial()
				require.NoError(t, err)
				require.EqualValues(t, secret, string(data))
				return &payloads.RegisterResponsePayload{UniqueIdentifier: "foobar"}, nil
			}))

			client.Register().
				WithKeyFormat(tc.fmt).
				SymmetricKey(kmip.CryptographicAlgorithmAES, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt, []byte(secret)).
				WithName("foo").
				MustExec()
		})
	}
}

func TestRegister_PrivateKey_RSA(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaKey)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(rsaKey)

	for _, tc := range []struct {
		kmipFmt kmip.KeyFormatType
		fmt     kmipclient.KeyFormat
		derKey  []byte
		pemType string
	}{
		{kmip.KeyFormatTypePKCS_1, kmipclient.PKCS1, pkcs1, "RSA PRIVATE KEY"},
		{kmip.KeyFormatTypePKCS_8, kmipclient.PKCS8, pkcs8, "PRIVATE KEY"},
		{kmip.KeyFormatTypeTransparentRSAPrivateKey, kmipclient.Transparent, pkcs8, "PRIVATE KEY"},
	} {
		t.Run(ttlv.EnumStr(tc.kmipFmt), func(t *testing.T) {
			mux := kmipserver.NewBatchExecutor()
			client := kmiptest.NewClientAndServer(t, mux)

			mux.Route(kmip.OperationRegister, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
				require.Equal(t, kmip.ObjectTypePrivateKey, pl.ObjectType)
				k, ok := pl.Object.(*kmip.PrivateKey)
				require.True(t, ok, "Object is not a private key")
				require.Equal(t, kmip.CryptographicAlgorithmRSA, k.KeyBlock.CryptographicAlgorithm)
				require.Equal(t, tc.kmipFmt, k.KeyBlock.KeyFormatType)
				// pl.TemplateAttribute.
				//TODO: Check attributes name and cryptographic usage mask
				data, err := k.RSA()
				require.NoError(t, err)
				require.EqualValues(t, rsaKey, data)
				return &payloads.RegisterResponsePayload{UniqueIdentifier: "foobar"}, nil
			}))

			pemKey := pem.EncodeToMemory(&pem.Block{Type: tc.pemType, Bytes: tc.derKey})

			client.Register().
				WithKeyFormat(tc.fmt).
				PemKey(pemKey, kmip.CryptographicUsageSign).
				WithName("foo").
				MustExec()

			client.Register().
				WithKeyFormat(tc.fmt).
				PrivateKey(rsaKey, kmip.CryptographicUsageSign).
				WithName("foo").
				MustExec()
		})
	}
}

func TestRegister_PrivateKey_ECDSA(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1, _ := x509.MarshalECPrivateKey(ecKey)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(ecKey)

	for _, tc := range []struct {
		kmipFmt kmip.KeyFormatType
		fmt     kmipclient.KeyFormat
		derKey  []byte
		pemType string
	}{
		{kmip.KeyFormatTypeECPrivateKey, kmipclient.SEC1, sec1, "EC PRIVATE KEY"},
		{kmip.KeyFormatTypePKCS_8, kmipclient.PKCS8, pkcs8, "PRIVATE KEY"},
		{kmip.KeyFormatTypeTransparentECPrivateKey, kmipclient.Transparent, pkcs8, "PRIVATE KEY"},
	} {
		t.Run(ttlv.EnumStr(tc.kmipFmt), func(t *testing.T) {
			mux := kmipserver.NewBatchExecutor()
			client := kmiptest.NewClientAndServer(t, mux)

			mux.Route(kmip.OperationRegister, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
				require.Equal(t, kmip.ObjectTypePrivateKey, pl.ObjectType)
				k, ok := pl.Object.(*kmip.PrivateKey)
				require.True(t, ok, "Object is not a private key")
				require.Equal(t, kmip.CryptographicAlgorithmECDSA, k.KeyBlock.CryptographicAlgorithm)
				require.Equal(t, tc.kmipFmt, k.KeyBlock.KeyFormatType)
				// pl.TemplateAttribute.
				//TODO: Check attributes name and cryptographic usage mask
				data, err := k.ECDSA()
				require.NoError(t, err)
				require.EqualValues(t, ecKey, data)
				return &payloads.RegisterResponsePayload{UniqueIdentifier: "foobar"}, nil
			}))

			pemKey := pem.EncodeToMemory(&pem.Block{Type: tc.pemType, Bytes: tc.derKey})

			client.Register().
				WithKeyFormat(tc.fmt).
				PemKey(pemKey, kmip.CryptographicUsageSign).
				WithName("foo").
				MustExec()

			client.Register().
				WithKeyFormat(tc.fmt).
				PrivateKey(ecKey, kmip.CryptographicUsageSign).
				WithName("foo").
				MustExec()
		})
	}
}

func TestRegister_PublicKey_RSA(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs1 := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
	pkix, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)

	for _, tc := range []struct {
		kmipFmt kmip.KeyFormatType
		fmt     kmipclient.KeyFormat
		derKey  []byte
		pemType string
	}{
		{kmip.KeyFormatTypePKCS_1, kmipclient.PKCS1, pkcs1, "RSA PUBLIC KEY"},
		{kmip.KeyFormatTypeX_509, kmipclient.X509, pkix, "PUBLIC KEY"},
		{kmip.KeyFormatTypeTransparentRSAPublicKey, kmipclient.Transparent, pkix, "PUBLIC KEY"},
	} {
		t.Run(ttlv.EnumStr(tc.kmipFmt), func(t *testing.T) {
			mux := kmipserver.NewBatchExecutor()
			client := kmiptest.NewClientAndServer(t, mux)

			mux.Route(kmip.OperationRegister, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
				require.Equal(t, kmip.ObjectTypePublicKey, pl.ObjectType)
				k, ok := pl.Object.(*kmip.PublicKey)
				require.True(t, ok, "Object is not a public key")
				require.Equal(t, kmip.CryptographicAlgorithmRSA, k.KeyBlock.CryptographicAlgorithm)
				require.Equal(t, tc.kmipFmt, k.KeyBlock.KeyFormatType)
				// pl.TemplateAttribute.
				//TODO: Check attributes name and cryptographic usage mask
				data, err := k.RSA()
				require.NoError(t, err)
				require.EqualValues(t, &rsaKey.PublicKey, data)
				return &payloads.RegisterResponsePayload{UniqueIdentifier: "foobar"}, nil
			}))

			pemKey := pem.EncodeToMemory(&pem.Block{Type: tc.pemType, Bytes: tc.derKey})

			client.Register().
				WithKeyFormat(tc.fmt).
				PemKey(pemKey, kmip.CryptographicUsageSign).
				WithName("foo").
				MustExec()

			client.Register().
				WithKeyFormat(tc.fmt).
				PublicKey(&rsaKey.PublicKey, kmip.CryptographicUsageSign).
				WithName("foo").
				MustExec()
		})
	}
}

func TestRegister_PublicKey_ECDSA(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkix, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)

	for _, tc := range []struct {
		kmipFmt kmip.KeyFormatType
		fmt     kmipclient.KeyFormat
		derKey  []byte
		pemType string
	}{
		{kmip.KeyFormatTypeX_509, kmipclient.X509, pkix, "PUBLIC KEY"},
		{kmip.KeyFormatTypeTransparentECPublicKey, kmipclient.Transparent, pkix, "PUBLIC KEY"},
	} {
		t.Run(ttlv.EnumStr(tc.kmipFmt), func(t *testing.T) {
			mux := kmipserver.NewBatchExecutor()
			client := kmiptest.NewClientAndServer(t, mux)

			mux.Route(kmip.OperationRegister, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
				require.Equal(t, kmip.ObjectTypePublicKey, pl.ObjectType)
				k, ok := pl.Object.(*kmip.PublicKey)
				require.True(t, ok, "Object is not a public key")
				require.Equal(t, kmip.CryptographicAlgorithmECDSA, k.KeyBlock.CryptographicAlgorithm)
				require.Equal(t, tc.kmipFmt, k.KeyBlock.KeyFormatType)
				// pl.TemplateAttribute.
				//TODO: Check attributes name and cryptographic usage mask
				data, err := k.ECDSA()
				require.NoError(t, err)
				require.EqualValues(t, &ecKey.PublicKey, data)
				return &payloads.RegisterResponsePayload{UniqueIdentifier: "foobar"}, nil
			}))

			pemKey := pem.EncodeToMemory(&pem.Block{Type: tc.pemType, Bytes: tc.derKey})

			client.Register().
				WithKeyFormat(tc.fmt).
				PemKey(pemKey, kmip.CryptographicUsageSign).
				WithName("foo").
				MustExec()

			client.Register().
				WithKeyFormat(tc.fmt).
				PublicKey(&ecKey.PublicKey, kmip.CryptographicUsageSign).
				WithName("foo").
				MustExec()
		})
	}
}
