package kmip

import (
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

	"github.com/ovh/kmip-go/ttlv"

	"github.com/stretchr/testify/require"
)

func TestObjectTypes(t *testing.T) {
	for ot := range objectTypes {
		t.Run(ttlv.EnumStr(ot), func(t *testing.T) {
			obj, err := NewObjectForType(ot)
			require.NoError(t, err)
			require.Equal(t, ot, obj.ObjectType())
		})
	}
	t.Run("invalid", func(t *testing.T) {
		obj, err := NewObjectForType(ObjectType(999))
		require.Error(t, err)
		require.Nil(t, obj)
	})
}

func TestSecretData_Data(t *testing.T) {
	t.Run("raw", func(t *testing.T) {
		data := []byte("foobar")
		secret := SecretData{SecretDataType: Password, KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatRaw,
			KeyValue:      &KeyValue{Plain: &PlainKeyValue{KeyMaterial: KeyMaterial{Bytes: &data}}},
		}}
		s, err := secret.Data()
		require.NoError(t, err)
		require.EqualValues(t, data, s)
	})
	t.Run("opaque", func(t *testing.T) {
		data := []byte("foobar")
		secret := SecretData{SecretDataType: Password, KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatOpaque,
			KeyValue:      &KeyValue{Plain: &PlainKeyValue{KeyMaterial: KeyMaterial{Bytes: &data}}},
		}}
		s, err := secret.Data()
		require.NoError(t, err)
		require.EqualValues(t, data, s)
	})
	t.Run("invalid", func(t *testing.T) {
		data := []byte("foobar")
		secret := SecretData{SecretDataType: Password, KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatPKCS_1,
			KeyValue:      &KeyValue{Plain: &PlainKeyValue{KeyMaterial: KeyMaterial{Bytes: &data}}},
		}}
		s, err := secret.Data()
		require.Error(t, err)
		require.Nil(t, s)
	})
}

func TestCertificate_X509Certificate(t *testing.T) {
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
	t.Run("valid", func(t *testing.T) {
		cert := Certificate{CertificateType: X_509, CertificateValue: der}
		xcert, err := cert.X509Certificate()
		require.NoError(t, err)
		require.EqualValues(t, caTpl.SerialNumber, xcert.SerialNumber)
		require.EqualValues(t, der, xcert.Raw)
		pemData, err := cert.PemCertificate()
		require.NoError(t, err)
		pemBlock, _ := pem.Decode([]byte(pemData))
		require.Equal(t, "CERTIFICATE", pemBlock.Type)
		require.EqualValues(t, der, pemBlock.Bytes)
	})

	t.Run("invalid-data", func(t *testing.T) {
		cert := Certificate{CertificateType: X_509, CertificateValue: []byte{1, 2, 3}}
		xcert, err := cert.X509Certificate()
		require.Error(t, err)
		require.Nil(t, xcert)
		pemData, err := cert.PemCertificate()
		require.Error(t, err)
		require.Empty(t, pemData)
	})

	t.Run("invalid-type", func(t *testing.T) {
		cert := Certificate{CertificateType: PGP, CertificateValue: der}
		xcert, err := cert.X509Certificate()
		require.Error(t, err)
		require.Nil(t, xcert)
		pemData, err := cert.PemCertificate()
		require.Error(t, err)
		require.Empty(t, pemData)
	})
}

func TestSymmetricKey_KeyMaterial(t *testing.T) {
	data := make([]byte, 32)
	_, _ = rand.Read(data)
	t.Run("raw", func(t *testing.T) {
		key := SymmetricKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatRaw,
			KeyValue:      &KeyValue{Plain: &PlainKeyValue{KeyMaterial: KeyMaterial{Bytes: &data}}},
		}}
		mat, err := key.KeyMaterial()
		require.NoError(t, err)
		require.EqualValues(t, data, mat)
	})

	t.Run("transparent", func(t *testing.T) {
		key := SymmetricKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatTransparentSymmetricKey,
			KeyValue:      &KeyValue{Plain: &PlainKeyValue{KeyMaterial: KeyMaterial{TransparentSymmetricKey: &TransparentSymmetricKey{Key: data}}}},
		}}
		mat, err := key.KeyMaterial()
		require.NoError(t, err)
		require.EqualValues(t, data, mat)
	})
	t.Run("transparent-nil", func(t *testing.T) {
		key := SymmetricKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatTransparentSymmetricKey,
			KeyValue:      &KeyValue{Plain: &PlainKeyValue{KeyMaterial: KeyMaterial{TransparentSymmetricKey: nil}}},
		}}
		mat, err := key.KeyMaterial()
		require.Error(t, err)
		require.Nil(t, mat)
	})
	t.Run("transparent-nil-material", func(t *testing.T) {
		key := SymmetricKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatTransparentSymmetricKey,
			KeyValue:      &KeyValue{Plain: nil},
		}}
		mat, err := key.KeyMaterial()
		require.Error(t, err)
		require.Nil(t, mat)
	})
	t.Run("invalid-format", func(t *testing.T) {
		key := SymmetricKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatPKCS_1,
			KeyValue:      &KeyValue{Plain: &PlainKeyValue{KeyMaterial: KeyMaterial{Bytes: &data}}},
		}}
		mat, err := key.KeyMaterial()
		require.Error(t, err)
		require.Nil(t, mat)
	})
}

func TestPublicKey_RSA(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	t.Run("pkcs1", func(t *testing.T) {
		der := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
		pkey := PublicKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatPKCS_1,
			KeyValue: &KeyValue{Plain: &PlainKeyValue{
				KeyMaterial: KeyMaterial{Bytes: &der},
			}},
		}}
		pub, err := pkey.RSA()
		require.NoError(t, err)
		require.EqualValues(t, &rsaKey.PublicKey, pub)
		cryptoKey, err := pkey.CryptoPublicKey()
		require.NoError(t, err)
		require.EqualValues(t, rsaKey.Public(), cryptoKey)
	})

	t.Run("spki", func(t *testing.T) {
		der, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		pkey := PublicKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatX_509,
			KeyValue: &KeyValue{Plain: &PlainKeyValue{
				KeyMaterial: KeyMaterial{Bytes: &der},
			}},
		}}
		pub, err := pkey.RSA()
		require.NoError(t, err)
		require.EqualValues(t, &rsaKey.PublicKey, pub)
		cryptoKey, err := pkey.CryptoPublicKey()
		require.NoError(t, err)
		require.EqualValues(t, rsaKey.Public(), cryptoKey)
	})

	t.Run("transparent", func(t *testing.T) {
		pkey := PublicKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatTransparentRSAPublicKey,
			KeyValue: &KeyValue{Plain: &PlainKeyValue{KeyMaterial: KeyMaterial{TransparentRSAPublicKey: &TransparentRSAPublicKey{
				Modulus:        *rsaKey.N,
				PublicExponent: *big.NewInt(int64(rsaKey.E)),
			}}}},
		}}
		pub, err := pkey.RSA()
		require.NoError(t, err)
		require.EqualValues(t, &rsaKey.PublicKey, pub)
		cryptoKey, err := pkey.CryptoPublicKey()
		require.NoError(t, err)
		require.EqualValues(t, rsaKey.Public(), cryptoKey)
	})
}

func TestPublicKey_ECDSA(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t.Run("spki", func(t *testing.T) {
		der, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
		pkey := PublicKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatX_509,
			KeyValue: &KeyValue{Plain: &PlainKeyValue{
				KeyMaterial: KeyMaterial{Bytes: &der},
			}},
		}}
		pub, err := pkey.ECDSA()
		require.NoError(t, err)
		require.EqualValues(t, &ecKey.PublicKey, pub)
		cryptoKey, err := pkey.CryptoPublicKey()
		require.NoError(t, err)
		require.EqualValues(t, ecKey.Public(), cryptoKey)
	})

	t.Run("transparent-uncompressed", func(t *testing.T) {
		comp := ECPublicKeyTypeUncompressed
		pkey := PublicKey{KeyBlock: KeyBlock{
			KeyFormatType:      KeyFormatTransparentECDSAPublicKey,
			KeyCompressionType: comp,
			KeyValue: &KeyValue{Plain: &PlainKeyValue{KeyMaterial: KeyMaterial{TransparentECDSAPublicKey: &TransparentECDSAPublicKey{
				RecommendedCurve: P_256,
				//nolint:staticcheck // We need this function compute ECDSA public key
				QString: elliptic.Marshal(elliptic.P256(), ecKey.X, ecKey.Y),
			}}}},
		}}
		pub, err := pkey.ECDSA()
		require.NoError(t, err)
		require.EqualValues(t, &ecKey.PublicKey, pub)
		cryptoKey, err := pkey.CryptoPublicKey()
		require.NoError(t, err)
		require.EqualValues(t, ecKey.Public(), cryptoKey)
	})

	t.Run("transparent-compressed-prime", func(t *testing.T) {
		comp := ECPublicKeyTypeX9_62CompressedPrime
		pkey := PublicKey{KeyBlock: KeyBlock{
			KeyFormatType:      KeyFormatTransparentECDSAPublicKey,
			KeyCompressionType: comp,
			KeyValue: &KeyValue{Plain: &PlainKeyValue{KeyMaterial: KeyMaterial{TransparentECDSAPublicKey: &TransparentECDSAPublicKey{
				RecommendedCurve: P_256,
				QString:          elliptic.MarshalCompressed(elliptic.P256(), ecKey.X, ecKey.Y),
			}}}},
		}}
		pub, err := pkey.ECDSA()
		require.NoError(t, err)
		require.EqualValues(t, &ecKey.PublicKey, pub)
		cryptoKey, err := pkey.CryptoPublicKey()
		require.NoError(t, err)
		require.EqualValues(t, ecKey.Public(), cryptoKey)
	})
}

func TestPrivateKey_RSA(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	t.Run("pkcs1", func(t *testing.T) {
		der := x509.MarshalPKCS1PrivateKey(rsaKey)
		pkey := PrivateKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatPKCS_1,
			KeyValue: &KeyValue{Plain: &PlainKeyValue{
				KeyMaterial: KeyMaterial{Bytes: &der},
			}},
		}}
		pub, err := pkey.RSA()
		require.NoError(t, err)
		require.EqualValues(t, rsaKey, pub)
		cryptoKey, err := pkey.CryptoPrivateKey()
		require.NoError(t, err)
		require.EqualValues(t, rsaKey, cryptoKey)
	})

	t.Run("pkcs8", func(t *testing.T) {
		der, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
		pkey := PrivateKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatPKCS_8,
			KeyValue: &KeyValue{Plain: &PlainKeyValue{
				KeyMaterial: KeyMaterial{Bytes: &der},
			}},
		}}
		pub, err := pkey.RSA()
		require.NoError(t, err)
		require.EqualValues(t, rsaKey, pub)
		cryptoKey, err := pkey.CryptoPrivateKey()
		require.NoError(t, err)
		require.EqualValues(t, rsaKey, cryptoKey)
	})

	t.Run("transparent", func(t *testing.T) {
		pkey := PrivateKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatTransparentRSAPrivateKey,
			KeyValue: &KeyValue{Plain: &PlainKeyValue{KeyMaterial: KeyMaterial{TransparentRSAPrivateKey: &TransparentRSAPrivateKey{
				Modulus:         *rsaKey.N,
				PrivateExponent: rsaKey.D,
				PublicExponent:  big.NewInt(int64(rsaKey.E)),
				P:               rsaKey.Primes[0],
				Q:               rsaKey.Primes[1],
				PrimeExponentP:  rsaKey.Precomputed.Dp,
				PrimeExponentQ:  rsaKey.Precomputed.Dq,
				CRTCoefficient:  rsaKey.Precomputed.Qinv,
			}}}},
		}}
		pub, err := pkey.RSA()
		require.NoError(t, err)
		require.EqualValues(t, rsaKey, pub)
		cryptoKey, err := pkey.CryptoPrivateKey()
		require.NoError(t, err)
		require.EqualValues(t, rsaKey, cryptoKey)
	})
}

func TestPrivateKey_ECDSA(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t.Run("pkcs8", func(t *testing.T) {
		der, _ := x509.MarshalPKCS8PrivateKey(ecKey)
		pkey := PrivateKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatPKCS_8,
			KeyValue: &KeyValue{Plain: &PlainKeyValue{
				KeyMaterial: KeyMaterial{Bytes: &der},
			}},
		}}
		pub, err := pkey.ECDSA()
		require.NoError(t, err)
		require.EqualValues(t, ecKey, pub)
		cryptoKey, err := pkey.CryptoPrivateKey()
		require.NoError(t, err)
		require.EqualValues(t, ecKey, cryptoKey)
	})
	t.Run("sec1", func(t *testing.T) {
		der, _ := x509.MarshalECPrivateKey(ecKey)
		pkey := PrivateKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatECPrivateKey,
			KeyValue: &KeyValue{Plain: &PlainKeyValue{
				KeyMaterial: KeyMaterial{Bytes: &der},
			}},
		}}
		pub, err := pkey.ECDSA()
		require.NoError(t, err)
		require.EqualValues(t, ecKey, pub)
		cryptoKey, err := pkey.CryptoPrivateKey()
		require.NoError(t, err)
		require.EqualValues(t, ecKey, cryptoKey)
	})

	t.Run("transparent", func(t *testing.T) {
		pkey := PrivateKey{KeyBlock: KeyBlock{
			KeyFormatType: KeyFormatTransparentECDSAPrivateKey,
			KeyValue: &KeyValue{Plain: &PlainKeyValue{KeyMaterial: KeyMaterial{TransparentECDSAPrivateKey: &TransparentECDSAPrivateKey{
				RecommendedCurve: P_256,
				D:                *ecKey.D,
			}}}},
		}}
		pub, err := pkey.ECDSA()
		require.NoError(t, err)
		require.EqualValues(t, ecKey, pub)
		cryptoKey, err := pkey.CryptoPrivateKey()
		require.NoError(t, err)
		require.EqualValues(t, ecKey, cryptoKey)
	})
}
