package kmipclient

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

// Register initializes the registration process for a KMIP object.
// Returns an ExecRegisterWantType which can be used to specify the type of object to register.
//
// Returns:
//   - ExecRegisterWantType: Used to configure and execute the register operation.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecRegister.
func (c *Client) Register() ExecRegisterWantType {
	return ExecRegisterWantType{
		client: c,
	}
}

// ExecRegister is a specialized executor for handling KMIP Register operations.
// It embeds the generic AttributeExecutor with request and response payload types specific to
// the Register KMIP operation, facilitating the execution and management of register requests and their responses.
//
// Usage:
//
//	exec := client.Register().WithKeyFormat(...).Object(...)
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the register operation if the object is invalid,
//     the server rejects the operation, or the key format is not supported.
type ExecRegister struct {
	AttributeExecutor[*payloads.RegisterRequestPayload, *payloads.RegisterResponsePayload, ExecRegister]
}

// ExecRegisterWantType represents the desired type for the register operation.
// It allows setting the key format and specifying the object to register.
type ExecRegisterWantType struct {
	client    *Client
	keyFormat KeyFormat
}

// error sets an error for the register operation and returns an ExecRegister with the error set.
func (ex ExecRegisterWantType) error(err error) ExecRegister {
	exec := ExecRegister{
		AttributeExecutor[*payloads.RegisterRequestPayload, *payloads.RegisterResponsePayload, ExecRegister]{
			Executor[*payloads.RegisterRequestPayload, *payloads.RegisterResponsePayload]{
				req: &payloads.RegisterRequestPayload{},
				err: err,
			},
			func(rrp **payloads.RegisterRequestPayload) *[]kmip.Attribute {
				return &(*rrp).TemplateAttribute.Attribute
			},
			func(ae AttributeExecutor[*payloads.RegisterRequestPayload, *payloads.RegisterResponsePayload, ExecRegister]) ExecRegister {
				return ExecRegister{ae}
			},
		},
	}
	return exec
}

// WithKeyFormat sets the key format for the register operation.
// Returns an ExecRegisterWantType with the specified key format.
func (ex ExecRegisterWantType) WithKeyFormat(format KeyFormat) ExecRegisterWantType {
	ex.keyFormat = format
	return ex
}

// Object registers a KMIP object and returns an ExecRegister with the specified object set.
func (ex ExecRegisterWantType) Object(value kmip.Object) ExecRegister {
	exec := ExecRegister{
		AttributeExecutor[*payloads.RegisterRequestPayload, *payloads.RegisterResponsePayload, ExecRegister]{
			Executor[*payloads.RegisterRequestPayload, *payloads.RegisterResponsePayload]{
				client: ex.client,
				req: &payloads.RegisterRequestPayload{
					ObjectType: value.ObjectType(),
					Object:     value,
				},
			},
			func(rrp **payloads.RegisterRequestPayload) *[]kmip.Attribute {
				return &(*rrp).TemplateAttribute.Attribute
			},
			func(ae AttributeExecutor[*payloads.RegisterRequestPayload, *payloads.RegisterResponsePayload, ExecRegister]) ExecRegister {
				return ExecRegister{ae}
			},
		},
	}
	return exec
}

// SecretString registers a secret string as a KMIP SecretData object.
// Returns an ExecRegister with the specified secret string set.
func (ex ExecRegisterWantType) SecretString(kind kmip.SecretDataType, value string) ExecRegister {
	return ex.Secret(kind, []byte(value))
}

// Secret registers a secret as a KMIP SecretData object.
// Returns an ExecRegister with the specified secret set.
func (ex ExecRegisterWantType) Secret(kind kmip.SecretDataType, value []byte) ExecRegister {
	return ex.Object(&kmip.SecretData{
		SecretDataType: kind,
		KeyBlock: kmip.KeyBlock{
			KeyFormatType: kmip.KeyFormatTypeRaw,
			KeyValue: &kmip.KeyValue{
				Plain: &kmip.PlainKeyValue{
					KeyMaterial: kmip.KeyMaterial{Bytes: &value},
				},
			},
		},
	})
}

// Certificate registers a certificate as a KMIP Certificate object.
// Returns an ExecRegister with the specified certificate set.
func (ex ExecRegisterWantType) Certificate(kind kmip.CertificateType, value []byte) ExecRegister {
	return ex.Object(&kmip.Certificate{
		CertificateType:  kind,
		CertificateValue: value,
	})
}

// PemCertificate registers a PEM encoded certificate.
// Returns an ExecRegister with the specified PEM certificate set.
// If the PEM data is invalid or not a certificate, it returns an error.
func (ex ExecRegisterWantType) PemCertificate(data []byte) ExecRegister {
	block, _ := pem.Decode(data)
	if block == nil {
		return ex.error(fmt.Errorf("Invalid PEM data provided"))
	}
	if block.Type != "CERTIFICATE" {
		return ex.error(fmt.Errorf("Not a certificate"))
	}
	return ex.Certificate(kmip.CertificateTypeX_509, block.Bytes)
}

// X509Certificate registers an X.509 certificate.
// Returns an ExecRegister with the specified X.509 certificate set.
func (ex ExecRegisterWantType) X509Certificate(cert *x509.Certificate) ExecRegister {
	return ex.Certificate(kmip.CertificateTypeX_509, cert.Raw)
}

// SymmetricKey registers a symmetric key.
// Returns an ExecRegister with the specified symmetric key set.
// Panics if the key format is unexpected or the key length is invalid.
func (ex ExecRegisterWantType) SymmetricKey(alg kmip.CryptographicAlgorithm, usage kmip.CryptographicUsageMask, value []byte) ExecRegister {
	bitLen := len(value) * 8
	if bitLen > math.MaxInt32 {
		return ex.error(fmt.Errorf("Invalid key length: %d", bitLen))
	}
	var keyFmt kmip.KeyFormatType
	var material kmip.KeyMaterial

	switch ex.keyFormat.symmetricFormat() {
	case RAW:
		keyFmt = kmip.KeyFormatTypeRaw
		material = kmip.KeyMaterial{
			Bytes: &value,
		}
	case Transparent:
		keyFmt = kmip.KeyFormatTypeTransparentSymmetricKey
		material = kmip.KeyMaterial{
			TransparentSymmetricKey: &kmip.TransparentSymmetricKey{
				Key: value,
			},
		}
	default:
		panic("Unexpected key format")
	}
	return ex.Object(&kmip.SymmetricKey{
		KeyBlock: kmip.KeyBlock{
			KeyFormatType:          keyFmt,
			CryptographicAlgorithm: alg,
			//nolint:gosec // integer bounds are checked above
			CryptographicLength: int32(bitLen),
			KeyValue: &kmip.KeyValue{
				Plain: &kmip.PlainKeyValue{
					KeyMaterial: material,
				},
			},
		},
	}).WithAttribute(kmip.AttributeNameCryptographicUsageMask, usage)
}

// rawKeyBytes registers raw key bytes as a KMIP key object.
// Returns an ExecRegister with the specified raw key bytes set.
func (ex ExecRegisterWantType) rawKeyBytes(private bool, der []byte, alg kmip.CryptographicAlgorithm, bitlen int32, format kmip.KeyFormatType, usage kmip.CryptographicUsageMask) ExecRegister {
	kb := kmip.KeyBlock{
		CryptographicAlgorithm: alg,
		KeyFormatType:          format,
		CryptographicLength:    bitlen,
		KeyValue: &kmip.KeyValue{
			Plain: &kmip.PlainKeyValue{
				KeyMaterial: kmip.KeyMaterial{
					Bytes: &der,
				},
			},
		},
	}
	var pkey kmip.Object
	if private {
		pkey = &kmip.PrivateKey{KeyBlock: kb}
	} else {
		pkey = &kmip.PublicKey{KeyBlock: kb}
	}
	return ex.Object(pkey).WithAttribute(kmip.AttributeNameCryptographicUsageMask, usage)
}

// PemKey registers a key from PEM data.
// Returns an ExecRegister with the specified PEM key set.
// If the PEM data is invalid or unsupported, it returns an error.
func (ex ExecRegisterWantType) PemKey(data []byte, usage kmip.CryptographicUsageMask) ExecRegister {
	block, _ := pem.Decode(data)
	if block == nil {
		return ex.error(fmt.Errorf("Invalid PEM data provider"))
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return ex.Pkcs1PrivateKey(block.Bytes, usage)
	case "EC PRIVATE KEY":
		return ex.Sec1PrivateKey(block.Bytes, usage)
	case "PRIVATE KEY":
		return ex.Pkcs8PrivateKey(block.Bytes, usage)
	case "RSA PUBLIC KEY":
		return ex.Pkcs1PublicKey(block.Bytes, usage)
	case "PUBLIC KEY":
		return ex.X509PublicKey(block.Bytes, usage)
	// case "CERTIFICATE":
	default:
		return ex.error(fmt.Errorf("Unsupported PEM type %q", block.Type))
	}
}

// PemPublicKey registers a public key from PEM data. It also accepts PEM encoded private keys but will
// register only the public key part of it. Returns an ExecRegister with the specified PEM public key set.
// If the PEM data is invalid or unsupported, it returns an error.
func (ex ExecRegisterWantType) PemPublicKey(data []byte, usage kmip.CryptographicUsageMask) ExecRegister {
	block, _ := pem.Decode(data)
	if block == nil {
		return ex.error(fmt.Errorf("Invalid PEM data provider"))
	}
	switch block.Type {
	case "RSA PUBLIC KEY":
		return ex.Pkcs1PublicKey(block.Bytes, usage)
	case "PUBLIC KEY":
		return ex.X509PublicKey(block.Bytes, usage)
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return ex.error(err)
		}
		return ex.RsaPublicKey(&key.PublicKey, usage)
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return ex.error(err)
		}
		return ex.EcdsaPublicKey(&key.PublicKey, usage)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return ex.error(err)
		}
		pk := key.(interface{ Public() crypto.PublicKey })
		return ex.PublicKey(pk.Public(), usage)
	default:
		return ex.error(fmt.Errorf("Unsupported PEM type %q", block.Type))
	}
}

// PemPrivateKey registers a private key from PEM data.
// Returns an ExecRegister with the specified PEM private key set.
// If the PEM data is invalid or unsupported, it returns an error.
func (ex ExecRegisterWantType) PemPrivateKey(data []byte, usage kmip.CryptographicUsageMask) ExecRegister {
	block, _ := pem.Decode(data)
	if block == nil {
		return ex.error(fmt.Errorf("Invalid PEM data provider"))
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return ex.Pkcs1PrivateKey(block.Bytes, usage)
	case "EC PRIVATE KEY":
		return ex.Sec1PrivateKey(block.Bytes, usage)
	case "PRIVATE KEY":
		return ex.Pkcs8PrivateKey(block.Bytes, usage)
	default:
		return ex.error(fmt.Errorf("Unsupported PEM type %q", block.Type))
	}
}

// Pkcs1PrivateKey registers a PKCS#1 private key.
// Returns an ExecRegister with the specified PKCS#1 private key set.
// If the DER data is invalid, it returns an error.
func (ex ExecRegisterWantType) Pkcs1PrivateKey(der []byte, usage kmip.CryptographicUsageMask) ExecRegister {
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return ex.error(err)
	}
	return ex.RsaPrivateKey(key, usage)
}

// Pkcs1PublicKey registers a PKCS#1 public key.
// Returns an ExecRegister with the specified PKCS#1 public key set.
// If the DER data is invalid, it returns an error.
func (ex ExecRegisterWantType) Pkcs1PublicKey(der []byte, usage kmip.CryptographicUsageMask) ExecRegister {
	key, err := x509.ParsePKCS1PublicKey(der)
	if err != nil {
		return ex.error(err)
	}
	return ex.RsaPublicKey(key, usage)
}

// Pkcs8PrivateKey registers a PKCS#8 private key.
// Returns an ExecRegister with the specified PKCS#8 private key set.
// If the DER data is invalid or the key type is unsupported, it returns an error.
func (ex ExecRegisterWantType) Pkcs8PrivateKey(der []byte, usage kmip.CryptographicUsageMask) ExecRegister {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return ex.error(err)
	}
	switch pkey := key.(type) {
	case *rsa.PrivateKey:
		return ex.RsaPrivateKey(pkey, usage)
	case *ecdsa.PrivateKey:
		return ex.EcdsaPrivateKey(pkey, usage)
	default:
		return ex.error(fmt.Errorf("Unsuported private key type %T", pkey))
	}
}

// Sec1PrivateKey registers a SEC1 private key.
// Returns an ExecRegister with the specified SEC1 private key set.
// If the DER data is invalid, it returns an error.
func (ex ExecRegisterWantType) Sec1PrivateKey(der []byte, usage kmip.CryptographicUsageMask) ExecRegister {
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return ex.error(err)
	}
	return ex.EcdsaPrivateKey(key, usage)
}

// X509PublicKey registers an X.509 public key.
// Returns an ExecRegister with the specified X.509 public key set.
// If the DER data is invalid or the key type is unsupported, it returns an error.
func (ex ExecRegisterWantType) X509PublicKey(der []byte, usage kmip.CryptographicUsageMask) ExecRegister {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return ex.error(err)
	}
	switch pkey := key.(type) {
	case *rsa.PublicKey:
		return ex.RsaPublicKey(pkey, usage)
	case *ecdsa.PublicKey:
		return ex.EcdsaPublicKey(pkey, usage)
	default:
		return ex.error(fmt.Errorf("Unsuported private key type %T", pkey))
	}
}

// PrivateKey registers a private key (RSA or ECDSA).
// Returns an ExecRegister with the specified private key set.
// If the key type is unsupported, it returns an error.
func (ex ExecRegisterWantType) PrivateKey(key crypto.PrivateKey, usage kmip.CryptographicUsageMask) ExecRegister {
	switch pk := key.(type) {
	case *rsa.PrivateKey:
		return ex.RsaPrivateKey(pk, usage)
	case *ecdsa.PrivateKey:
		return ex.EcdsaPrivateKey(pk, usage)
	default:
		return ex.error(fmt.Errorf("Unsupported key type: %T", pk))
	}
}

// PublicKey registers a public key (RSA or ECDSA).
// Returns an ExecRegister with the specified public key set.
// If the key type is unsupported, it returns an error.
func (ex ExecRegisterWantType) PublicKey(key crypto.PublicKey, usage kmip.CryptographicUsageMask) ExecRegister {
	switch pk := key.(type) {
	case *rsa.PublicKey:
		return ex.RsaPublicKey(pk, usage)
	case *ecdsa.PublicKey:
		return ex.EcdsaPublicKey(pk, usage)
	default:
		return ex.error(fmt.Errorf("Unsupported key type: %T", pk))
	}
}

// RsaPrivateKey registers an RSA private key.
// Returns an ExecRegister with the specified RSA private key set.
// Panics if the key format is unexpected or the key length is invalid.
func (ex ExecRegisterWantType) RsaPrivateKey(key *rsa.PrivateKey, usage kmip.CryptographicUsageMask) ExecRegister {
	alg := kmip.CryptographicAlgorithmRSA
	bitlen := key.N.BitLen()
	if bitlen < 0 || bitlen > math.MaxInt32 {
		return ex.error(fmt.Errorf("Invalid key length: %d", bitlen))
	}
	bitlen32 := int32(bitlen)
	switch ex.keyFormat.rsaPrivFormat() {
	case PKCS1:
		return ex.rawKeyBytes(true, x509.MarshalPKCS1PrivateKey(key), alg, bitlen32, kmip.KeyFormatTypePKCS_1, usage)
	case PKCS8:
		kb, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return ex.error(err)
		}
		return ex.rawKeyBytes(true, kb, alg, bitlen32, kmip.KeyFormatTypePKCS_8, usage)
	case Transparent:
		pkey := &kmip.PrivateKey{
			KeyBlock: kmip.KeyBlock{
				CryptographicAlgorithm: alg,
				KeyFormatType:          kmip.KeyFormatTypeTransparentRSAPrivateKey,
				CryptographicLength:    bitlen32,
				KeyValue: &kmip.KeyValue{
					Plain: &kmip.PlainKeyValue{
						KeyMaterial: kmip.KeyMaterial{
							TransparentRSAPrivateKey: &kmip.TransparentRSAPrivateKey{
								Modulus:         *key.N,
								PrivateExponent: key.D,
								PublicExponent:  big.NewInt(int64(key.E)),
								P:               key.Primes[0],
								Q:               key.Primes[1],
								PrimeExponentP:  key.Precomputed.Dp,
								PrimeExponentQ:  key.Precomputed.Dq,
								CRTCoefficient:  key.Precomputed.Qinv,
							},
						},
					},
				},
			},
		}
		return ex.Object(pkey).WithAttribute(kmip.AttributeNameCryptographicUsageMask, usage)
	default:
		panic("Unexpected key format")
	}
}

// RsaPublicKey registers an RSA public key.
// Returns an ExecRegister with the specified RSA public key set.
// Panics if the key format is unexpected or the key length is invalid.
func (ex ExecRegisterWantType) RsaPublicKey(key *rsa.PublicKey, usage kmip.CryptographicUsageMask) ExecRegister {
	alg := kmip.CryptographicAlgorithmRSA
	bitlen := key.N.BitLen()
	if bitlen < 0 || bitlen > math.MaxInt32 {
		return ex.error(fmt.Errorf("Invalid key length: %d", bitlen))
	}
	bitlen32 := int32(bitlen)
	switch ex.keyFormat.rsaPubFormat() {
	case PKCS1:
		return ex.rawKeyBytes(false, x509.MarshalPKCS1PublicKey(key), alg, bitlen32, kmip.KeyFormatTypePKCS_1, usage)
	case X509:
		kb, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return ex.error(err)
		}
		return ex.rawKeyBytes(false, kb, alg, bitlen32, kmip.KeyFormatTypeX_509, usage)
	case Transparent:
		pkey := &kmip.PublicKey{
			KeyBlock: kmip.KeyBlock{
				CryptographicAlgorithm: alg,
				KeyFormatType:          kmip.KeyFormatTypeTransparentRSAPublicKey,
				CryptographicLength:    bitlen32,
				KeyValue: &kmip.KeyValue{
					Plain: &kmip.PlainKeyValue{
						KeyMaterial: kmip.KeyMaterial{
							TransparentRSAPublicKey: &kmip.TransparentRSAPublicKey{
								Modulus:        *key.N,
								PublicExponent: *big.NewInt(int64(key.E)),
							},
						},
					},
				},
			},
		}
		return ex.Object(pkey).WithAttribute(kmip.AttributeNameCryptographicUsageMask, usage)
	default:
		panic("Unexpected key format")
	}
}

// EcdsaPrivateKey registers an ECDSA private key.
// Returns an ExecRegister with the specified ECDSA private key set.
// Panics if the key format is unexpected or the curve is unsupported.
func (ex ExecRegisterWantType) EcdsaPrivateKey(key *ecdsa.PrivateKey, usage kmip.CryptographicUsageMask) ExecRegister {
	alg := kmip.CryptographicAlgorithmECDSA
	bitlen, crv, err := curveToKMIP(key.Curve)
	if err != nil {
		return ex.error(err)
	}

	switch ex.keyFormat.ecdsaPrivFormat() {
	case SEC1:
		kb, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return ex.error(err)
		}
		return ex.rawKeyBytes(true, kb, alg, bitlen, kmip.KeyFormatTypeECPrivateKey, usage)
	case PKCS8:
		kb, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return ex.error(err)
		}
		return ex.rawKeyBytes(true, kb, alg, bitlen, kmip.KeyFormatTypePKCS_8, usage)
	case Transparent:
		keyMaterial := kmip.KeyMaterial{}
		//nolint:staticcheck // for backward compatibility
		keyFormat := kmip.KeyFormatTypeTransparentECDSAPrivateKey
		if ttlv.CompareVersions(ex.client.Version(), kmip.V1_3) >= 0 {
			// TransparentECDSAPrivateKey is deprecated since KMIP 1.3
			keyFormat = kmip.KeyFormatTypeTransparentECPrivateKey
			keyMaterial.TransparentECPrivateKey = &kmip.TransparentECPrivateKey{
				D:                *key.D,
				RecommendedCurve: crv,
			}
		} else {
			//nolint:staticcheck // for backward compatibility
			keyMaterial.TransparentECDSAPrivateKey = &kmip.TransparentECDSAPrivateKey{
				D:                *key.D,
				RecommendedCurve: crv,
			}
		}
		pkey := &kmip.PrivateKey{
			KeyBlock: kmip.KeyBlock{
				CryptographicAlgorithm: alg,
				KeyFormatType:          keyFormat,
				CryptographicLength:    bitlen,
				KeyValue: &kmip.KeyValue{
					Plain: &kmip.PlainKeyValue{
						KeyMaterial: keyMaterial,
					},
				},
			},
		}
		return ex.Object(pkey).WithAttribute(kmip.AttributeNameCryptographicUsageMask, usage)
	default:
		panic("Unexpected key format")
	}
}

// EcdsaPublicKey registers an ECDSA public key.
// Returns an ExecRegister with the specified ECDSA public key set.
// Panics if the key format is unexpected or the curve is unsupported.
func (ex ExecRegisterWantType) EcdsaPublicKey(key *ecdsa.PublicKey, usage kmip.CryptographicUsageMask) ExecRegister {
	alg := kmip.CryptographicAlgorithmECDSA
	bitlen, crv, err := curveToKMIP(key.Curve)
	if err != nil {
		return ex.error(err)
	}

	switch ex.keyFormat.ecdsaPubFormat() {
	case X509:
		kb, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return ex.error(err)
		}
		return ex.rawKeyBytes(false, kb, alg, bitlen, kmip.KeyFormatTypeX_509, usage)
	case Transparent:
		compressionType := kmip.KeyCompressionTypeECPublicKeyTypeUncompressed
		keyMaterial := kmip.KeyMaterial{}
		//nolint:staticcheck // for backward compatibility
		keyFormat := kmip.KeyFormatTypeTransparentECDSAPublicKey
		if ttlv.CompareVersions(ex.client.Version(), kmip.V1_3) >= 0 {
			// TransparentECDSAPrivateKey is deprecated since KMIP 1.3
			keyFormat = kmip.KeyFormatTypeTransparentECPublicKey
			keyMaterial.TransparentECPublicKey = &kmip.TransparentECPublicKey{
				//nolint:staticcheck // We need this function to marshal public key into its uncompressed form
				QString:          elliptic.Marshal(key.Curve, key.X, key.Y),
				RecommendedCurve: crv,
			}
		} else {
			//nolint:staticcheck // for backward compatibility
			keyMaterial.TransparentECDSAPublicKey = &kmip.TransparentECDSAPublicKey{
				//nolint:staticcheck // We need this function to marshal public key into its uncompressed form
				QString:          elliptic.Marshal(key.Curve, key.X, key.Y),
				RecommendedCurve: crv,
			}
		}
		pkey := &kmip.PublicKey{
			KeyBlock: kmip.KeyBlock{
				CryptographicAlgorithm: alg,
				KeyFormatType:          keyFormat,
				KeyCompressionType:     compressionType,
				CryptographicLength:    bitlen,
				KeyValue: &kmip.KeyValue{
					Plain: &kmip.PlainKeyValue{
						KeyMaterial: keyMaterial,
					},
				},
			},
		}
		return ex.Object(pkey).WithAttribute(kmip.AttributeNameCryptographicUsageMask, usage)
	default:
		panic("Unexpected key format")
	}
}

// curveToKMIP converts an elliptic curve to KMIP parameters.
// Returns the bit length, recommended curve, and an error if the curve is unsupported.
func curveToKMIP(curve elliptic.Curve) (int32, kmip.RecommendedCurve, error) {
	var crv kmip.RecommendedCurve
	switch curve {
	case elliptic.P224():
		crv = kmip.RecommendedCurveP_224
	case elliptic.P256():
		crv = kmip.RecommendedCurveP_256
	case elliptic.P384():
		crv = kmip.RecommendedCurveP_384
	case elliptic.P521():
		crv = kmip.RecommendedCurveP_521
	default:
		return 0, kmip.RecommendedCurve(0), errors.New("Unsupported curve")
	}
	return crv.Bitlen(), crv, nil
}

// KeyFormat represents the format of a key for registration operations.
type KeyFormat uint8

const (
	// Transparent key format.
	Transparent KeyFormat = 1 << iota
	// X509 key format.
	X509
	// PKCS8 key format.
	PKCS8
	// PKCS1 key format.
	PKCS1
	// SEC1 key format.
	SEC1
	// RAW key format.
	RAW
)

// rsaPubFormat returns the RSA public key format.
// If the key format is not set, it defaults to PKCS1.
func (kf KeyFormat) rsaPubFormat() KeyFormat {
	if kf == 0 || kf&PKCS1 == PKCS1 {
		return PKCS1
	}
	if kf&X509 == X509 {
		return X509
	}
	if kf&Transparent == Transparent {
		return Transparent
	}
	return PKCS1
}

// rsaPrivFormat returns the RSA private key format.
// If the key format is not set, it defaults to PKCS1.
func (kf KeyFormat) rsaPrivFormat() KeyFormat {
	if kf == 0 || kf&PKCS1 == PKCS1 {
		return PKCS1
	}
	if kf&PKCS8 == PKCS8 {
		return PKCS8
	}
	if kf&Transparent == Transparent {
		return Transparent
	}
	return PKCS1
}

// ecdsaPubFormat returns the ECDSA public key format.
// If the key format is not set, it defaults to X509.
func (kf KeyFormat) ecdsaPubFormat() KeyFormat {
	if kf == 0 || kf&X509 == X509 {
		return X509
	}
	if kf&Transparent == Transparent {
		return Transparent
	}
	return X509
}

// ecdsaPrivFormat returns the ECDSA private key format.
// If the key format is not set, it defaults to SEC1.
func (kf KeyFormat) ecdsaPrivFormat() KeyFormat {
	if kf == 0 || kf&SEC1 == SEC1 {
		return SEC1
	}
	if kf&PKCS8 == PKCS8 {
		return PKCS8
	}
	if kf&Transparent == Transparent {
		return Transparent
	}
	return SEC1
}

// symmetricFormat returns the symmetric key format.
// If the key format is not set, it defaults to RAW.
func (kf KeyFormat) symmetricFormat() KeyFormat {
	if kf == 0 || kf&RAW == RAW {
		return RAW
	}
	if kf&Transparent == Transparent {
		return Transparent
	}
	return RAW
}
