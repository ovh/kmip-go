//nolint:unused // This is a test file
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"slices"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"

	"github.com/google/uuid"
)

const (
	ADDR = "localhost:5696"
	CA   = "tests/root_certificate.pem"
	CERT = "tests/client_certificate_john_doe.pem"
	KEY  = "tests/client_key_john_doe.pem"
)

var RESOURCE = "cb0ea267-d912-4bd4-9be2-2093e1ed02a4"

func main() {
	client := newClient()
	defer client.Close()

	unsupported_operation(client)

	activateAll(client)
	cleanupDomain(client)

	time_consuming_batch(client)

	test_encrypt_decrypt_aes(client)
	test_encrypt_decrypt_aes_default(client)
	test_encrypt_encrypt_aes_cbc_pkcs5(client)
	test_encrypt_decrypt_aes_with_usage(client)
	test_encrypt_decrypt_rsa_oaep(client)
	test_encrypt_decrypt_rsa_pkcs1(client)
	test_locate_by_range(client)

	test_state_transitions(client)
	test_register(client)
	test_usage_limits(client)
	test_get_uage_limits_no_attributes(client)

	test_register_ecdsa_wrong_alg(client)

	discover(client)
	query(client)
	activate(client)
	destroy(client)
	revoke(client)
	get_attribute_list(client)
	get_attributes(client)
	create_aes(client)
	create_3des(client)
	create_skipjack(client)
	create_rsa(client)
	create_ecdsa(client)
	locate(client)
	archive(client)
	recover(client)

	register_secret(client)
	register_certificate(client)
	register_split_key(client)
	register_opaque(client)
	register_template(client)
	register_pgp(client)

	register_aes_raw(client)
	register_aes_transparent(client)

	register_rsa_transparent(client)

	register_ecdsa_transparent(client)
	register_ecdsa_sec1(client)

	rekey(client)

	get(client)

	double_destroy(client)

	test_get_unsupported_wrapped_key(client)
	test_get_register_wrapped_aes_key(client)
	test_get_register_wrapped_rsa_key(client)
	test_get_register_wrapped_ecdsa_key(client)

	test_extractable(client)
	test_sensitive(client)
}

func newClient() *kmipclient.Client {
	fmt.Println("Connecting to KMIP endpoint")
	client, err := kmipclient.Dial(
		ADDR,
		kmipclient.WithRootCAFile(CA),
		kmipclient.WithClientCertFiles(CERT, KEY),
		kmipclient.WithMiddlewares(
			kmipclient.CorrelationValueMiddleware(uuid.NewString),
			// kmipclient.DebugMiddleware(os.Stdout, func(data any) []byte { b, _ := json.MarshalIndent(data, "", "    "); return b }),
			kmipclient.DebugMiddleware(os.Stdout, ttlv.MarshalXML),
		),
		kmipclient.EnforceVersion(kmip.V1_4),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Connected using KMIP version", client.Version())
	return client
}

func discover(client *kmipclient.Client) {
	msg := kmip.NewRequestMessage(kmip.V1_4,
		&payloads.DiscoverVersionsRequestPayload{
			ProtocolVersion: []kmip.ProtocolVersion{
				{
					ProtocolVersionMajor: 1,
					ProtocolVersionMinor: 4,
				},
				{
					ProtocolVersionMajor: 1,
					ProtocolVersionMinor: 0,
				},
			},
		},
		&payloads.DiscoverVersionsRequestPayload{
			ProtocolVersion: []kmip.ProtocolVersion{},
		},
	)
	if _, err := client.Roundtrip(context.Background(), &msg); err != nil {
		panic(err)
	}
}

func unsupported_operation(client *kmipclient.Client) {
	req := kmip.NewUnknownPayload(0x8000041, ttlv.Value{Tag: kmip.TagUniqueIdentifier, Value: "abcdef"})
	if _, err := client.Request(context.Background(), req); err != nil {
		panic(err)
	}
}

func activate(client *kmipclient.Client) {
	client.Activate(RESOURCE).MustExec()
}

func destroy(client *kmipclient.Client) {
	client.Destroy(RESOURCE).MustExec()
}

func revoke(client *kmipclient.Client) {
	client.Revoke(RESOURCE).
		WithRevocationReasonCode(kmip.RevocationReasonCodeKeyCompromise).
		MustExec()
}

func get_attribute_list(client *kmipclient.Client) {
	client.GetAttributeList(RESOURCE).MustExec()
}

func get_attributes(client *kmipclient.Client) {
	client.GetAttributes(RESOURCE).
		// WithAttributes(kmip.AttributeNameName, kmip.AttributeNameObjectType).
		MustExec()
}

func create_aes(client *kmipclient.Client) {
	client.Create().
		AES(256, kmip.Encrypt|kmip.Decrypt|kmip.WrapKey|kmip.UnwrapKey).
		WithName("Test-PH-AES (go)").
		WithAttribute(kmip.AttributeName("x-toto"), "foobar").
		MustExec()
}

func create_3des(client *kmipclient.Client) {
	client.Create().
		TDES(168, kmip.Encrypt|kmip.Decrypt|kmip.WrapKey|kmip.UnwrapKey).
		WithName("Test-PH-3DES (go)").
		MustExec()
}

func create_skipjack(client *kmipclient.Client) {
	client.Create().
		Skipjack(kmip.Encrypt | kmip.Decrypt | kmip.WrapKey | kmip.UnwrapKey).
		WithName("Test-PH-Skipjack (go)").
		MustExec()

}

func create_rsa(client *kmipclient.Client) {
	client.CreateKeyPair().
		RSA(4096, kmip.Sign, kmip.Verify).
		// Common().WithName("Test-PH-RSA (go)").
		PrivateKey().WithName("Test-PH-RSA-priv (go)").
		PublicKey().WithName("Test-PH-RSA-pub (go)").
		MustExec()
}

func create_ecdsa(client *kmipclient.Client) {
	client.CreateKeyPair().
		ECDSA(kmip.P_256, kmip.Sign, kmip.Verify).
		Common().WithName("Test-PH-ECDSA (go)").
		MustExec()
}

func locate(client *kmipclient.Client) {
	client.Locate().
		// WithAttribute(kmip.AttributeNameName, kmip.Name{NameValue: "Test-PH-Symmetric Raw (go)"}).
		// WithAttribute(kmip.AttributeNameLink, kmip.Link{LinkedObjectIdentifier: "1139b0c0-1bca-4e40-98cd-af5d7f177391"}).
		MustExec()
}

func archive(client *kmipclient.Client) {
	client.Archive(RESOURCE).MustExec()
}

func recover(client *kmipclient.Client) {
	client.Recover(RESOURCE).MustExec()
}

func register_secret(client *kmipclient.Client) {
	client.Register().
		SecretString(kmip.Password, "Hello World").
		WithName("Test-PH-Secret (go)").
		// WithObjectType(kmip.ObjectTypeCertificate).
		MustExec()
}

func register_aes_raw(client *kmipclient.Client) {
	data := make([]byte, 24)
	_, _ = rand.Read(data)
	client.Register().WithKeyFormat(kmipclient.RAW).
		SymmetricKey(kmip.AES, kmip.Encrypt|kmip.Decrypt, data).
		WithName("Test-PH-Symmetric Raw (go)").
		// WithAttribute(kmip.AttributeNameOperationPolicyName, "toto").
		MustExec()
}

func register_aes_transparent(client *kmipclient.Client) {
	client.Register().WithKeyFormat(kmipclient.Transparent).
		SymmetricKey(kmip.AES, kmip.Encrypt|kmip.Decrypt, make([]byte, 32)).
		WithName("Test-PH-Symmetric Raw 2 (go)").
		MustExec()
}

func register_ecdsa_sec1(client *kmipclient.Client) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	client.Register().WithKeyFormat(kmipclient.SEC1).EcdsaPrivateKey(key, kmip.Sign).MustExec()
}

func register_ecdsa_transparent(client *kmipclient.Client) {
	pkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	client.Register().WithKeyFormat(kmipclient.Transparent).EcdsaPrivateKey(pkey, kmip.Sign|kmip.Verify).MustExec()
}

func register_rsa_transparent(client *kmipclient.Client) {
	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	client.Register().WithKeyFormat(kmipclient.Transparent).RsaPrivateKey(pkey, kmip.Sign|kmip.Verify).MustExec()
}

func register_split_key(client *kmipclient.Client) {
	alg := kmip.AES
	clen := int32(4)
	client.Register().Object(&kmip.SplitKey{
		SplitKeyParts:     2,
		KeyPartIdentifier: 1,
		SplitKeyThreshold: 2,
		SplitKeyMethod:    kmip.SplitKeyMethodXOR,
		KeyBlock: kmip.KeyBlock{
			KeyFormatType:          kmip.KeyFormatRaw,
			CryptographicAlgorithm: &alg,  // FIXME: If alg is null, Internal server error
			CryptographicLength:    &clen, // FIXME: Same here
			KeyValue: &kmip.KeyValue{
				Plain: &kmip.PlainKeyValue{
					KeyMaterial: kmip.KeyMaterial{Bytes: &[]byte{1, 2, 3, 4}},
				},
			},
		},
	}).
		WithName("my split key part 1").
		MustExec()
}

func register_opaque(client *kmipclient.Client) {
	resp := client.Register().Object(&kmip.OpaqueObject{
		OpaqueDataType:  kmip.OpaqueDataType(12),
		OpaqueDataValue: []byte("foobar"),
	}).WithName("Test-PH-Opaque (go)").MustExec()

	client.Get(resp.UniqueIdentifier).MustExec()
}

func register_template(client *kmipclient.Client) {
	activationDate := time.Now().AddDate(0, 0, 1).Round(time.Second)
	resp := client.Register().Object(&kmip.Template{
		Attribute: []kmip.Attribute{
			{AttributeName: kmip.AttributeNameActivationDate, AttributeValue: activationDate},
		},
	}).WithName("Test-PH-Template").MustExec()

	client.Get(resp.UniqueIdentifier).MustExec()

	aesKey := client.Create().AES(128, kmip.Sign|kmip.Verify).WithTemplate("Test-PH-Template", kmip.UninterpretedTextString).MustExec()
	date := client.GetAttributes(aesKey.UniqueIdentifier, kmip.AttributeNameActivationDate).MustExec().Attribute[0].AttributeValue.(time.Time)
	if !date.Equal(activationDate) {
		panic(fmt.Sprintf("unexpected activation date. got %q, want %q", date, activationDate))
	}
}

func register_pgp(client *kmipclient.Client) {
	key := []byte("foobar")
	alg := kmip.RSA
	clen := int32(2048)
	client.Register().Object(&kmip.PGPKey{
		PGPKeyVersion: 12,
		KeyBlock:      kmip.KeyBlock{KeyFormatType: kmip.KeyFormatRaw, CryptographicAlgorithm: &alg, CryptographicLength: &clen, KeyValue: &kmip.KeyValue{Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{Bytes: &key}}}},
	}).WithAttribute(kmip.AttributeNameCryptographicUsageMask, kmip.Sign|kmip.Verify).MustExec()
}

func register_certificate(client *kmipclient.Client) {
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName:   "Test-PH-x509",
			Country:      []string{"FR"},
			Organization: []string{"OVH"},
		},
		DNSNames:       []string{"name.dns.org"},
		EmailAddresses: []string{"foo@bar.org"},
		IPAddresses:    []net.IP{{127, 0, 0, 1}},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(1, 0, 0),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	cert, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		panic(err)
	}
	resp := client.Register().Certificate(kmip.X_509, cert).WithName("X509 certificate").MustExec()

	client.GetAttributeList(resp.UniqueIdentifier).MustExec()

	client.GetAttributes(resp.UniqueIdentifier).MustExec()

	client.GetAttributes(resp.UniqueIdentifier, kmip.AttributeNameX509CertificateIdentifier, kmip.AttributeNameX509CertificateIssuer, kmip.AttributeNameX509CertificateSubject, kmip.AttributeNameCertificateLength, kmip.AttributeNameFresh).MustExec()
}

func get(client *kmipclient.Client) {
	client.Get(RESOURCE).MustExec()
}

func rekey(client *kmipclient.Client) {
	client.Rekey(RESOURCE).MustExec()
}

func query(client *kmipclient.Client) {
	client.Query().All().MustExec()
}

func double_destroy(client *kmipclient.Client) {
	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		WithName("test-double-destroy").
		MustExec()
	client.Activate(res.UniqueIdentifier).MustExec()

	client.Revoke(res.UniqueIdentifier).MustExec()
	client.Destroy(res.UniqueIdentifier).MustExec()
	client.Destroy(res.UniqueIdentifier).MustExec()
}

func test_register(client *kmipclient.Client) {
	client.Register().SecretString(kmip.Password, "azerty1234").MustExec()
	client.Register().SymmetricKey(kmip.AES, kmip.Encrypt|kmip.Decrypt, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).MustExec()
	test_register_rsa(client)
	test_register_ecdsa(client)
}

func test_register_rsa(client *kmipclient.Client) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkey := client.Register().RsaPrivateKey(rsaKey, kmip.Sign).MustExec()
	pubKey := client.Register().RsaPublicKey(&rsaKey.PublicKey, kmip.Verify).
		WithLink(kmip.PrivateKeyLink, pkey.UniqueIdentifier).
		MustExec()

	client.AddAttribute(pkey.UniqueIdentifier, kmip.AttributeNameLink, kmip.Link{LinkType: kmip.PublicKeyLink, LinkedObjectIdentifier: pubKey.UniqueIdentifier}).MustExec()

	client.GetAttributes(pubKey.UniqueIdentifier, kmip.AttributeNameLink).MustExec()
	client.GetAttributes(pkey.UniqueIdentifier, kmip.AttributeNameLink).MustExec()

	priv, err := client.Get(pkey.UniqueIdentifier).MustExec().RsaPrivateKey()
	if err != nil {
		panic(err)
	}
	if !priv.Equal(rsaKey) {
		panic("EC key not equal")
	}
}

func test_register_ecdsa(client *kmipclient.Client) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkey := client.Register().EcdsaPrivateKey(ecKey, kmip.Sign).WithName("test-register-ecdsa-priv").MustExec()
	pubKey := client.Register().EcdsaPublicKey(&ecKey.PublicKey, kmip.Verify).
		WithLink(kmip.PrivateKeyLink, pkey.UniqueIdentifier).
		WithName("test-register-ecdsa-pub").
		MustExec()

	client.AddAttribute(pkey.UniqueIdentifier, kmip.AttributeNameLink, kmip.Link{LinkType: kmip.PublicKeyLink, LinkedObjectIdentifier: pubKey.UniqueIdentifier}).MustExec()

	client.GetAttributes(pubKey.UniqueIdentifier, kmip.AttributeNameLink).MustExec()

	priv, err := client.Get(pkey.UniqueIdentifier).MustExec().EcdsaPrivateKey()
	if err != nil {
		panic(err)
	}
	if !priv.Equal(ecKey) {
		panic("EC key not equal")
	}
}

func test_register_ecdsa_wrong_alg(client *kmipclient.Client) {
	alg := kmip.RSA
	clen := int32(2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client.Register().
		Object(&kmip.PrivateKey{
			KeyBlock: kmip.KeyBlock{
				KeyFormatType: kmip.KeyFormatTransparentECDSAPrivateKey,
				KeyValue: &kmip.KeyValue{
					Plain: &kmip.PlainKeyValue{
						KeyMaterial: kmip.KeyMaterial{
							TransparentECDSAPrivateKey: &kmip.TransparentECDSAPrivateKey{
								RecommendedCurve: kmip.P_256,
								D:                *ecKey.D,
							},
						},
					},
				},
				CryptographicAlgorithm: &alg,
				CryptographicLength:    &clen,
			},
		}).
		WithAttribute(kmip.AttributeNameCryptographicUsageMask, kmip.Sign|kmip.Verify).
		MustExec()
}

func test_usage_limits(client *kmipclient.Client) {
	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		WithName("AES-test-usage-limits").
		WithUsageLimit(10, kmip.UsageLimitsUnitObject).
		MustExec()
	defer client.Destroy(res.UniqueIdentifier).MustExec()

	client.Activate(res.UniqueIdentifier).MustExec()
	defer client.Revoke(res.UniqueIdentifier).MustExec()

	attributes := client.GetAttributes(res.UniqueIdentifier, kmip.AttributeNameUsageLimits).MustExec()
	limits := attributes.Attribute[0].AttributeValue.(kmip.UsageLimits)
	if !limits.Equals(&kmip.UsageLimits{
		UsageLimitsUnit:  kmip.UsageLimitsUnitObject,
		UsageLimitsTotal: 10,
		UsageLimitsCount: ptrTo(int64(10)),
	}) {
		panic("Unexpected limits")
	}

	client.GetUsageAllocation(res.UniqueIdentifier, 3).MustExec()

	attributes = client.GetAttributes(res.UniqueIdentifier, kmip.AttributeNameUsageLimits).MustExec()
	limits = attributes.Attribute[0].AttributeValue.(kmip.UsageLimits)
	if !limits.Equals(&kmip.UsageLimits{
		UsageLimitsUnit:  kmip.UsageLimitsUnitObject,
		UsageLimitsTotal: 10,
		UsageLimitsCount: ptrTo(int64(7)),
	}) {
		panic("Unexpected limits")
	}

	_, err := client.GetUsageAllocation(res.UniqueIdentifier, 8).Exec()
	if err == nil {
		panic("Expected an error")
	}

	attributes = client.GetAttributes(res.UniqueIdentifier, kmip.AttributeNameUsageLimits).MustExec()
	limits = attributes.Attribute[0].AttributeValue.(kmip.UsageLimits)
	if !limits.Equals(&kmip.UsageLimits{
		UsageLimitsUnit:  kmip.UsageLimitsUnitObject,
		UsageLimitsTotal: 10,
		UsageLimitsCount: ptrTo(int64(7)),
	}) {
		panic("Unexpected limits")
	}

	client.GetAttributes(res.UniqueIdentifier).MustExec()

	client.GetUsageAllocation(res.UniqueIdentifier, 7).MustExec()

	attributes = client.GetAttributes(res.UniqueIdentifier, kmip.AttributeNameUsageLimits).MustExec()
	limits = attributes.Attribute[0].AttributeValue.(kmip.UsageLimits)
	if !limits.Equals(&kmip.UsageLimits{
		UsageLimitsUnit:  kmip.UsageLimitsUnitObject,
		UsageLimitsTotal: 10,
		UsageLimitsCount: ptrTo(int64(0)),
	}) {
		panic("Unexpected limits")
	}

	client.GetAttributes(res.UniqueIdentifier, kmip.AttributeNameState).MustExec()
	client.Get(res.UniqueIdentifier).MustExec()
}

func test_get_uage_limits_no_attributes(client *kmipclient.Client) {
	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		WithName("AES-test-usage-no-limit").
		MustExec()
	defer client.Destroy(res.UniqueIdentifier).MustExec()

	client.Activate(res.UniqueIdentifier).MustExec()
	defer client.Revoke(res.UniqueIdentifier).MustExec()

	_, err := client.GetUsageAllocation(res.UniqueIdentifier, 8).Exec()
	if err == nil {
		panic("Expected an error")
	}

	client.AddAttribute(res.UniqueIdentifier, kmip.AttributeNameUsageLimits, kmip.UsageLimits{
		UsageLimitsUnit:  kmip.UsageLimitsUnitObject,
		UsageLimitsTotal: 10,
		// UsageLimitsCount: 0,
	}).MustExec()
}

func test_extractable(client *kmipclient.Client) {
	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		WithAttribute(kmip.AttributeNameExtractable, false).
		// WithAttribute(kmip.AttributeNameNeverExtractable, false).
		MustExec()
	client.GetAttributes(res.UniqueIdentifier).
		WithAttributes(kmip.AttributeNameExtractable, kmip.AttributeNameNeverExtractable).
		MustExec()

	if _, err := client.Get(res.UniqueIdentifier).Exec(); err == nil {
		panic("Expected an error")
	}

	client.ModifyAttribute(res.UniqueIdentifier, kmip.AttributeNameExtractable, true).MustExec()
	client.GetAttributes(res.UniqueIdentifier).
		WithAttributes(kmip.AttributeNameExtractable, kmip.AttributeNameNeverExtractable).
		MustExec()

	client.Get(res.UniqueIdentifier).MustExec()

	if _, err := client.ModifyAttribute(res.UniqueIdentifier, kmip.AttributeNameNeverExtractable, true).Exec(); err == nil {
		panic("Expected an error")
	}
}

func test_sensitive(client *kmipclient.Client) {
	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		WithAttribute(kmip.AttributeNameSensitive, true).
		MustExec()
	client.GetAttributes(res.UniqueIdentifier).
		WithAttributes(kmip.AttributeNameSensitive, kmip.AttributeNameAlwaysSensitive).
		MustExec()

	if _, err := client.Get(res.UniqueIdentifier).Exec(); err == nil {
		panic("Expected an error")
	}

	client.ModifyAttribute(res.UniqueIdentifier, kmip.AttributeNameSensitive, false).MustExec()
	client.GetAttributes(res.UniqueIdentifier).
		WithAttributes(kmip.AttributeNameSensitive, kmip.AttributeNameAlwaysSensitive).
		MustExec()

	client.Get(res.UniqueIdentifier).MustExec()

	if _, err := client.ModifyAttribute(res.UniqueIdentifier, kmip.AttributeNameAlwaysSensitive, true).Exec(); err == nil {
		panic("Expected an error")
	}
}

func test_get_unsupported_wrapped_key(client *kmipclient.Client) {
	wrapKey := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).MustExec()

	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		// WithAttribute(kmip.AttributeNameSensitive, true).
		MustExec()

	req := payloads.GetRequestPayload{
		UniqueIdentifier: &res.UniqueIdentifier,
		KeyWrappingSpecification: &kmip.KeyWrappingSpecification{
			WrappingMethod: kmip.WrappingMethodEncrypt,
			EncryptionKeyInformation: &kmip.EncryptionKeyInformation{
				UniqueIdentifier: wrapKey.UniqueIdentifier,
				CryptographicParameters: &kmip.CryptographicParameters{
					BlockCipherMode:        ptrTo(kmip.AESKeyWrapPadding),
					CryptographicAlgorithm: ptrTo(kmip.AES),
				},
			},
		},
	}
	_, err := client.Request(context.Background(), &req)
	if err != nil {
		panic(err)
	}
}

func test_get_register_wrapped_aes_key(client *kmipclient.Client) {
	wrapKey := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).MustExec()

	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		// WithAttribute(kmip.AttributeNameSensitive, true).
		MustExec()

	resp := client.Get(res.UniqueIdentifier).WithKeyWrapping(kmip.KeyWrappingSpecification{
		WrappingMethod: kmip.WrappingMethodEncrypt,
		EncryptionKeyInformation: &kmip.EncryptionKeyInformation{
			UniqueIdentifier: wrapKey.UniqueIdentifier,
			CryptographicParameters: &kmip.CryptographicParameters{
				BlockCipherMode:        ptrTo(kmip.NISTKeyWrap),
				CryptographicAlgorithm: ptrTo(kmip.AES),
			},
		},
	}).MustExec()

	client.Register().Object(&kmip.SymmetricKey{
		KeyBlock: resp.Object.(*kmip.SymmetricKey).KeyBlock,
	}).WithAttribute(kmip.AttributeNameCryptographicUsageMask, kmip.Encrypt|kmip.Decrypt).MustExec()
}

func test_get_register_wrapped_rsa_key(client *kmipclient.Client) {
	wrapKey := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).MustExec()

	res := client.CreateKeyPair().RSA(2048, kmip.Sign, kmip.Verify).MustExec()

	resp := client.Get(res.PrivateKeyUniqueIdentifier).WithKeyWrapping(kmip.KeyWrappingSpecification{
		WrappingMethod: kmip.WrappingMethodEncrypt,
		EncryptionKeyInformation: &kmip.EncryptionKeyInformation{
			UniqueIdentifier: wrapKey.UniqueIdentifier,
			CryptographicParameters: &kmip.CryptographicParameters{
				BlockCipherMode:        ptrTo(kmip.NISTKeyWrap),
				CryptographicAlgorithm: ptrTo(kmip.AES),
			},
		},
	}).MustExec()

	client.Register().Object(&kmip.PrivateKey{
		KeyBlock: resp.Object.(*kmip.PrivateKey).KeyBlock,
	}).WithAttribute(kmip.AttributeNameCryptographicUsageMask, kmip.Sign).MustExec()
}

func test_get_register_wrapped_ecdsa_key(client *kmipclient.Client) {
	wrapKey := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).MustExec()

	res := client.CreateKeyPair().ECDSA(kmip.P_256, kmip.Sign, kmip.Verify).MustExec()

	resp := client.Get(res.PrivateKeyUniqueIdentifier).WithKeyWrapping(kmip.KeyWrappingSpecification{
		WrappingMethod: kmip.WrappingMethodEncrypt,
		EncryptionKeyInformation: &kmip.EncryptionKeyInformation{
			UniqueIdentifier: wrapKey.UniqueIdentifier,
			CryptographicParameters: &kmip.CryptographicParameters{
				BlockCipherMode:        ptrTo(kmip.NISTKeyWrap),
				CryptographicAlgorithm: ptrTo(kmip.AES),
			},
		},
	}).MustExec()

	client.Register().Object(&kmip.PrivateKey{
		KeyBlock: resp.Object.(*kmip.PrivateKey).KeyBlock,
	}).WithAttribute(kmip.AttributeNameCryptographicUsageMask, kmip.Sign).MustExec()
}

func time_consuming_batch(client *kmipclient.Client) {
	req := &payloads.CreateKeyPairRequestPayload{
		CommonTemplateAttribute: &kmip.TemplateAttribute{
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "test-batch-rsa", NameType: kmip.UninterpretedTextString}},
				{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.RSA},
				{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: int32(4096)},
				{AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: kmip.Sign | kmip.Verify},
			},
		},
		// PrivateKeyTemplateAttribute: &kmip.TemplateAttribute{},
		// PublicKeyTemplateAttribute:  &kmip.TemplateAttribute{},
	}
	// msg := kmip.NewRequestMessage(kmip.V1_4, req, req, req, req, req, req, req, req, req, req)
	// opt := kmip.Continue
	// msg.Header.BatchErrorContinuationOption = &opt
	// _, err := client.Roundtrip(context.Background(), &msg)
	_, err := client.Batch(context.Background(), req, req, req, req, req, req, req, req, req, req)
	if err != nil {
		panic(err)
	}
}

func test_locate_by_range(client *kmipclient.Client) {
	cleanupDomain(client)
	now := time.Now()
	now10 := now.Add(10 * time.Minute)
	now100 := now.Add(100 * time.Minute)
	now1000 := now.Add(1000 * time.Minute)
	k1 := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).WithAttribute(kmip.AttributeNameProcessStartDate, now10).MustExec().UniqueIdentifier
	k2 := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).WithAttribute(kmip.AttributeNameProcessStartDate, now100).MustExec().UniqueIdentifier
	k3 := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).WithAttribute(kmip.AttributeNameProcessStartDate, now1000).MustExec().UniqueIdentifier

	lresp := client.Locate().
		WithAttribute(kmip.AttributeNameProcessStartDate, now).
		WithAttribute(kmip.AttributeNameProcessStartDate, now100).
		MustExec()

	if !slices.Contains(lresp.UniqueIdentifier, k1) || !slices.Contains(lresp.UniqueIdentifier, k2) {
		panic("Did not found expected keys")
	}
	if slices.Contains(lresp.UniqueIdentifier, k3) {
		panic("Found an unexpected keys")
	}
}

func ptrTo[T any](v T) *T {
	return &v
}
