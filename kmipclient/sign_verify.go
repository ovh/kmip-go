package kmipclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

type ExecSign struct {
	Executor[*payloads.SignRequestPayload, *payloads.SignResponsePayload]
}

type ExecSignatureVerify struct {
	Executor[*payloads.SignatureVerifyRequestPayload, *payloads.SignatureVerifyResponsePayload]
}

type ExecSignWantsData struct {
	req    *payloads.SignRequestPayload
	client *Client
}

type ExecSignatureVerifyWantsData struct {
	req    *payloads.SignatureVerifyRequestPayload
	client *Client
}

type ExecSignatureVerifyWantsSignature struct {
	req    *payloads.SignatureVerifyRequestPayload
	client *Client
}

func (c *Client) Sign(id string) ExecSignWantsData {
	return ExecSignWantsData{
		client: c,
		req: &payloads.SignRequestPayload{
			UniqueIdentifier: id,
		},
	}
}

func (ex ExecSignWantsData) WithCryptographicParameters(params kmip.CryptographicParameters) ExecSignWantsData {
	ex.req.CryptographicParameters = &params
	return ex
}

func (ex ExecSignWantsData) Data(data []byte) ExecSign {
	ex.req.Data = data
	return ExecSign{
		Executor[*payloads.SignRequestPayload, *payloads.SignResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}

func (ex ExecSignWantsData) DigestedData(data []byte) ExecSign {
	ex.req.DigestedData = data
	return ExecSign{
		Executor[*payloads.SignRequestPayload, *payloads.SignResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}

func (c *Client) SignatureVerify(id string) ExecSignatureVerifyWantsData {
	return ExecSignatureVerifyWantsData{
		client: c,
		req: &payloads.SignatureVerifyRequestPayload{
			UniqueIdentifier: id,
		},
	}
}

func (ex ExecSignatureVerifyWantsData) WithCryptographicParameters(params kmip.CryptographicParameters) ExecSignatureVerifyWantsData {
	ex.req.CryptographicParameters = &params
	return ex
}

func (ex ExecSignatureVerifyWantsData) Data(data []byte) ExecSignatureVerifyWantsSignature {
	ex.req.Data = data
	return ExecSignatureVerifyWantsSignature(ex)
}

func (ex ExecSignatureVerifyWantsData) DigestedData(data []byte) ExecSignatureVerifyWantsSignature {
	ex.req.DigestedData = data
	return ExecSignatureVerifyWantsSignature(ex)
}

func (ex ExecSignatureVerifyWantsData) Signature(sig []byte) ExecSignatureVerify {
	ex.req.SignatureData = sig
	return ExecSignatureVerify{
		Executor[*payloads.SignatureVerifyRequestPayload, *payloads.SignatureVerifyResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}

func (ex ExecSignatureVerifyWantsSignature) Signature(sig []byte) ExecSignatureVerify {
	ex.req.SignatureData = sig
	return ExecSignatureVerify{
		Executor[*payloads.SignatureVerifyRequestPayload, *payloads.SignatureVerifyResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}

// Signer returns a crypto.Signer implementation using the remote private key for signing.
// The public key must be non sensitive and extractable. The private key must be linked to its publickey.
//
// At least one of privateKeyId or publicKeyId must be given. If only one of them is given, the other will be retrieved
// from the appropriate Link attribute.
func (c *Client) Signer(ctx context.Context, privateKeyId, publicKeyId string) (crypto.Signer, error) {
	if privateKeyId == "" && publicKeyId == "" {
		return nil, errors.New("at least one of public key or private key ID must be given")
	}
	signer := &cryptoSigner{
		client: c,
	}

	// If privateKey is given then check its attributes.
	if privateKeyId != "" {
		// Get key attributes and verify:
		//        - Key is a private key object
		//        - Key has Sign usage mask
		//        - Has public key link
		//        - Has supported algorithm
		pubKeyId, err := signer.verifySignerKeyAttributes(ctx, privateKeyId, kmip.ObjectTypePrivateKey, kmip.CryptographicUsageSign)
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
		// If public key is not given then use the linked publicKeyId we found.
		if publicKeyId == "" {
			publicKeyId = pubKeyId
		}
	}
	// At this point, publicKeyId must not be empty, otherwise it's a failure.
	if publicKeyId == "" {
		return nil, fmt.Errorf("link to public key is missing")
	}
	// Check public key attributes:
	//		  - Key is public key
	//        - Key has same algorithm than private key
	//        - Key has Verify usage mask
	privKeyId, err := signer.verifySignerKeyAttributes(ctx, publicKeyId, kmip.ObjectTypePublicKey, kmip.CryptographicUsageVerify)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	// If private key is not given, then use the linked one we found when checking the public key
	if privateKeyId == "" {
		privateKeyId = privKeyId
		// At this point, if privateKeyId is still empty, it's a failure
		if privateKeyId == "" {
			return nil, fmt.Errorf("link to private key is missing")
		}
		// Check the found private key attributes.
		if _, err := signer.verifySignerKeyAttributes(ctx, privateKeyId, kmip.ObjectTypePrivateKey, kmip.CryptographicUsageSign); err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
	}

	// Save the private key ID for later usage.
	signer.privateKeyId = privateKeyId

	// Get and save public key material
	resp, err := c.Get(publicKeyId).ExecContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key material: %w", err)
	}
	signer.publicKey, err = resp.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("invalid public key material: %w", err)
	}

	return signer, nil
}

type cryptoSigner struct {
	alg          kmip.CryptographicAlgorithm
	privateKeyId string
	publicKey    crypto.PublicKey
	client       *Client
}

// Public implements crypto.Signer.
func (c *cryptoSigner) Public() crypto.PublicKey {
	return c.publicKey
}

func hashToKmip(h crypto.Hash) (kmip.HashingAlgorithm, error) {
	switch h {
	case crypto.SHA256:
		return kmip.HashingAlgorithmSHA_256, nil
	case crypto.SHA384:
		return kmip.HashingAlgorithmSHA_384, nil
	case crypto.SHA512:
		return kmip.HashingAlgorithmSHA_512, nil
	default:
		return 0, errors.New("unsupported hash function")
	}
}

// Sign implements crypto.Signer.
func (c *cryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts == nil {
		return nil, errors.New("opts cannot be nil")
	}
	hashAlg, err := hashToKmip(opts.HashFunc())
	if err != nil {
		return nil, err
	}

	cparams := kmip.CryptographicParameters{
		CryptographicAlgorithm: c.alg,
		HashingAlgorithm:       hashAlg,
	}
	if c.alg == kmip.CryptographicAlgorithmRSA {
		// When using RSA, default to PKCS1V1_5 padding.
		cparams.PaddingMethod = kmip.PaddingMethodPKCS1V1_5
	}
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		// Then if opts in a PSSOptions, then overwrite padding method with PSS.
		if c.alg != kmip.CryptographicAlgorithmRSA {
			return nil, errors.New("rsa.PSSOptions can only be used with RSA keys")
		}
		cparams.PaddingMethod = kmip.PaddingMethodPSS
		cparams.MaskGenerator = kmip.MaskGeneratorMGF1
		cparams.MaskGeneratorHashingAlgorithm = hashAlg
		if pss.SaltLength > rsa.PSSSaltLengthAuto && pss.SaltLength < math.MaxInt32 {
			// In case of rsa.PSSSaltLengthAuto we don't add saltlength, and let the server decide for us.
			// Signature verification will autodetect the salt length used.
			saltLength := int32(pss.SaltLength)
			cparams.SaltLength = &saltLength
		} else if pss.SaltLength == rsa.PSSSaltLengthEqualsHash {
			saltLength := int32(opts.HashFunc().Size())
			cparams.SaltLength = &saltLength
		} else if pss.SaltLength < rsa.PSSSaltLengthEqualsHash {
			return nil, errors.New("invalid PSS salt length")
		}
	}

	normalizeDSACryptoParams(&cparams)

	resp, err := c.client.Sign(c.privateKeyId).
		WithCryptographicParameters(cparams).
		DigestedData(digest).
		Exec()
	if err != nil {
		return nil, err
	}

	// As the KMIP standard does not specify which signature format is returned for ECDSA signatures,
	// we must check which format is returned, and convert to ASN.1 if it's a raw signatures (concatenation of R and S).
	if c.alg == kmip.CryptographicAlgorithmEC || c.alg == kmip.CryptographicAlgorithmECDSA {
		// Check of signature is raw concatenation of r and s, or if it's ASN.1.
		// One way to do it is to check the signature size. If it's exactly 2 times the size of curve size
		// then it's raw. ANS.1 will always have more bytes.
		curve := c.publicKey.(*ecdsa.PublicKey).Curve
		if len(resp.SignatureData) == 2*((curve.Params().BitSize+7)/8) {
			// Need to convert to ASN.1
			resp.SignatureData, err = convertRawECDSAToASN1DER(resp.SignatureData, curve)
			if err != nil {
				return nil, err
			}
		}
	}

	return resp.SignatureData, nil
}

func (c *cryptoSigner) verifySignerKeyAttributes(ctx context.Context, id string, expectedObjectType kmip.ObjectType, expectedUsageMask kmip.CryptographicUsageMask) (string, error) {
	resp, err := c.client.GetAttributes(id,
		kmip.AttributeNameObjectType,
		kmip.AttributeNameCryptographicAlgorithm,
		kmip.AttributeNameLink,
		kmip.AttributeNameCryptographicUsageMask,
	).ExecContext(ctx)
	if err != nil {
		return "", err
	}

	linkedKeyId := ""

	for _, attr := range resp.Attribute {
		switch attr.AttributeName {
		case kmip.AttributeNameObjectType:
			if ot := attr.AttributeValue.(kmip.ObjectType); ot != expectedObjectType {
				return "", fmt.Errorf("unexpected object type (got %s, wants %s)", ttlv.EnumStr(ot), ttlv.EnumStr(expectedObjectType))
			}
		case kmip.AttributeNameCryptographicAlgorithm:
			// Save private key algorithm
			alg := attr.AttributeValue.(kmip.CryptographicAlgorithm)
			if alg != kmip.CryptographicAlgorithmRSA && alg != kmip.CryptographicAlgorithmEC && alg != kmip.CryptographicAlgorithmECDSA {
				return "", fmt.Errorf("unsupported cryptographic algorithm %s", ttlv.EnumStr(alg))
			}
			if c.alg == 0 {
				c.alg = alg
			} else if alg != c.alg {
				return "", fmt.Errorf("invalid cryptographic algorithm %s", ttlv.EnumStr(alg))
			}

		case kmip.AttributeNameLink:
			// Get public or private key id
			if ln := attr.AttributeValue.(kmip.Link); ln.LinkType == kmip.LinkTypePublicKeyLink && expectedObjectType == kmip.ObjectTypePrivateKey || ln.LinkType == kmip.LinkTypePrivateKeyLink && expectedObjectType == kmip.ObjectTypePublicKey {
				linkedKeyId = ln.LinkedObjectIdentifier
			}
		case kmip.AttributeNameCryptographicUsageMask:
			if cum := attr.AttributeValue.(kmip.CryptographicUsageMask); cum&expectedUsageMask == 0 {
				return "", fmt.Errorf("unexpected usage mask (got %s, wants %s)", ttlv.BitmaskStr(cum, "|"), ttlv.BitmaskStr(expectedUsageMask, "|"))
			}
		}
	}
	return linkedKeyId, nil
}

// convertRawECDSAToASN1DER converts a raw ECDSA signature (r || s) into ASN.1 DER format.
func convertRawECDSAToASN1DER(rawSig []byte, curve elliptic.Curve) ([]byte, error) {
	//TODO: Change maybe to use x/crypto's cryptobyte package which would be more permfromant.

	// ECDSASignature represents the ASN.1 structure of an ECDSA signature
	type ECDSASignature struct {
		R, S *big.Int
	}

	// Ensure the raw signature length is correct
	orderSize := (curve.Params().BitSize + 7) / 8 // Curve order size in bytes
	if len(rawSig) != 2*orderSize {
		return nil, fmt.Errorf("invalid raw signature length: expected %d, got %d", 2*orderSize, len(rawSig))
	}

	// Split raw signature into r and s
	r := new(big.Int).SetBytes(rawSig[:orderSize])
	s := new(big.Int).SetBytes(rawSig[orderSize:])

	// Encode as ASN.1
	der, err := asn1.Marshal(ECDSASignature{R: r, S: s})
	if err != nil {
		return nil, err
	}

	return der, nil
}

func normalizeDSACryptoParams(cparams *kmip.CryptographicParameters) {
	switch cparams.CryptographicAlgorithm {
	case kmip.CryptographicAlgorithmRSA:
		switch cparams.PaddingMethod {
		case kmip.PaddingMethodPKCS1V1_5:
			switch cparams.HashingAlgorithm {
			case kmip.HashingAlgorithmSHA_256:
				cparams.DigitalSignatureAlgorithm = kmip.DigitalSignatureAlgorithmSHA_256WithRSAEncryptionPKCS_1v1_5
			case kmip.HashingAlgorithmSHA_384:
				cparams.DigitalSignatureAlgorithm = kmip.DigitalSignatureAlgorithmSHA_384WithRSAEncryptionPKCS_1v1_5
			case kmip.HashingAlgorithmSHA_512:
				cparams.DigitalSignatureAlgorithm = kmip.DigitalSignatureAlgorithmSHA_512WithRSAEncryptionPKCS_1v1_5
			}
		case kmip.PaddingMethodPSS:
			cparams.DigitalSignatureAlgorithm = kmip.DigitalSignatureAlgorithmRSASSA_PSSPKCS_1v2_1
		}
	case kmip.CryptographicAlgorithmEC, kmip.CryptographicAlgorithmECDSA:
		switch cparams.HashingAlgorithm {
		case kmip.HashingAlgorithmSHA_256:
			cparams.DigitalSignatureAlgorithm = kmip.DigitalSignatureAlgorithmECDSAWithSHA256
		case kmip.HashingAlgorithmSHA_384:
			cparams.DigitalSignatureAlgorithm = kmip.DigitalSignatureAlgorithmECDSAWithSHA384
		case kmip.HashingAlgorithmSHA_512:
			cparams.DigitalSignatureAlgorithm = kmip.DigitalSignatureAlgorithmECDSAWithSHA512
		}
	}
}
