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

// ExecSign is a specialized executor for handling Sign operations.
// It embeds the generic Executor with request and response payload types specific to
// the Sign KMIP operation, facilitating the execution and management of sign requests and their responses.
//
// Usage:
//
//	exec := client.Sign("key-id").WithCryptographicParameters(...).Data(...)
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the sign operation if the key is invalid,
//     the server rejects the operation, or the cryptographic parameters are not supported.
type ExecSign struct {
	Executor[*payloads.SignRequestPayload, *payloads.SignResponsePayload]
}

// ExecSignatureVerify is a specialized executor for handling SignatureVerify operations.
// It embeds the generic Executor with request and response payload types specific to
// the SignatureVerify KMIP operation, facilitating the execution and management of signature verification requests and their responses.
//
// Usage:
//
//	exec := client.SignatureVerify("key-id").WithCryptographicParameters(...).Data(...).Signature(...)
//	resp, err := exec.ExecContext(ctx)
//
// Errors:
//   - Errors may be returned when executing the signature verify operation if the key is invalid,
//     the server rejects the operation, or the cryptographic parameters are not supported.
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

// Sign initializes a signing operation for the object identified by the given unique identifier.
// It returns an ExecSignWantsData struct, which allows the caller to provide the data to be signed.
// The signing operation is not executed until the data is supplied.
func (c *Client) Sign(id string) ExecSignWantsData {
	return ExecSignWantsData{
		client: c,
		req: &payloads.SignRequestPayload{
			UniqueIdentifier: id,
		},
	}
}

// WithCryptographicParameters sets the CryptographicParameters field of the request to the provided params.
// It returns the updated ExecSignWantsData to allow for method chaining.
func (ex ExecSignWantsData) WithCryptographicParameters(params kmip.CryptographicParameters) ExecSignWantsData {
	ex.req.CryptographicParameters = &params
	return ex
}

// Data sets the data to be signed in the request and returns an ExecSign instance
// for executing the sign operation with the provided data.
func (ex ExecSignWantsData) Data(data []byte) ExecSign {
	ex.req.Data = data
	return ExecSign{
		Executor[*payloads.SignRequestPayload, *payloads.SignResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}

// DigestedData sets the digested (hashed) data to be signed in the request payload.
// It accepts a byte slice containing the digested data and returns an ExecSign instance
// for further configuration or execution of the signing operation.
func (ex ExecSignWantsData) DigestedData(data []byte) ExecSign {
	ex.req.DigestedData = data
	return ExecSign{
		Executor[*payloads.SignRequestPayload, *payloads.SignResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}

// SignatureVerify initializes a signature verification operation for the object identified by the given unique identifier.
// It returns an ExecSignatureVerifyWantsData struct, which allows the caller to provide the data and signature to be verified.
// The verification process is performed using the cryptographic object referenced by the unique identifier.
//
// Parameters:
//   - id: The unique identifier of the cryptographic object to be used for signature verification.
//
// Returns:
//   - ExecSignatureVerifyWantsData: A struct for chaining the next steps of the signature verification process.
//
// Errors:
//   - This function does not return errors directly. Errors may be returned when executing the ExecSignatureVerifyWantsData or ExecSignatureVerify.
//   - If the object does not exist or the server rejects the operation, an error will be returned during execution.
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

// Data sets the data to be verified in the request and returns an ExecSignatureVerifyWantsSignature instance
// for providing the signature and executing the verification operation.
func (ex ExecSignatureVerifyWantsData) Data(data []byte) ExecSignatureVerifyWantsSignature {
	ex.req.Data = data
	return ExecSignatureVerifyWantsSignature(ex)
}

// DigestedData sets the digested (hashed) data to be verified in the request payload.
// Returns an ExecSignatureVerifyWantsSignature instance for providing the signature and executing the verification operation.
func (ex ExecSignatureVerifyWantsData) DigestedData(data []byte) ExecSignatureVerifyWantsSignature {
	ex.req.DigestedData = data
	return ExecSignatureVerifyWantsSignature(ex)
}

// Signature sets the signature data to be verified in the request and returns an ExecSignatureVerify
// instance for executing the signature verification operation.
//
// Parameters:
//   - sig ([]byte): The signature data to be verified.
//
// Returns:
//   - ExecSignatureVerify: An executor configured with the provided signature data.
func (ex ExecSignatureVerifyWantsData) Signature(sig []byte) ExecSignatureVerify {
	ex.req.SignatureData = sig
	return ExecSignatureVerify{
		Executor[*payloads.SignatureVerifyRequestPayload, *payloads.SignatureVerifyResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}

// Signature sets the signature data to be verified in the request payload and returns
// an ExecSignatureVerify instance for further execution. The provided sig parameter
// should contain the signature bytes to be verified.
//
// Parameters:
//   - sig: The signature data as a byte slice.
//
// Returns:
//   - ExecSignatureVerify: An executor configured with the signature data.
//   - error: An error if the key attributes are invalid or if required keys are missing.
func (ex ExecSignatureVerifyWantsSignature) Signature(sig []byte) ExecSignatureVerify {
	ex.req.SignatureData = sig
	return ExecSignatureVerify{
		Executor[*payloads.SignatureVerifyRequestPayload, *payloads.SignatureVerifyResponsePayload]{
			client: ex.client,
			req:    ex.req,
		},
	}
}

// Signer creates a crypto.Signer using the provided private and public key IDs.
// It verifies the attributes of the keys to ensure they are suitable for signing and verifying operations.
// If only one key ID is provided, it attempts to find the corresponding linked key ID.
//
// Parameters:
//   - ctx: The context for the operation.
//   - privateKeyId: The ID of the private key. Can be empty if publicKeyId is provided.
//   - publicKeyId: The ID of the public key. Can be empty if privateKeyId is provided.
//
// Returns:
//   - crypto.Signer: The signer object that can be used for signing operations.
//   - error: An error if the key attributes are invalid or if required keys are missing.
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
		//TODO: If private key is extractable and non-sensitive, then we can extract the public key from the private key.
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
			saltLength := opts.HashFunc().Size()
			if saltLength < 0 || saltLength > math.MaxInt32 {
				return nil, errors.New("invalid Hash size")
			}
			saltLength32 := int32(saltLength)
			cparams.SaltLength = &saltLength32
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
	//TODO: Change maybe to use x/crypto's cryptobyte package which would be more performant, but would add a new dependency.

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
