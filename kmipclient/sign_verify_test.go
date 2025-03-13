package kmipclient_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"
	"github.com/stretchr/testify/require"
)

func TestCryptoSignerRSA(t *testing.T) {
	mux := kmipserver.NewBatchExecutor()
	privateKeyRsa, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux.Route(kmip.OperationGetAttributes, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
		resp := &payloads.GetAttributesResponsePayload{
			UniqueIdentifier: pl.UniqueIdentifier,
		}
		switch pl.UniqueIdentifier {
		case "private-key-rsa":
			resp.Attribute = []kmip.Attribute{
				{AttributeName: kmip.AttributeNameObjectType, AttributeValue: kmip.ObjectTypePrivateKey},
				{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmRSA},
				{AttributeName: kmip.AttributeNameLink, AttributeValue: kmip.Link{LinkType: kmip.LinkTypePublicKeyLink, LinkedObjectIdentifier: "public-key-rsa"}},
				{AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: kmip.CryptographicUsageSign},
			}
		case "public-key-rsa":
			resp.Attribute = []kmip.Attribute{
				{AttributeName: kmip.AttributeNameObjectType, AttributeValue: kmip.ObjectTypePublicKey},
				{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmRSA},
				{AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: kmip.CryptographicUsageVerify},
			}
		default:
			return nil, kmipserver.ErrItemNotFound
		}
		return resp, nil
	}))

	mux.Route(kmip.OperationGet, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
		switch pl.UniqueIdentifier {
		case "public-key-rsa":
			pkix, _ := x509.MarshalPKIXPublicKey(privateKeyRsa.Public())
			return &payloads.GetResponsePayload{
				ObjectType:       kmip.ObjectTypePublicKey,
				UniqueIdentifier: "public-key-rsa",
				Object: &kmip.PublicKey{
					KeyBlock: kmip.KeyBlock{
						KeyFormatType:          kmip.KeyFormatTypeX_509,
						CryptographicAlgorithm: kmip.CryptographicAlgorithmRSA,
						CryptographicLength:    int32(privateKeyRsa.Size()) * 8,
						KeyValue: &kmip.KeyValue{
							Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{Bytes: &pkix}},
						},
					},
				},
			}, nil
		default:
			return nil, kmipserver.ErrPermissionDenied
		}
	}))

	mux.Route(kmip.OperationSign, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.SignRequestPayload) (*payloads.SignResponsePayload, error) {
		var signature []byte
		var err error

		switch pl.UniqueIdentifier {
		case "private-key-rsa":
			var hash crypto.Hash
			switch pl.CryptographicParameters.HashingAlgorithm {
			case kmip.HashingAlgorithmSHA_256:
				hash = crypto.SHA256
			case kmip.HashingAlgorithmSHA_384:
				hash = crypto.SHA384
			case kmip.HashingAlgorithmSHA_512:
				hash = crypto.SHA512
			}
			if pl.CryptographicParameters.PaddingMethod == kmip.PaddingMethodPKCS1V1_5 {
				signature, err = rsa.SignPKCS1v15(rand.Reader, privateKeyRsa, hash, pl.DigestedData)
			} else if pl.CryptographicParameters.PaddingMethod == kmip.PaddingMethodPSS {
				// saltLen := pl.CryptographicParameters.SaltLength
				opts := rsa.PSSOptions{
					Hash: hash,
				}
				if saltLen := pl.CryptographicParameters.SaltLength; saltLen != nil && *saltLen > 0 {
					opts.SaltLength = int(*saltLen)
				}
				signature, err = rsa.SignPSS(rand.Reader, privateKeyRsa, hash, pl.DigestedData, &opts)
			} else {
				return nil, kmipserver.ErrInvalidField
			}
		default:
			return nil, kmipserver.ErrPermissionDenied
		}

		if err != nil {
			return nil, err
		}
		return &payloads.SignResponsePayload{
			UniqueIdentifier: pl.UniqueIdentifier,
			SignatureData:    signature,
		}, nil
	}))

	client := kmiptest.NewClientAndServer(t, mux)

	data := []byte("hello world")

	signer, err := client.Signer("private-key-rsa")
	require.NoError(t, err)

	for _, hashfunc := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		t.Run(hashfunc.String(), func(t *testing.T) {
			h := hashfunc.New()
			h.Write(data)
			digest := h.Sum(nil)

			t.Run("PKCS1v15", func(t *testing.T) {
				sig, err := signer.Sign(rand.Reader, digest[:], hashfunc)
				require.NoError(t, err)
				pubKey := signer.Public().(*rsa.PublicKey)
				err = rsa.VerifyPKCS1v15(pubKey, hashfunc, digest[:], sig)
				require.NoError(t, err)
			})

			t.Run("PSS-saltlen-auto", func(t *testing.T) {
				sig, err := signer.Sign(rand.Reader, digest[:], &rsa.PSSOptions{Hash: hashfunc})
				require.NoError(t, err)
				pubKey := signer.Public().(*rsa.PublicKey)
				err = rsa.VerifyPSS(pubKey, hashfunc, digest[:], sig, &rsa.PSSOptions{Hash: hashfunc})
				require.NoError(t, err)
			})
			t.Run("PSS-saltlen-hash", func(t *testing.T) {
				sig, err := signer.Sign(rand.Reader, digest[:], &rsa.PSSOptions{Hash: hashfunc, SaltLength: rsa.PSSSaltLengthEqualsHash})
				require.NoError(t, err)
				pubKey := signer.Public().(*rsa.PublicKey)
				err = rsa.VerifyPSS(pubKey, hashfunc, digest[:], sig, &rsa.PSSOptions{Hash: hashfunc, SaltLength: rsa.PSSSaltLengthEqualsHash})
				require.NoError(t, err)
			})
			t.Run("PSS-saltlen-8", func(t *testing.T) {
				sig, err := signer.Sign(rand.Reader, digest[:], &rsa.PSSOptions{Hash: hashfunc, SaltLength: 8})
				require.NoError(t, err)
				pubKey := signer.Public().(*rsa.PublicKey)
				err = rsa.VerifyPSS(pubKey, hashfunc, digest[:], sig, &rsa.PSSOptions{Hash: hashfunc, SaltLength: 8})
				require.NoError(t, err)
			})
		})
	}
}

func TestCryptoSignerECDSA(t *testing.T) {
	for _, crv := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(crv.Params().Name, func(t *testing.T) {
			t.Parallel()
			privateKeyEcdsa, err := ecdsa.GenerateKey(crv, rand.Reader)
			require.NoError(t, err)

			mux := kmipserver.NewBatchExecutor()
			mux.Route(kmip.OperationGetAttributes, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
				resp := &payloads.GetAttributesResponsePayload{
					UniqueIdentifier: pl.UniqueIdentifier,
				}
				switch pl.UniqueIdentifier {
				case "private-key-ecdsa", "private-key-ecdsa-raw":
					resp.Attribute = []kmip.Attribute{
						{AttributeName: kmip.AttributeNameObjectType, AttributeValue: kmip.ObjectTypePrivateKey},
						{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmEC},
						{AttributeName: kmip.AttributeNameLink, AttributeValue: kmip.Link{LinkType: kmip.LinkTypePublicKeyLink, LinkedObjectIdentifier: "public-key-ecdsa"}},
						{AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: kmip.CryptographicUsageSign},
					}
				case "public-key-ecdsa":
					resp.Attribute = []kmip.Attribute{
						{AttributeName: kmip.AttributeNameObjectType, AttributeValue: kmip.ObjectTypePublicKey},
						{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmEC},
						{AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: kmip.CryptographicUsageVerify},
					}
				default:
					return nil, kmipserver.ErrItemNotFound
				}
				return resp, nil
			}))

			mux.Route(kmip.OperationGet, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
				switch pl.UniqueIdentifier {
				case "public-key-ecdsa":
					pkix, _ := x509.MarshalPKIXPublicKey(privateKeyEcdsa.Public())
					return &payloads.GetResponsePayload{
						ObjectType:       kmip.ObjectTypePublicKey,
						UniqueIdentifier: "public-key-ecdsa",
						Object: &kmip.PublicKey{
							KeyBlock: kmip.KeyBlock{
								KeyFormatType:          kmip.KeyFormatTypeX_509,
								CryptographicAlgorithm: kmip.CryptographicAlgorithmEC,
								CryptographicLength:    int32(privateKeyEcdsa.Curve.Params().BitSize),
								KeyValue: &kmip.KeyValue{
									Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{Bytes: &pkix}},
								},
							},
						},
					}, nil
				default:
					return nil, kmipserver.ErrPermissionDenied
				}
			}))

			mux.Route(kmip.OperationSign, kmipserver.HandleFunc(func(ctx context.Context, pl *payloads.SignRequestPayload) (*payloads.SignResponsePayload, error) {
				var signature []byte
				var err error

				switch pl.UniqueIdentifier {
				case "private-key-ecdsa":
					// Provide an ASN.1 signature.
					signature, err = ecdsa.SignASN1(rand.Reader, privateKeyEcdsa, pl.DigestedData)
				case "private-key-ecdsa-raw":
					// Provide a raw signature.
					r, s, err := ecdsa.Sign(rand.Reader, privateKeyEcdsa, pl.DigestedData)
					if err != nil {
						return nil, err
					}
					orderSize := (privateKeyEcdsa.Curve.Params().BitSize + 7) / 8
					signature = make([]byte, orderSize*2)
					r.FillBytes(signature[:orderSize])
					s.FillBytes(signature[orderSize:])
				default:
					return nil, kmipserver.ErrPermissionDenied
				}

				if err != nil {
					return nil, err
				}
				return &payloads.SignResponsePayload{
					UniqueIdentifier: pl.UniqueIdentifier,
					SignatureData:    signature,
				}, nil
			}))

			client := kmiptest.NewClientAndServer(t, mux)

			data := []byte("hello world")

			for _, hashfunc := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
				t.Run(hashfunc.String(), func(t *testing.T) {
					h := hashfunc.New()
					h.Write(data)
					digest := h.Sum(nil)

					t.Run("ASN1", func(t *testing.T) {
						signer, err := client.Signer("private-key-ecdsa")
						require.NoError(t, err)

						sig, err := signer.Sign(rand.Reader, digest[:], hashfunc)
						require.NoError(t, err)
						pubKey := signer.Public().(*ecdsa.PublicKey)
						valid := ecdsa.VerifyASN1(pubKey, digest[:], sig)
						require.True(t, valid)
					})

					t.Run("RAW", func(t *testing.T) {
						signer, err := client.Signer("private-key-ecdsa-raw")
						require.NoError(t, err)

						sig, err := signer.Sign(rand.Reader, digest[:], hashfunc)
						require.NoError(t, err)
						pubKey := signer.Public().(*ecdsa.PublicKey)
						valid := ecdsa.VerifyASN1(pubKey, digest[:], sig)
						require.True(t, valid)
					})

				})
			}
		})
	}
}
