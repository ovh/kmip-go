package kmip

import "github.com/ovh/kmip-go/ttlv"

func init() {
	ttlv.RegisterEnum(TagResultStatus, map[ResultStatus]string{
		StatusSuccess:          "Success",
		StatusOperationFailed:  "OperationFailed",
		StatusOperationPending: "OperationPending",
		StatusOperationUndone:  "OperationUndone",
	})
	ttlv.RegisterEnum(TagResultReason, map[ResultReason]string{
		// ReasonNone:                             "None",
		ReasonItemNotFound:                     "ItemNotFound",
		ReasonResponseTooLarge:                 "ResponseTooLarge",
		ReasonAuthenticationNotSuccessful:      "AuthenticationNotSuccessful",
		ReasonInvalidMessage:                   "InvalidMessage",
		ReasonOperationNotSupported:            "OperationNotSupported",
		ReasonMissingData:                      "MissingData",
		ReasonInvalidField:                     "InvalidField",
		ReasonFeatureNotSupported:              "FeatureNotSupported",
		ReasonOperationCanceledByRequester:     "OperationCanceledByRequester",
		ReasonCryptographicFailure:             "CryptographicFailure",
		ReasonIllegalOperation:                 "IllegalOperation",
		ReasonPermissionDenied:                 "PermissionDenied",
		ReasonObjectarchived:                   "Objectarchived",
		ReasonIndexOutofBounds:                 "IndexOutofBounds",
		ReasonApplicationNamespaceNotSupported: "ApplicationNamespaceNotSupported",
		ReasonKeyFormatTypeNotSupported:        "KeyFormatTypeNotSupported",
		ReasonKeyCompressionTypeNotSupported:   "KeyCompressionTypeNotSupported",
		ReasonGeneralFailure:                   "GeneralFailure",
		// KMIP 1.1.
		ReasonEncodingOptionError: "EncodingOptionError",
		// KMIP 1.2.
		ReasonKeyValueNotPresent:  "KeyValueNotPresent",
		ReasonAttestationRequired: "AttestationRequired",
		ReasonAttestationFailed:   "AttestationFailed",
		// KMIP 1.4.
		Sensitive:           "Sensitive",
		NotExtractable:      "NotExtractable",
		ObjectAlreadyExists: "ObjectAlreadyExists",
	})
	ttlv.RegisterEnum(TagCredentialType, map[CredentialType]string{
		CredentialUsernameAndPassword: "UsernameAndPassword",
		// KMIP 1.1.
		CredentialDevice: "Device",
		// KMIP 1.2.
		CredentialAttestation: "Attestation",
	})
	ttlv.RegisterEnum(TagRevocationReasonCode, map[RevocationReasonCode]string{
		RevocationReasonCodeUnspecified:          "Unspecified",
		RevocationReasonCodeKeyCompromise:        "KeyCompromise",
		RevocationReasonCodeCACompromise:         "CACompromise",
		RevocationReasonCodeAffiliationChanged:   "AffiliationChanged",
		RevocationReasonCodeSuperseded:           "Superseded",
		RevocationReasonCodeCessationOfOperation: "CessationOfOperation",
		RevocationReasonCodePrivilegeWithdrawn:   "PrivilegeWithdrawn",
	})
	ttlv.RegisterEnum(TagBatchErrorContinuationOption, map[BatchErrorContinuationOption]string{
		Continue: "Continue",
		Stop:     "Stop",
		Undo:     "Undo",
	})
	ttlv.RegisterEnum(TagNameType, map[NameType]string{
		UninterpretedTextString: "UninterpretedTextString",
		Uri:                     "Uri",
	})
	ttlv.RegisterEnum(TagObjectType, map[ObjectType]string{
		ObjectTypeCertificate:  "Certificate",
		ObjectTypeSymmetricKey: "SymmetricKey",
		ObjectTypePublicKey:    "PublicKey",
		ObjectTypePrivateKey:   "PrivateKey",
		ObjectTypeSplitKey:     "SplitKey",
		ObjectTypeTemplate:     "Template",
		ObjectTypeSecretData:   "SecretData",
		ObjectTypeOpaqueObject: "OpaqueObject",

		// KMIP 1.2.
		ObjectTypePGPKey: "PGPKey",
	})
	ttlv.RegisterEnum(TagOpaqueDataType, map[OpaqueDataType]string{})
	ttlv.RegisterEnum(TagState, map[State]string{
		StatePreActive:            "PreActive",
		StateActive:               "Active",
		StateDeactivated:          "Deactivated",
		StateCompromised:          "Compromised",
		StateDestroyed:            "Destroyed",
		StateDestroyedCompromised: "DestroyedCompromised",
	})
	ttlv.RegisterEnum(TagCryptographicAlgorithm, map[CryptographicAlgorithm]string{
		DES:        "DES",
		TDES:       "TDES",
		AES:        "AES",
		RSA:        "RSA",
		DSA:        "DSA",
		ECDSA:      "ECDSA",
		HMACSHA1:   "HMACSHA1",
		HMACSHA224: "HMACSHA224",
		HMACSHA256: "HMACSHA256",
		HMACSHA384: "HMACSHA384",
		HMACSHA512: "HMACSHA512",
		HMACMD5:    "HMACMD5",
		DH:         "DH",
		ECDH:       "ECDH",
		ECMQV:      "ECMQV",
		Blowfish:   "Blowfish",
		Camellia:   "Camellia",
		CAST5:      "CAST5",
		IDEA:       "IDEA",
		MARS:       "MARS",
		RC2:        "RC2",
		RC4:        "RC4",
		RC5:        "RC5",
		SKIPJACK:   "SKIPJACK",
		Twofish:    "Twofish",

		// KMIP 1.2.
		EC: "EC",

		// KMIP 1.3.
		OneTimePad: "OneTimePad",

		// KMIP 1.4.
		ChaCha20:         "ChaCha20",
		Poly1305:         "Poly1305",
		ChaCha20Poly1305: "ChaCha20Poly1305",
		SHA3_224:         "SHA3_224",
		SHA3_256:         "SHA3_256",
		SHA3_384:         "SHA3_384",
		SHA3_512:         "SHA3_512",
		HMAC_SHA3_224:    "HMAC_SHA3_224",
		HMAC_SHA3_256:    "HMAC_SHA3_256",
		HMAC_SHA3_384:    "HMAC_SHA3_384",
		HMAC_SHA3_512:    "HMAC_SHA3_512",
		SHAKE_128:        "SHAKE_128",
		SHAKE_256:        "SHAKE_256",
	})
	ttlv.RegisterEnum(TagBlockCipherMode, map[BlockCipherMode]string{
		CBC:               "CBC",
		ECB:               "ECB",
		PCBC:              "PCBC",
		CFB:               "CFB",
		OFB:               "OFB",
		CTR:               "CTR",
		CMAC:              "CMAC",
		CCM:               "CCM",
		GCM:               "GCM",
		CBCMAC:            "CBCMAC",
		XTS:               "XTS",
		AESKeyWrapPadding: "AESKeyWrapPadding",
		NISTKeyWrap:       "NISTKeyWrap",
		X9_102AESKW:       "X9_102AESKW",
		X9_102TDKW:        "X9_102TDKW",
		X9_102AKW1:        "X9_102AKW1",
		X9_102AKW2:        "X9_102AKW2",
		// KMIP 1.4
		AEAD: "AEAD",
	})
	ttlv.RegisterEnum(TagPaddingMethod, map[PaddingMethod]string{
		None:      "None",
		OAEP:      "OAEP",
		PKCS5:     "PKCS5",
		SSL3:      "SSL3",
		Zeros:     "Zeros",
		ANSIX9_23: "ANSIX9_23",
		ISO10126:  "ISO10126",
		PKCS1V1_5: "PKCS1V1_5",
		X9_31:     "X9_31",
		PSS:       "PSS",
	})
	ttlv.RegisterEnum(TagHashingAlgorithm, map[HashingAlgorithm]string{
		MD2:        "MD2",
		MD4:        "MD4",
		MD5:        "MD5",
		SHA_1:      "SHA_1",
		SHA_224:    "SHA_224",
		SHA_256:    "SHA_256",
		SHA_384:    "SHA_384",
		SHA_512:    "SHA_512",
		RIPEMD_160: "RIPEMD_160",
		Tiger:      "Tiger",
		Whirlpool:  "Whirlpool",

		// KMIP 1.2.
		SHA_512_224: "SHA_512_224",
		SHA_512_256: "SHA_512_256",

		// KMIP 1.4.
		SHA_3_224: "SHA_3_224",
		SHA_3_256: "SHA_3_256",
		SHA_3_384: "SHA_3_384",
		SHA_3_512: "SHA_3_512",
	})
	ttlv.RegisterEnum(TagKeyRoleType, map[KeyRoleType]string{
		BDK:      "BDK",
		CVK:      "CVK",
		DEK:      "DEK",
		MKAC:     "MKAC",
		MKSMC:    "MKSMC",
		MKSMI:    "MKSMI",
		MKDAC:    "MKDAC",
		MKDN:     "MKDN",
		MKCP:     "MKCP",
		MKOTH:    "MKOTH",
		KEK:      "KEK",
		MAC16609: "MAC16609",
		MAC97971: "MAC97971",
		MAC97972: "MAC97972",
		MAC97973: "MAC97973",
		MAC97974: "MAC97974",
		MAC97975: "MAC97975",
		ZPK:      "ZPK",
		PVKIBM:   "PVKIBM",
		PVKPVV:   "PVKPVV",
		PVKOTH:   "PVKOTH",

		// KMIP 1.4
		DUKPT: "DUKPT",
		IV:    "IV",
		TRKBK: "TRKBK",
	})
	ttlv.RegisterEnum(TagRecommendedCurve, map[RecommendedCurve]string{
		P_192:            "P_192",
		K_163:            "K_163",
		B_163:            "B_163",
		P_224:            "P_224",
		K_233:            "K_233",
		B_233:            "B_233",
		P_256:            "P_256",
		K_283:            "K_283",
		B_283:            "B_283",
		P_384:            "P_384",
		K_409:            "K_409",
		B_409:            "B_409",
		P_521:            "P_521",
		K_571:            "K_571",
		B_571:            "B_571",
		SECP112R1:        "SECP112R1",
		SECP112R2:        "SECP112R2",
		SECP128R1:        "SECP128R1",
		SECP128R2:        "SECP128R2",
		SECP160K1:        "SECP160K1",
		SECP160R1:        "SECP160R1",
		SECP160R2:        "SECP160R2",
		SECP192K1:        "SECP192K1",
		SECP224K1:        "SECP224K1",
		SECP256K1:        "SECP256K1",
		SECT113R1:        "SECT113R1",
		SECT113R2:        "SECT113R2",
		SECT131R1:        "SECT131R1",
		SECT131R2:        "SECT131R2",
		SECT163R1:        "SECT163R1",
		SECT193R1:        "SECT193R1",
		SECT193R2:        "SECT193R2",
		SECT239K1:        "SECT239K1",
		ANSIX9P192V2:     "ANSIX9P192V2",
		ANSIX9P192V3:     "ANSIX9P192V3",
		ANSIX9P239V1:     "ANSIX9P239V1",
		ANSIX9P239V2:     "ANSIX9P239V2",
		ANSIX9P239V3:     "ANSIX9P239V3",
		ANSIX9C2PNB163V1: "ANSIX9C2PNB163V1",
		ANSIX9C2PNB163V2: "ANSIX9C2PNB163V2",
		ANSIX9C2PNB163V3: "ANSIX9C2PNB163V3",
		ANSIX9C2PNB176V1: "ANSIX9C2PNB176V1",
		ANSIX9C2TNB191V1: "ANSIX9C2TNB191V1",
		ANSIX9C2TNB191V2: "ANSIX9C2TNB191V2",
		ANSIX9C2TNB191V3: "ANSIX9C2TNB191V3",
		ANSIX9C2PNB208W1: "ANSIX9C2PNB208W1",
		ANSIX9C2TNB239V1: "ANSIX9C2TNB239V1",
		ANSIX9C2TNB239V2: "ANSIX9C2TNB239V2",
		ANSIX9C2TNB239V3: "ANSIX9C2TNB239V3",
		ANSIX9C2PNB272W1: "ANSIX9C2PNB272W1",
		ANSIX9C2PNB304W1: "ANSIX9C2PNB304W1",
		ANSIX9C2TNB359V1: "ANSIX9C2TNB359V1",
		ANSIX9C2PNB368W1: "ANSIX9C2PNB368W1",
		ANSIX9C2TNB431R1: "ANSIX9C2TNB431R1",
		BRAINPOOLP160R1:  "BRAINPOOLP160R1",
		BRAINPOOLP160T1:  "BRAINPOOLP160T1",
		BRAINPOOLP192R1:  "BRAINPOOLP192R1",
		BRAINPOOLP192T1:  "BRAINPOOLP192T1",
		BRAINPOOLP224R1:  "BRAINPOOLP224R1",
		BRAINPOOLP224T1:  "BRAINPOOLP224T1",
		BRAINPOOLP256R1:  "BRAINPOOLP256R1",
		BRAINPOOLP256T1:  "BRAINPOOLP256T1",
		BRAINPOOLP320R1:  "BRAINPOOLP320R1",
		BRAINPOOLP320T1:  "BRAINPOOLP320T1",
		BRAINPOOLP384R1:  "BRAINPOOLP384R1",
		BRAINPOOLP384T1:  "BRAINPOOLP384T1",
		BRAINPOOLP512R1:  "BRAINPOOLP512R1",
		BRAINPOOLP512T1:  "BRAINPOOLP512T1",
	})
	ttlv.RegisterEnum(TagSecretDataType, map[SecretDataType]string{
		Password: "Password",
		Seed:     "Seed",
	})
	ttlv.RegisterEnum(TagKeyFormatType, map[KeyFormatType]string{
		KeyFormatRaw:                        "Raw",
		KeyFormatOpaque:                     "Opaque",
		KeyFormatPKCS_1:                     "PKCS_1",
		KeyFormatPKCS_8:                     "PKCS_8",
		KeyFormatX_509:                      "X_509",
		KeyFormatECPrivateKey:               "ECPrivateKey",
		KeyFormatTransparentSymmetricKey:    "TransparentSymmetricKey",
		KeyFormatTransparentDSAPrivateKey:   "TransparentDSAPrivateKey",
		KeyFormatTransparentDSAPublicKey:    "TransparentDSAPublicKey",
		KeyFormatTransparentRSAPrivateKey:   "TransparentRSAPrivateKey",
		KeyFormatTransparentRSAPublicKey:    "TransparentRSAPublicKey",
		KeyFormatTransparentDHPrivateKey:    "TransparentDHPrivateKey",
		KeyFormatTransparentDHPublicKey:     "TransparentDHPublicKey",
		KeyFormatTransparentECDSAPrivateKey: "TransparentECDSAPrivateKey",
		KeyFormatTransparentECDSAPublicKey:  "TransparentECDSAPublicKey",
		KeyFormatTransparentECDHPrivateKey:  "TransparentECDHPrivateKey",
		KeyFormatTransparentECDHPublicKey:   "TransparentECDHPublicKey",
		KeyFormatTransparentECMQVPrivateKey: "TransparentECMQVPrivateKey",
		KeyFormatTransparentECMQVPublicKey:  "TransparentECMQVPublicKey",

		// KMIP 1.3.
		KeyFormatTransparentECPrivateKey: "TransparentECPrivateKey",
		KeyFormatTransparentECPublicKey:  "TransparentECPublicKey",

		// KMIP 1.4.
		KeyFormatPKCS_12: "PKCS_12",
	})
	ttlv.RegisterEnum(TagKeyCompressionType, map[KeyCompressionType]string{
		ECPublicKeyTypeUncompressed:         "ECPublicKeyTypeUncompressed",
		ECPublicKeyTypeX9_62CompressedPrime: "ECPublicKeyTypeX9_62CompressedPrime",
		ECPublicKeyTypeX9_62CompressedChar2: "ECPublicKeyTypeX9_62CompressedChar2",
		ECPublicKeyTypeX9_62Hybrid:          "ECPublicKeyTypeX9_62Hybrid",
	})
	ttlv.RegisterEnum(TagWrappingMethod, map[WrappingMethod]string{
		WrappingMethodEncrypt:            "Encrypt",
		WrappingMethodMACSign:            "MACSign",
		WrappingMethodEncryptThenMACSign: "EncryptThenMACSign",
		WrappingMethodMACSignThenEncrypt: "MACSignThenEncrypt",
		WrappingMethodTR_31:              "TR_31",
	})
	ttlv.RegisterEnum(TagCertificateType, map[CertificateType]string{
		X_509: "X_509",
		PGP:   "PGP",
	})
	ttlv.RegisterEnum(TagLinkType, map[LinkType]string{
		CertificateLink:          "CertificateLink",
		PublicKeyLink:            "PublicKeyLink",
		PrivateKeyLink:           "PrivateKeyLink",
		DerivationBaseObjectLink: "DerivationBaseObjectLink",
		DerivedKeyLink:           "DerivedKeyLink",
		ReplacementObjectLink:    "ReplacementObjectLink",
		ReplacedObjectLink:       "ReplacedObjectLink",

		// KMIP 1.2.
		ParentLink:   "ParentLink",
		ChildLink:    "ChildLink",
		PreviousLink: "PreviousLink",
		NextLink:     "NextLink",

		// KMIP 1.4.
		PKCS_12CertificateLink: "PKCS_12CertificateLink",
		PKCS_12PasswordLink:    "PKCS_12PasswordLink",

		//FIXME: This is defined in KMIP 2.0+ only.
		WrappingKeyLink: "WrappingKeyLink",
	})
	ttlv.RegisterEnum(TagQueryFunction, map[QueryFunction]string{
		QueryOperations:            "QueryOperations",
		QueryObjects:               "QueryObjects",
		QueryServerInformation:     "QueryServerInformation",
		QueryApplicationNamespaces: "QueryApplicationNamespaces",
		// KMIP 1.1.
		QueryExtensionList: "QueryExtensionList",
		QueryExtensionMap:  "QueryExtensionMap",
		// KMIP 1.2.
		QueryAttestationTypes: "QueryAttestationTypes",
		// KMIP 1.3.
		QueryRNGs:                      "QueryRNGs",
		QueryValidations:               "QueryValidations",
		QueryProfiles:                  "QueryProfiles",
		QueryCapabilities:              "QueryCapabilities",
		QueryClientRegistrationMethods: "QueryClientRegistrationMethods",
	})
	ttlv.RegisterEnum(TagUsageLimitsUnit, map[UsageLimitsUnit]string{
		UsageLimitsUnitByte:   "UnitByte",
		UsageLimitsUnitObject: "UnitObject",
	})
	ttlv.RegisterEnum(TagCancellationResult, map[CancellationResult]string{
		Canceled:       "Canceled",
		UnableToCancel: "UnableToCancel",
		Completed:      "Completed",
		Failed:         "Failed",
		Unavailable:    "Unavailable",
	})
	ttlv.RegisterEnum(TagPutFunction, map[PutFunction]string{
		New:     "New",
		Replace: "Replace",
	})
	ttlv.RegisterEnum(TagCertificateRequestType, map[CertificateRequestType]string{
		CertificateRequestTypeCRMF:    "CRMF",
		CertificateRequestTypePKCS_10: "PKCS_10",
		CertificateRequestTypePEM:     "PEM",
		CertificateRequestTypePGP:     "PGP",
	})
	ttlv.RegisterEnum(TagSplitKeyMethod, map[SplitKeyMethod]string{
		SplitKeyMethodXOR:                         "XOR",
		SplitKeyMethodPolynomialSharingGF216:      "PolynomialSharingGF216",
		SplitKeyMethodPolynomialSharingPrimeField: "PolynomialSharingPrimeField",
		// KMIP 1.2.
		SplitKeyMethodPolynomialSharingGF28: "PolynomialSharingGF28",
	})
	ttlv.RegisterEnum(TagObjectGroupMember, map[ObjectGroupMember]string{
		GroupMemberFresh:   "GroupMemberFresh",
		GroupMemberDefault: "GroupMemberDefault",
	})
	ttlv.RegisterEnum(TagEncodingOption, map[EncodingOption]string{
		NoEncoding:   "NoEncoding",
		TTLVEncoding: "TTLVEncoding",
	})
	ttlv.RegisterEnum(TagDigitalSignatureAlgorithm, map[DigitalSignatureAlgorithm]string{
		MD2WithRSAEncryptionPKCS_1v1_5:     "MD2WithRSAEncryptionPKCS_1v1_5",
		MD5WithRSAEncryptionPKCS_1v1_5:     "MD5WithRSAEncryptionPKCS_1v1_5",
		SHA_1WithRSAEncryptionPKCS_1v1_5:   "SHA_1WithRSAEncryptionPKCS_1v1_5",
		SHA_224WithRSAEncryptionPKCS_1v1_5: "SHA_224WithRSAEncryptionPKCS_1v1_5",
		SHA_256WithRSAEncryptionPKCS_1v1_5: "SHA_256WithRSAEncryptionPKCS_1v1_5",
		SHA_384WithRSAEncryptionPKCS_1v1_5: "SHA_384WithRSAEncryptionPKCS_1v1_5",
		SHA_512WithRSAEncryptionPKCS_1v1_5: "SHA_512WithRSAEncryptionPKCS_1v1_5",
		RSASSA_PSSPKCS_1v2_1:               "RSASSA_PSSPKCS_1v2_1",
		DSAWithSHA_1:                       "DSAWithSHA_1",
		DSAWithSHA224:                      "DSAWithSHA224",
		DSAWithSHA256:                      "DSAWithSHA256",
		ECDSAWithSHA_1:                     "ECDSAWithSHA_1",
		ECDSAWithSHA224:                    "ECDSAWithSHA224",
		ECDSAWithSHA256:                    "ECDSAWithSHA256",
		ECDSAWithSHA384:                    "ECDSAWithSHA384",
		ECDSAWithSHA512:                    "ECDSAWithSHA512",

		// KMIP 1.4.
		SHA3_256WithRSAEncryption: "SHA3_256WithRSAEncryption",
		SHA3_384WithRSAEncryption: "SHA3_384WithRSAEncryption",
		SHA3_512WithRSAEncryption: "SHA3_512WithRSAEncryption",
	})
	ttlv.RegisterEnum(TagAttestationType, map[AttestationType]string{
		TPMQuote:           "TPMQuote",
		TCGIntegrityReport: "TCGIntegrityReport",
		SAMLAssertion:      "SAMLAssertion",
	})
	ttlv.RegisterEnum(TagAlternativeNameType, map[AlternativeNameType]string{
		AlternativeNameTypeUninterpretedTextString: "UninterpretedTextString",
		AlternativeNameTypeURI:                     "URI",
		AlternativeNameTypeObjectSerialNumber:      "ObjectSerialNumber",
		AlternativeNameTypeEmailAddress:            "EmailAddress",
		AlternativeNameTypeDNSName:                 "DNSName",
		AlternativeNameTypeX_500DistinguishedName:  "X_500DistinguishedName",
		AlternativeNameTypeIPAddress:               "IPAddress",
	})
	ttlv.RegisterEnum(TagKeyValueLocationType, map[KeyValueLocationType]string{
		KeyValueLocationTypeUninterpretedTextString: "UninterpretedTextString",
		KeyValueLocationTypeURI:                     "URI",
	})
	ttlv.RegisterEnum(TagValidityIndicator, map[ValidityIndicator]string{
		ValidityIndicatorValid:   "Valid",
		ValidityIndicatorInvalid: "Invalid",
		ValidityIndicatorUnknown: "Unknown",
	})

	ttlv.RegisterEnum(TagRNGAlgorithm, map[RNGAlgorithm]string{
		RNGAlgorithmUnspecified: "Unspecified",
		RNGAlgorithmFIPS186_2:   "FIPS186_2",
		RNGAlgorithmDRBG:        "DRBG",
		RNGAlgorithmNRBG:        "NRBG",
		RNGAlgorithmANSIX9_31:   "ANSIX9_31",
		RNGAlgorithmANSIX9_62:   "ANSIX9_62",
	})
	ttlv.RegisterEnum(TagDRBGAlgorithm, map[DRBGAlgorithm]string{
		DRBGAlgorithmUnspecified: "Unspecified",
		DRBGAlgorithmDual_EC:     "Dual_EC",
		DRBGAlgorithmHash:        "Hash",
		DRBGAlgorithmHMAC:        "HMAC",
		DRBGAlgorithmCTR:         "CTR",
	})
	ttlv.RegisterEnum(TagFIPS186Variation, map[FIPS186Variation]string{
		FIPS186VariationUnspecified:     "Unspecified",
		FIPS186VariationGPXOriginal:     "GPXOriginal",
		FIPS186VariationGPXChangeNotice: "GPXChangeNotice",
		FIPS186VariationXOriginal:       "XOriginal",
		FIPS186VariationXChangeNotice:   "XChangeNotice",
		FIPS186VariationKOriginal:       "KOriginal",
		FIPS186VariationKChangeNotice:   "KChangeNotice",
	})
	ttlv.RegisterEnum(TagProfileName, map[ProfileName]string{
		BaselineServerBasicKMIPV1_2:                       "BaselineServerBasicKMIPV1_2",
		BaselineServerTLSV1_2KMIPV1_2:                     "BaselineServerTLSV1_2KMIPV1_2",
		BaselineClientBasicKMIPV1_2:                       "BaselineClientBasicKMIPV1_2",
		BaselineClientTLSV1_2KMIPV1_2:                     "BaselineClientTLSV1_2KMIPV1_2",
		CompleteServerBasicKMIPV1_2:                       "CompleteServerBasicKMIPV1_2",
		CompleteServerTLSV1_2KMIPV1_2:                     "CompleteServerTLSV1_2KMIPV1_2",
		TapeLibraryClientKMIPV1_0:                         "TapeLibraryClientKMIPV1_0",
		TapeLibraryClientKMIPV1_1:                         "TapeLibraryClientKMIPV1_1",
		TapeLibraryClientKMIPV1_2:                         "TapeLibraryClientKMIPV1_2",
		TapeLibraryServerKMIPV1_0:                         "TapeLibraryServerKMIPV1_0",
		TapeLibraryServerKMIPV1_1:                         "TapeLibraryServerKMIPV1_1",
		TapeLibraryServerKMIPV1_2:                         "TapeLibraryServerKMIPV1_2",
		SymmetricKeyLifecycleClientKMIPV1_0:               "SymmetricKeyLifecycleClientKMIPV1_0",
		SymmetricKeyLifecycleClientKMIPV1_1:               "SymmetricKeyLifecycleClientKMIPV1_1",
		SymmetricKeyLifecycleClientKMIPV1_2:               "SymmetricKeyLifecycleClientKMIPV1_2",
		SymmetricKeyLifecycleServerKMIPV1_0:               "SymmetricKeyLifecycleServerKMIPV1_0",
		SymmetricKeyLifecycleServerKMIPV1_1:               "SymmetricKeyLifecycleServerKMIPV1_1",
		SymmetricKeyLifecycleServerKMIPV1_2:               "SymmetricKeyLifecycleServerKMIPV1_2",
		AsymmetricKeyLifecycleClientKMIPV1_0:              "AsymmetricKeyLifecycleClientKMIPV1_0",
		AsymmetricKeyLifecycleClientKMIPV1_1:              "AsymmetricKeyLifecycleClientKMIPV1_1",
		AsymmetricKeyLifecycleClientKMIPV1_2:              "AsymmetricKeyLifecycleClientKMIPV1_2",
		AsymmetricKeyLifecycleServerKMIPV1_0:              "AsymmetricKeyLifecycleServerKMIPV1_0",
		AsymmetricKeyLifecycleServerKMIPV1_1:              "AsymmetricKeyLifecycleServerKMIPV1_1",
		AsymmetricKeyLifecycleServerKMIPV1_2:              "AsymmetricKeyLifecycleServerKMIPV1_2",
		BasicCryptographicClientKMIPV1_2:                  "BasicCryptographicClientKMIPV1_2",
		BasicCryptographicServerKMIPV1_2:                  "BasicCryptographicServerKMIPV1_2",
		AdvancedCryptographicClientKMIPV1_2:               "AdvancedCryptographicClientKMIPV1_2",
		AdvancedCryptographicServerKMIPV1_2:               "AdvancedCryptographicServerKMIPV1_2",
		RNGCryptographicClientKMIPV1_2:                    "RNGCryptographicClientKMIPV1_2",
		RNGCryptographicServerKMIPV1_2:                    "RNGCryptographicServerKMIPV1_2",
		BasicSymmetricKeyFoundryClientKMIPV1_0:            "BasicSymmetricKeyFoundryClientKMIPV1_0",
		IntermediateSymmetricKeyFoundryClientKMIPV1_0:     "IntermediateSymmetricKeyFoundryClientKMIPV1_0",
		AdvancedSymmetricKeyFoundryClientKMIPV1_0:         "AdvancedSymmetricKeyFoundryClientKMIPV1_0",
		BasicSymmetricKeyFoundryClientKMIPV1_1:            "BasicSymmetricKeyFoundryClientKMIPV1_1",
		IntermediateSymmetricKeyFoundryClientKMIPV1_1:     "IntermediateSymmetricKeyFoundryClientKMIPV1_1",
		AdvancedSymmetricKeyFoundryClientKMIPV1_1:         "AdvancedSymmetricKeyFoundryClientKMIPV1_1",
		BasicSymmetricKeyFoundryClientKMIPV1_2:            "BasicSymmetricKeyFoundryClientKMIPV1_2",
		IntermediateSymmetricKeyFoundryClientKMIPV1_2:     "IntermediateSymmetricKeyFoundryClientKMIPV1_2",
		AdvancedSymmetricKeyFoundryClientKMIPV1_2:         "AdvancedSymmetricKeyFoundryClientKMIPV1_2",
		SymmetricKeyFoundryServerKMIPV1_0:                 "SymmetricKeyFoundryServerKMIPV1_0",
		SymmetricKeyFoundryServerKMIPV1_1:                 "SymmetricKeyFoundryServerKMIPV1_1",
		SymmetricKeyFoundryServerKMIPV1_2:                 "SymmetricKeyFoundryServerKMIPV1_2",
		OpaqueManagedObjectStoreClientKMIPV1_0:            "OpaqueManagedObjectStoreClientKMIPV1_0",
		OpaqueManagedObjectStoreClientKMIPV1_1:            "OpaqueManagedObjectStoreClientKMIPV1_1",
		OpaqueManagedObjectStoreClientKMIPV1_2:            "OpaqueManagedObjectStoreClientKMIPV1_2",
		OpaqueManagedObjectStoreServerKMIPV1_0:            "OpaqueManagedObjectStoreServerKMIPV1_0",
		OpaqueManagedObjectStoreServerKMIPV1_1:            "OpaqueManagedObjectStoreServerKMIPV1_1",
		OpaqueManagedObjectStoreServerKMIPV1_2:            "OpaqueManagedObjectStoreServerKMIPV1_2",
		SuiteBMinLOS_128ClientKMIPV1_0:                    "SuiteBMinLOS_128ClientKMIPV1_0",
		SuiteBMinLOS_128ClientKMIPV1_1:                    "SuiteBMinLOS_128ClientKMIPV1_1",
		SuiteBMinLOS_128ClientKMIPV1_2:                    "SuiteBMinLOS_128ClientKMIPV1_2",
		SuiteBMinLOS_128ServerKMIPV1_0:                    "SuiteBMinLOS_128ServerKMIPV1_0",
		SuiteBMinLOS_128ServerKMIPV1_1:                    "SuiteBMinLOS_128ServerKMIPV1_1",
		SuiteBMinLOS_128ServerKMIPV1_2:                    "SuiteBMinLOS_128ServerKMIPV1_2",
		SuiteBMinLOS_192ClientKMIPV1_0:                    "SuiteBMinLOS_192ClientKMIPV1_0",
		SuiteBMinLOS_192ClientKMIPV1_1:                    "SuiteBMinLOS_192ClientKMIPV1_1",
		SuiteBMinLOS_192ClientKMIPV1_2:                    "SuiteBMinLOS_192ClientKMIPV1_2",
		SuiteBMinLOS_192ServerKMIPV1_0:                    "SuiteBMinLOS_192ServerKMIPV1_0",
		SuiteBMinLOS_192ServerKMIPV1_1:                    "SuiteBMinLOS_192ServerKMIPV1_1",
		SuiteBMinLOS_192ServerKMIPV1_2:                    "SuiteBMinLOS_192ServerKMIPV1_2",
		StorageArrayWithSelfEncryptingDriveClientKMIPV1_0: "StorageArrayWithSelfEncryptingDriveClientKMIPV1_0",
		StorageArrayWithSelfEncryptingDriveClientKMIPV1_1: "StorageArrayWithSelfEncryptingDriveClientKMIPV1_1",
		StorageArrayWithSelfEncryptingDriveClientKMIPV1_2: "StorageArrayWithSelfEncryptingDriveClientKMIPV1_2",
		StorageArrayWithSelfEncryptingDriveServerKMIPV1_0: "StorageArrayWithSelfEncryptingDriveServerKMIPV1_0",
		StorageArrayWithSelfEncryptingDriveServerKMIPV1_1: "StorageArrayWithSelfEncryptingDriveServerKMIPV1_1",
		StorageArrayWithSelfEncryptingDriveServerKMIPV1_2: "StorageArrayWithSelfEncryptingDriveServerKMIPV1_2",
		HTTPSClientKMIPV1_0:                               "HTTPSClientKMIPV1_0",
		HTTPSClientKMIPV1_1:                               "HTTPSClientKMIPV1_1",
		HTTPSClientKMIPV1_2:                               "HTTPSClientKMIPV1_2",
		HTTPSServerKMIPV1_0:                               "HTTPSServerKMIPV1_0",
		HTTPSServerKMIPV1_1:                               "HTTPSServerKMIPV1_1",
		HTTPSServerKMIPV1_2:                               "HTTPSServerKMIPV1_2",
		JSONClientKMIPV1_0:                                "JSONClientKMIPV1_0",
		JSONClientKMIPV1_1:                                "JSONClientKMIPV1_1",
		JSONClientKMIPV1_2:                                "JSONClientKMIPV1_2",
		JSONServerKMIPV1_0:                                "JSONServerKMIPV1_0",
		JSONServerKMIPV1_1:                                "JSONServerKMIPV1_1",
		JSONServerKMIPV1_2:                                "JSONServerKMIPV1_2",
		XMLClientKMIPV1_0:                                 "XMLClientKMIPV1_0",
		XMLClientKMIPV1_1:                                 "XMLClientKMIPV1_1",
		XMLClientKMIPV1_2:                                 "XMLClientKMIPV1_2",
		XMLServerKMIPV1_0:                                 "XMLServerKMIPV1_0",
		XMLServerKMIPV1_1:                                 "XMLServerKMIPV1_1",
		XMLServerKMIPV1_2:                                 "XMLServerKMIPV1_2",
		BaselineServerBasicKMIPV1_3:                       "BaselineServerBasicKMIPV1_3",
		BaselineServerTLSV1_2KMIPV1_3:                     "BaselineServerTLSV1_2KMIPV1_3",
		BaselineClientBasicKMIPV1_3:                       "BaselineClientBasicKMIPV1_3",
		BaselineClientTLSV1_2KMIPV1_3:                     "BaselineClientTLSV1_2KMIPV1_3",
		CompleteServerBasicKMIPV1_3:                       "CompleteServerBasicKMIPV1_3",
		CompleteServerTLSV1_2KMIPV1_3:                     "CompleteServerTLSV1_2KMIPV1_3",
		TapeLibraryClientKMIPV1_3:                         "TapeLibraryClientKMIPV1_3",
		TapeLibraryServerKMIPV1_3:                         "TapeLibraryServerKMIPV1_3",
		SymmetricKeyLifecycleClientKMIPV1_3:               "SymmetricKeyLifecycleClientKMIPV1_3",
		SymmetricKeyLifecycleServerKMIPV1_3:               "SymmetricKeyLifecycleServerKMIPV1_3",
		AsymmetricKeyLifecycleClientKMIPV1_3:              "AsymmetricKeyLifecycleClientKMIPV1_3",
		AsymmetricKeyLifecycleServerKMIPV1_3:              "AsymmetricKeyLifecycleServerKMIPV1_3",
		BasicCryptographicClientKMIPV1_3:                  "BasicCryptographicClientKMIPV1_3",
		BasicCryptographicServerKMIPV1_3:                  "BasicCryptographicServerKMIPV1_3",
		AdvancedCryptographicClientKMIPV1_3:               "AdvancedCryptographicClientKMIPV1_3",
		AdvancedCryptographicServerKMIPV1_3:               "AdvancedCryptographicServerKMIPV1_3",
		RNGCryptographicClientKMIPV1_3:                    "RNGCryptographicClientKMIPV1_3",
		RNGCryptographicServerKMIPV1_3:                    "RNGCryptographicServerKMIPV1_3",
		BasicSymmetricKeyFoundryClientKMIPV1_3:            "BasicSymmetricKeyFoundryClientKMIPV1_3",
		IntermediateSymmetricKeyFoundryClientKMIPV1_3:     "IntermediateSymmetricKeyFoundryClientKMIPV1_3",
		AdvancedSymmetricKeyFoundryClientKMIPV1_3:         "AdvancedSymmetricKeyFoundryClientKMIPV1_3",
		SymmetricKeyFoundryServerKMIPV1_3:                 "SymmetricKeyFoundryServerKMIPV1_3",
		OpaqueManagedObjectStoreClientKMIPV1_3:            "OpaqueManagedObjectStoreClientKMIPV1_3",
		OpaqueManagedObjectStoreServerKMIPV1_3:            "OpaqueManagedObjectStoreServerKMIPV1_3",
		SuiteBMinLOS_128ClientKMIPV1_3:                    "SuiteBMinLOS_128ClientKMIPV1_3",
		SuiteBMinLOS_128ServerKMIPV1_3:                    "SuiteBMinLOS_128ServerKMIPV1_3",
		SuiteBMinLOS_192ClientKMIPV1_3:                    "SuiteBMinLOS_192ClientKMIPV1_3",
		SuiteBMinLOS_192ServerKMIPV1_3:                    "SuiteBMinLOS_192ServerKMIPV1_3",
		StorageArrayWithSelfEncryptingDriveClientKMIPV1_3: "StorageArrayWithSelfEncryptingDriveClientKMIPV1_3",
		StorageArrayWithSelfEncryptingDriveServerKMIPV1_3: "StorageArrayWithSelfEncryptingDriveServerKMIPV1_3",
		HTTPSClientKMIPV1_3:                               "HTTPSClientKMIPV1_3",
		HTTPSServerKMIPV1_3:                               "HTTPSServerKMIPV1_3",
		JSONClientKMIPV1_3:                                "JSONClientKMIPV1_3",
		JSONServerKMIPV1_3:                                "JSONServerKMIPV1_3",
		XMLClientKMIPV1_3:                                 "XMLClientKMIPV1_3",
		XMLServerKMIPV1_3:                                 "XMLServerKMIPV1_3",

		// KMIP 1.4.
		BaselineServerBasicKMIPV1_4:                       "BaselineServerBasicKMIPV1_4",
		BaselineServerTLSV1_2KMIPV1_4:                     "BaselineServerTLSV1_2KMIPV1_4",
		BaselineClientBasicKMIPV1_4:                       "BaselineClientBasicKMIPV1_4",
		BaselineClientTLSV1_2KMIPV1_4:                     "BaselineClientTLSV1_2KMIPV1_4",
		CompleteServerBasicKMIPV1_4:                       "CompleteServerBasicKMIPV1_4",
		CompleteServerTLSV1_2KMIPV1_4:                     "CompleteServerTLSV1_2KMIPV1_4",
		TapeLibraryClientKMIPV1_4:                         "TapeLibraryClientKMIPV1_4",
		TapeLibraryServerKMIPV1_4:                         "TapeLibraryServerKMIPV1_4",
		SymmetricKeyLifecycleClientKMIPV1_4:               "SymmetricKeyLifecycleClientKMIPV1_4",
		SymmetricKeyLifecycleServerKMIPV1_4:               "SymmetricKeyLifecycleServerKMIPV1_4",
		AsymmetricKeyLifecycleClientKMIPV1_4:              "AsymmetricKeyLifecycleClientKMIPV1_4",
		AsymmetricKeyLifecycleServerKMIPV1_4:              "AsymmetricKeyLifecycleServerKMIPV1_4",
		BasicCryptographicClientKMIPV1_4:                  "BasicCryptographicClientKMIPV1_4",
		BasicCryptographicServerKMIPV1_4:                  "BasicCryptographicServerKMIPV1_4",
		AdvancedCryptographicClientKMIPV1_4:               "AdvancedCryptographicClientKMIPV1_4",
		AdvancedCryptographicServerKMIPV1_4:               "AdvancedCryptographicServerKMIPV1_4",
		RNGCryptographicClientKMIPV1_4:                    "RNGCryptographicClientKMIPV1_4",
		RNGCryptographicServerKMIPV1_4:                    "RNGCryptographicServerKMIPV1_4",
		BasicSymmetricKeyFoundryClientKMIPV1_4:            "BasicSymmetricKeyFoundryClientKMIPV1_4",
		IntermediateSymmetricKeyFoundryClientKMIPV1_4:     "IntermediateSymmetricKeyFoundryClientKMIPV1_4",
		AdvancedSymmetricKeyFoundryClientKMIPV1_4:         "AdvancedSymmetricKeyFoundryClientKMIPV1_4",
		SymmetricKeyFoundryServerKMIPV1_4:                 "SymmetricKeyFoundryServerKMIPV1_4",
		OpaqueManagedObjectStoreClientKMIPV1_4:            "OpaqueManagedObjectStoreClientKMIPV1_4",
		OpaqueManagedObjectStoreServerKMIPV1_4:            "OpaqueManagedObjectStoreServerKMIPV1_4",
		SuiteBMinLOS_128ClientKMIPV1_4:                    "SuiteBMinLOS_128ClientKMIPV1_4",
		SuiteBMinLOS_128ServerKMIPV1_4:                    "SuiteBMinLOS_128ServerKMIPV1_4",
		SuiteBMinLOS_192ClientKMIPV1_4:                    "SuiteBMinLOS_192ClientKMIPV1_4",
		SuiteBMinLOS_192ServerKMIPV1_4:                    "SuiteBMinLOS_192ServerKMIPV1_4",
		StorageArrayWithSelfEncryptingDriveClientKMIPV1_4: "StorageArrayWithSelfEncryptingDriveClientKMIPV1_4",
		StorageArrayWithSelfEncryptingDriveServerKMIPV1_4: "StorageArrayWithSelfEncryptingDriveServerKMIPV1_4",
		HTTPSClientKMIPV1_4:                               "HTTPSClientKMIPV1_4",
		HTTPSServerKMIPV1_4:                               "HTTPSServerKMIPV1_4",
		JSONClientKMIPV1_4:                                "JSONClientKMIPV1_4",
		JSONServerKMIPV1_4:                                "JSONServerKMIPV1_4",
		XMLClientKMIPV1_4:                                 "XMLClientKMIPV1_4",
		XMLServerKMIPV1_4:                                 "XMLServerKMIPV1_4",
	})
	ttlv.RegisterEnum(TagValidationAuthorityType, map[ValidationAuthorityType]string{
		ValidationAuthorityTypeUnspecified:    "Unspecified",
		ValidationAuthorityTypeNISTCMVP:       "NISTCMVP",
		ValidationAuthorityTypeCommonCriteria: "CommonCriteria",
	})
	ttlv.RegisterEnum(TagValidationType, map[ValidationType]string{
		ValidationTypeUnspecified: "Unspecified",
		ValidationTypeHardware:    "Hardware",
		ValidationTypeSoftware:    "Software",
		ValidationTypeFirmware:    "Firmware",
		ValidationTypeHybrid:      "Hybrid",
	})
	ttlv.RegisterEnum(TagUnwrapMode, map[UnwrapMode]string{
		UnwrapModeUnspecified:  "Unspecified",
		UnwrapModeProcessed:    "Processed",
		UnwrapModeNotProcessed: "NotProcessed",
	})
	ttlv.RegisterEnum(TagDestroyAction, map[DestroyAction]string{
		DestroyActionUnspecified:         "Unspecified",
		DestroyActionKeyMaterialDeleted:  "KeyMaterialDeleted",
		DestroyActionKeyMaterialShredded: "KeyMaterialShredded",
		DestroyActionMetaDataDeleted:     "MetaDataDeleted",
		DestroyActionMetaDataShredded:    "MetaDataShredded",
		DestroyActionDeleted:             "Deleted",
		DestroyActionShredded:            "Shredded",
	})
	ttlv.RegisterEnum(TagShreddingAlgorithm, map[ShreddingAlgorithm]string{
		ShreddingAlgorithmUnspecified:   "Unspecified",
		ShreddingAlgorithmCryptographic: "Cryptographic",
		ShreddingAlgorithmUnsupported:   "Unsupported",
	})
	ttlv.RegisterEnum(TagRNGMode, map[RNGMode]string{
		RNGModeUnspecified:            "Unspecified",
		RNGModeSharedInstantiation:    "SharedInstantiation",
		RNGModeNonSharedInstantiation: "NonSharedInstantiation",
	})
	ttlv.RegisterEnum(TagClientRegistrationMethod, map[ClientRegistrationMethod]string{
		ClientRegistrationMethodUnspecified:        "Unspecified",
		ClientRegistrationMethodServerPreGenerated: "ServerPreGenerated",
		ClientRegistrationMethodServerOnDemand:     "ServerOnDemand",
		ClientRegistrationMethodClientGenerated:    "ClientGenerated",
		ClientRegistrationMethodClientRegistered:   "ClientRegistered",
	})
	ttlv.RegisterEnum(TagMaskGenerator, map[MaskGenerator]string{
		MGF1: "MGF1",
	})
}

type ResultStatus uint32

const (
	StatusSuccess ResultStatus = iota
	StatusOperationFailed
	StatusOperationPending
	StatusOperationUndone
)

type ResultReason uint32

// See https://docs.oasis-open.org/kmip/spec/v1.4/errata01/os/kmip-spec-v1.4-errata01-os-redlined.html#_Toc490660949
const (
	ReasonItemNotFound                     ResultReason = 0x00000001
	ReasonResponseTooLarge                 ResultReason = 0x00000002
	ReasonAuthenticationNotSuccessful      ResultReason = 0x00000003
	ReasonInvalidMessage                   ResultReason = 0x00000004
	ReasonOperationNotSupported            ResultReason = 0x00000005
	ReasonMissingData                      ResultReason = 0x00000006
	ReasonInvalidField                     ResultReason = 0x00000007
	ReasonFeatureNotSupported              ResultReason = 0x00000008
	ReasonOperationCanceledByRequester     ResultReason = 0x00000009
	ReasonCryptographicFailure             ResultReason = 0x0000000A
	ReasonIllegalOperation                 ResultReason = 0x0000000B
	ReasonPermissionDenied                 ResultReason = 0x0000000C
	ReasonObjectarchived                   ResultReason = 0x0000000D
	ReasonIndexOutofBounds                 ResultReason = 0x0000000E
	ReasonApplicationNamespaceNotSupported ResultReason = 0x0000000F
	ReasonKeyFormatTypeNotSupported        ResultReason = 0x00000010
	ReasonKeyCompressionTypeNotSupported   ResultReason = 0x00000011
	// KMIP 1.1.
	ReasonEncodingOptionError ResultReason = 0x00000012
	// KMIP 1.2.
	ReasonKeyValueNotPresent  ResultReason = 0x00000013
	ReasonAttestationRequired ResultReason = 0x00000014
	ReasonAttestationFailed   ResultReason = 0x00000015

	// KMIP 1.4.
	Sensitive           ResultReason = 0x00000016
	NotExtractable      ResultReason = 0x00000017
	ObjectAlreadyExists ResultReason = 0x00000018

	ReasonGeneralFailure ResultReason = 0x00000100
)

type CredentialType uint32

const (
	CredentialUsernameAndPassword CredentialType = 0x00000001
	// KMIP 1.1.
	CredentialDevice CredentialType = 0x00000002
	// KMIP 1.2.
	CredentialAttestation CredentialType = 0x00000003
)

type RevocationReasonCode uint32

const (
	RevocationReasonCodeUnspecified          RevocationReasonCode = 0x00000001
	RevocationReasonCodeKeyCompromise        RevocationReasonCode = 0x00000002
	RevocationReasonCodeCACompromise         RevocationReasonCode = 0x00000003
	RevocationReasonCodeAffiliationChanged   RevocationReasonCode = 0x00000004
	RevocationReasonCodeSuperseded           RevocationReasonCode = 0x00000005
	RevocationReasonCodeCessationOfOperation RevocationReasonCode = 0x00000006
	RevocationReasonCodePrivilegeWithdrawn   RevocationReasonCode = 0x00000007
	// Extensions 8XXXXXXX
)

type BatchErrorContinuationOption uint32

const (
	Continue BatchErrorContinuationOption = 1
	Stop     BatchErrorContinuationOption = 2
	Undo     BatchErrorContinuationOption = 3
)

type NameType uint32

const (
	UninterpretedTextString NameType = 1
	Uri                     NameType = 2
)

type ObjectType uint32

const (
	ObjectTypeCertificate  ObjectType = 0x00000001
	ObjectTypeSymmetricKey ObjectType = 0x00000002
	ObjectTypePublicKey    ObjectType = 0x00000003
	ObjectTypePrivateKey   ObjectType = 0x00000004
	ObjectTypeSplitKey     ObjectType = 0x00000005
	// Deprecated: deprecated as of kmip 1.3.
	ObjectTypeTemplate     ObjectType = 0x00000006
	ObjectTypeSecretData   ObjectType = 0x00000007
	ObjectTypeOpaqueObject ObjectType = 0x00000008
	// KMIP 1.2.
	ObjectTypePGPKey ObjectType = 0x00000009
)

type OpaqueDataType uint32

type State uint32

const (
	StatePreActive            State = 0x00000001
	StateActive               State = 0x00000002
	StateDeactivated          State = 0x00000003
	StateCompromised          State = 0x00000004
	StateDestroyed            State = 0x00000005
	StateDestroyedCompromised State = 0x00000006
)

type CryptographicAlgorithm uint32

const (
	DES        CryptographicAlgorithm = 0x00000001
	TDES       CryptographicAlgorithm = 0x00000002
	AES        CryptographicAlgorithm = 0x00000003
	RSA        CryptographicAlgorithm = 0x00000004
	DSA        CryptographicAlgorithm = 0x00000005
	ECDSA      CryptographicAlgorithm = 0x00000006
	HMACSHA1   CryptographicAlgorithm = 0x00000007
	HMACSHA224 CryptographicAlgorithm = 0x00000008
	HMACSHA256 CryptographicAlgorithm = 0x00000009
	HMACSHA384 CryptographicAlgorithm = 0x0000000A
	HMACSHA512 CryptographicAlgorithm = 0x0000000B
	HMACMD5    CryptographicAlgorithm = 0x0000000C
	DH         CryptographicAlgorithm = 0x0000000D
	ECDH       CryptographicAlgorithm = 0x0000000E
	ECMQV      CryptographicAlgorithm = 0x0000000F
	Blowfish   CryptographicAlgorithm = 0x00000010
	Camellia   CryptographicAlgorithm = 0x00000011
	CAST5      CryptographicAlgorithm = 0x00000012
	IDEA       CryptographicAlgorithm = 0x00000013
	MARS       CryptographicAlgorithm = 0x00000014
	RC2        CryptographicAlgorithm = 0x00000015
	RC4        CryptographicAlgorithm = 0x00000016
	RC5        CryptographicAlgorithm = 0x00000017
	SKIPJACK   CryptographicAlgorithm = 0x00000018
	Twofish    CryptographicAlgorithm = 0x00000019

	// KMIP 1.2.
	EC CryptographicAlgorithm = 0x0000001A

	// KMIP 1.3.
	OneTimePad CryptographicAlgorithm = 0x0000001B

	// KMIP 1.4.
	ChaCha20         CryptographicAlgorithm = 0x0000001C
	Poly1305         CryptographicAlgorithm = 0x0000001D
	ChaCha20Poly1305 CryptographicAlgorithm = 0x0000001E
	SHA3_224         CryptographicAlgorithm = 0x0000001F
	SHA3_256         CryptographicAlgorithm = 0x00000020
	SHA3_384         CryptographicAlgorithm = 0x00000021
	SHA3_512         CryptographicAlgorithm = 0x00000022
	HMAC_SHA3_224    CryptographicAlgorithm = 0x00000023
	HMAC_SHA3_256    CryptographicAlgorithm = 0x00000024
	HMAC_SHA3_384    CryptographicAlgorithm = 0x00000025
	HMAC_SHA3_512    CryptographicAlgorithm = 0x00000026
	SHAKE_128        CryptographicAlgorithm = 0x00000027
	SHAKE_256        CryptographicAlgorithm = 0x00000028
)

type BlockCipherMode uint32

const (
	CBC               BlockCipherMode = 0x00000001
	ECB               BlockCipherMode = 0x00000002
	PCBC              BlockCipherMode = 0x00000003
	CFB               BlockCipherMode = 0x00000004
	OFB               BlockCipherMode = 0x00000005
	CTR               BlockCipherMode = 0x00000006
	CMAC              BlockCipherMode = 0x00000007
	CCM               BlockCipherMode = 0x00000008
	GCM               BlockCipherMode = 0x00000009
	CBCMAC            BlockCipherMode = 0x0000000A
	XTS               BlockCipherMode = 0x0000000B
	AESKeyWrapPadding BlockCipherMode = 0x0000000C
	NISTKeyWrap       BlockCipherMode = 0x0000000D
	X9_102AESKW       BlockCipherMode = 0x0000000E
	X9_102TDKW        BlockCipherMode = 0x0000000F
	X9_102AKW1        BlockCipherMode = 0x00000010
	X9_102AKW2        BlockCipherMode = 0x00000011
	// KMIP 1.4.
	AEAD BlockCipherMode = 0x00000012
)

type PaddingMethod uint32

const (
	None      PaddingMethod = 0x00000001
	OAEP      PaddingMethod = 0x00000002
	PKCS5     PaddingMethod = 0x00000003
	SSL3      PaddingMethod = 0x00000004
	Zeros     PaddingMethod = 0x00000005
	ANSIX9_23 PaddingMethod = 0x00000006
	ISO10126  PaddingMethod = 0x00000007
	PKCS1V1_5 PaddingMethod = 0x00000008
	X9_31     PaddingMethod = 0x00000009
	PSS       PaddingMethod = 0x0000000A
)

type HashingAlgorithm uint32

const (
	MD2        HashingAlgorithm = 0x00000001
	MD4        HashingAlgorithm = 0x00000002
	MD5        HashingAlgorithm = 0x00000003
	SHA_1      HashingAlgorithm = 0x00000004
	SHA_224    HashingAlgorithm = 0x00000005
	SHA_256    HashingAlgorithm = 0x00000006
	SHA_384    HashingAlgorithm = 0x00000007
	SHA_512    HashingAlgorithm = 0x00000008
	RIPEMD_160 HashingAlgorithm = 0x00000009
	Tiger      HashingAlgorithm = 0x0000000A
	Whirlpool  HashingAlgorithm = 0x0000000B

	// KMIP 1.2.
	SHA_512_224 HashingAlgorithm = 0x0000000C
	SHA_512_256 HashingAlgorithm = 0x0000000D

	// KMIP 1.4.
	SHA_3_224 HashingAlgorithm = 0x0000000E
	SHA_3_256 HashingAlgorithm = 0x0000000F
	SHA_3_384 HashingAlgorithm = 0x00000010
	SHA_3_512 HashingAlgorithm = 0x00000011
)

type KeyRoleType uint32

const (
	BDK      KeyRoleType = 0x00000001
	CVK      KeyRoleType = 0x00000002
	DEK      KeyRoleType = 0x00000003
	MKAC     KeyRoleType = 0x00000004
	MKSMC    KeyRoleType = 0x00000005
	MKSMI    KeyRoleType = 0x00000006
	MKDAC    KeyRoleType = 0x00000007
	MKDN     KeyRoleType = 0x00000008
	MKCP     KeyRoleType = 0x00000009
	MKOTH    KeyRoleType = 0x0000000A
	KEK      KeyRoleType = 0x0000000B
	MAC16609 KeyRoleType = 0x0000000C
	MAC97971 KeyRoleType = 0x0000000D
	MAC97972 KeyRoleType = 0x0000000E
	MAC97973 KeyRoleType = 0x0000000F
	MAC97974 KeyRoleType = 0x00000010
	MAC97975 KeyRoleType = 0x00000011
	ZPK      KeyRoleType = 0x00000012
	PVKIBM   KeyRoleType = 0x00000013
	PVKPVV   KeyRoleType = 0x00000014
	PVKOTH   KeyRoleType = 0x00000015

	// KMIP 1.4.
	DUKPT KeyRoleType = 0x00000016
	IV    KeyRoleType = 0x00000017
	TRKBK KeyRoleType = 0x00000018
)

type RecommendedCurve uint32

const (
	P_192 RecommendedCurve = 0x00000001
	K_163 RecommendedCurve = 0x00000002
	B_163 RecommendedCurve = 0x00000003
	P_224 RecommendedCurve = 0x00000004
	K_233 RecommendedCurve = 0x00000005
	B_233 RecommendedCurve = 0x00000006
	P_256 RecommendedCurve = 0x00000007
	K_283 RecommendedCurve = 0x00000008
	B_283 RecommendedCurve = 0x00000009
	P_384 RecommendedCurve = 0x0000000A
	K_409 RecommendedCurve = 0x0000000B
	B_409 RecommendedCurve = 0x0000000C
	P_521 RecommendedCurve = 0x0000000D
	K_571 RecommendedCurve = 0x0000000E
	B_571 RecommendedCurve = 0x0000000F

	// KMIP 1.2.
	SECP112R1        RecommendedCurve = 0x00000010
	SECP112R2        RecommendedCurve = 0x00000011
	SECP128R1        RecommendedCurve = 0x00000012
	SECP128R2        RecommendedCurve = 0x00000013
	SECP160K1        RecommendedCurve = 0x00000014
	SECP160R1        RecommendedCurve = 0x00000015
	SECP160R2        RecommendedCurve = 0x00000016
	SECP192K1        RecommendedCurve = 0x00000017
	SECP224K1        RecommendedCurve = 0x00000018
	SECP256K1        RecommendedCurve = 0x00000019
	SECT113R1        RecommendedCurve = 0x0000001A
	SECT113R2        RecommendedCurve = 0x0000001B
	SECT131R1        RecommendedCurve = 0x0000001C
	SECT131R2        RecommendedCurve = 0x0000001D
	SECT163R1        RecommendedCurve = 0x0000001E
	SECT193R1        RecommendedCurve = 0x0000001F
	SECT193R2        RecommendedCurve = 0x00000020
	SECT239K1        RecommendedCurve = 0x00000021
	ANSIX9P192V2     RecommendedCurve = 0x00000022
	ANSIX9P192V3     RecommendedCurve = 0x00000023
	ANSIX9P239V1     RecommendedCurve = 0x00000024
	ANSIX9P239V2     RecommendedCurve = 0x00000025
	ANSIX9P239V3     RecommendedCurve = 0x00000026
	ANSIX9C2PNB163V1 RecommendedCurve = 0x00000027
	ANSIX9C2PNB163V2 RecommendedCurve = 0x00000028
	ANSIX9C2PNB163V3 RecommendedCurve = 0x00000029
	ANSIX9C2PNB176V1 RecommendedCurve = 0x0000002A
	ANSIX9C2TNB191V1 RecommendedCurve = 0x0000002B
	ANSIX9C2TNB191V2 RecommendedCurve = 0x0000002C
	ANSIX9C2TNB191V3 RecommendedCurve = 0x0000002D
	ANSIX9C2PNB208W1 RecommendedCurve = 0x0000002E
	ANSIX9C2TNB239V1 RecommendedCurve = 0x0000002F
	ANSIX9C2TNB239V2 RecommendedCurve = 0x00000030
	ANSIX9C2TNB239V3 RecommendedCurve = 0x00000031
	ANSIX9C2PNB272W1 RecommendedCurve = 0x00000032
	ANSIX9C2PNB304W1 RecommendedCurve = 0x00000033
	ANSIX9C2TNB359V1 RecommendedCurve = 0x00000034
	ANSIX9C2PNB368W1 RecommendedCurve = 0x00000035
	ANSIX9C2TNB431R1 RecommendedCurve = 0x00000036
	BRAINPOOLP160R1  RecommendedCurve = 0x00000037
	BRAINPOOLP160T1  RecommendedCurve = 0x00000038
	BRAINPOOLP192R1  RecommendedCurve = 0x00000039
	BRAINPOOLP192T1  RecommendedCurve = 0x0000003A
	BRAINPOOLP224R1  RecommendedCurve = 0x0000003B
	BRAINPOOLP224T1  RecommendedCurve = 0x0000003C
	BRAINPOOLP256R1  RecommendedCurve = 0x0000003D
	BRAINPOOLP256T1  RecommendedCurve = 0x0000003E
	BRAINPOOLP320R1  RecommendedCurve = 0x0000003F
	BRAINPOOLP320T1  RecommendedCurve = 0x00000040
	BRAINPOOLP384R1  RecommendedCurve = 0x00000041
	BRAINPOOLP384T1  RecommendedCurve = 0x00000042
	BRAINPOOLP512R1  RecommendedCurve = 0x00000043
	BRAINPOOLP512T1  RecommendedCurve = 0x00000044
)

func (crv RecommendedCurve) Bitlen() int32 {
	switch crv {
	case P_192, SECP192K1, ANSIX9P192V2, ANSIX9P192V3, BRAINPOOLP192R1, BRAINPOOLP192T1:
		return 192
	case K_163, B_163, SECT163R1, ANSIX9C2PNB163V1, ANSIX9C2PNB163V2, ANSIX9C2PNB163V3:
		return 163
	case P_256, SECP256K1, BRAINPOOLP256R1, BRAINPOOLP256T1:
		return 256
	case P_224, SECP224K1:
		return 224
	case K_233, B_233:
		return 233
	case K_283, B_283:
		return 283
	case P_384, BRAINPOOLP384R1, BRAINPOOLP384T1:
		return 384
	case K_409, B_409:
		return 409
	case P_521:
		return 521
	case K_571, B_571:
		return 571
	case SECP112R1, SECP112R2:
		return 112
	case SECP128R1, SECP128R2:
		return 128
	case SECP160K1, SECP160R1, SECP160R2, BRAINPOOLP160R1, BRAINPOOLP160T1:
		return 160
	case SECT113R1, SECT113R2:
		return 113
	case SECT131R1, SECT131R2:
		return 131
	case SECT193R1, SECT193R2:
		return 193
	case SECT239K1, ANSIX9P239V1, ANSIX9P239V2, ANSIX9P239V3, ANSIX9C2TNB239V1, ANSIX9C2TNB239V2, ANSIX9C2TNB239V3:
		return 239
	case ANSIX9C2PNB176V1:
		return 176
	case ANSIX9C2TNB191V1, ANSIX9C2TNB191V2, ANSIX9C2TNB191V3:
		return 191
	case ANSIX9C2PNB208W1:
		return 208
	case ANSIX9C2PNB272W1:
		return 272
	case ANSIX9C2PNB304W1:
		return 304
	case ANSIX9C2TNB359V1:
		return 359
	case ANSIX9C2PNB368W1:
		return 368
	case ANSIX9C2TNB431R1:
		return 431
	case BRAINPOOLP224R1, BRAINPOOLP224T1:
		return 224
	case BRAINPOOLP320R1, BRAINPOOLP320T1:
		return 320
	case BRAINPOOLP512R1, BRAINPOOLP512T1:
		return 512
	default:
		return 0
	}
}

type SecretDataType uint32

const (
	Password SecretDataType = 0x00000001
	Seed     SecretDataType = 0x00000002
)

type KeyFormatType uint32

const (
	KeyFormatRaw                      KeyFormatType = 0x00000001
	KeyFormatOpaque                   KeyFormatType = 0x00000002
	KeyFormatPKCS_1                   KeyFormatType = 0x00000003
	KeyFormatPKCS_8                   KeyFormatType = 0x00000004
	KeyFormatX_509                    KeyFormatType = 0x00000005
	KeyFormatECPrivateKey             KeyFormatType = 0x00000006
	KeyFormatTransparentSymmetricKey  KeyFormatType = 0x00000007
	KeyFormatTransparentDSAPrivateKey KeyFormatType = 0x00000008
	KeyFormatTransparentDSAPublicKey  KeyFormatType = 0x00000009
	KeyFormatTransparentRSAPrivateKey KeyFormatType = 0x0000000A
	KeyFormatTransparentRSAPublicKey  KeyFormatType = 0x0000000B
	KeyFormatTransparentDHPrivateKey  KeyFormatType = 0x0000000C
	KeyFormatTransparentDHPublicKey   KeyFormatType = 0x0000000D
	// Deprecated: deprecated as of kmip 1.3.
	KeyFormatTransparentECDSAPrivateKey KeyFormatType = 0x0000000E
	// Deprecated: deprecated as of kmip 1.3.
	KeyFormatTransparentECDSAPublicKey KeyFormatType = 0x0000000F
	// Deprecated: deprecated as of kmip 1.3.
	KeyFormatTransparentECDHPrivateKey KeyFormatType = 0x00000010
	// Deprecated: deprecated as of kmip 1.3.
	KeyFormatTransparentECDHPublicKey KeyFormatType = 0x00000011
	// Deprecated: deprecated as of kmip 1.3.
	KeyFormatTransparentECMQVPrivateKey KeyFormatType = 0x00000012
	// Deprecated: deprecated as of kmip 1.3.
	KeyFormatTransparentECMQVPublicKey KeyFormatType = 0x00000013

	// KMIP 1.3.
	KeyFormatTransparentECPrivateKey KeyFormatType = 0x00000014
	KeyFormatTransparentECPublicKey  KeyFormatType = 0x00000015

	// KMIP 1.4.
	KeyFormatPKCS_12 KeyFormatType = 0x00000016
)

type KeyCompressionType uint32

const (
	ECPublicKeyTypeUncompressed         KeyCompressionType = 0x00000001
	ECPublicKeyTypeX9_62CompressedPrime KeyCompressionType = 0x00000002
	ECPublicKeyTypeX9_62CompressedChar2 KeyCompressionType = 0x00000003
	ECPublicKeyTypeX9_62Hybrid          KeyCompressionType = 0x00000004
)

type WrappingMethod uint32

const (
	WrappingMethodEncrypt            WrappingMethod = 0x00000001
	WrappingMethodMACSign            WrappingMethod = 0x00000002
	WrappingMethodEncryptThenMACSign WrappingMethod = 0x00000003
	WrappingMethodMACSignThenEncrypt WrappingMethod = 0x00000004
	WrappingMethodTR_31              WrappingMethod = 0x00000005
)

type CertificateType uint32

const (
	X_509 CertificateType = 0x00000001
	// Deprecated: deprecated as of version 1.2.
	PGP CertificateType = 0x00000002
)

type LinkType uint32

const (
	CertificateLink          LinkType = 0x00000101
	PublicKeyLink            LinkType = 0x00000102
	PrivateKeyLink           LinkType = 0x00000103
	DerivationBaseObjectLink LinkType = 0x00000104
	DerivedKeyLink           LinkType = 0x00000105
	ReplacementObjectLink    LinkType = 0x00000106
	ReplacedObjectLink       LinkType = 0x00000107

	// KMIP 1.2.
	ParentLink   LinkType = 0x00000108
	ChildLink    LinkType = 0x00000109
	PreviousLink LinkType = 0x0000010A
	NextLink     LinkType = 0x0000010B

	// KMPI 1.4.
	PKCS_12CertificateLink LinkType = 0x0000010C
	PKCS_12PasswordLink    LinkType = 0x0000010D

	//FIXME: This is defined in KMIP 2.0+ only.
	WrappingKeyLink LinkType = 0x0000010E
	// Extensions 8XXXXXXX
)

type QueryFunction uint32

const (
	QueryOperations            QueryFunction = 0x00000001
	QueryObjects               QueryFunction = 0x00000002
	QueryServerInformation     QueryFunction = 0x00000003
	QueryApplicationNamespaces QueryFunction = 0x00000004
	// KMIP 1.1.
	QueryExtensionList QueryFunction = 0x00000005
	QueryExtensionMap  QueryFunction = 0x00000006
	// KMIP 1.2.
	QueryAttestationTypes QueryFunction = 0x00000007

	// KMIP 1.3.
	QueryRNGs                      QueryFunction = 0x00000008
	QueryValidations               QueryFunction = 0x00000009
	QueryProfiles                  QueryFunction = 0x0000000A
	QueryCapabilities              QueryFunction = 0x0000000B
	QueryClientRegistrationMethods QueryFunction = 0x0000000C
)

type UsageLimitsUnit uint32

const (
	UsageLimitsUnitByte   UsageLimitsUnit = 0x00000001
	UsageLimitsUnitObject UsageLimitsUnit = 0x00000002
)

type CancellationResult uint32

const (
	Canceled       CancellationResult = 0x00000001
	UnableToCancel CancellationResult = 0x00000002
	Completed      CancellationResult = 0x00000003
	Failed         CancellationResult = 0x00000004
	Unavailable    CancellationResult = 0x00000005
)

type PutFunction uint32

const (
	New     PutFunction = 0x00000001
	Replace PutFunction = 0x00000002
)

type CertificateRequestType uint32

const (
	CertificateRequestTypeCRMF    CertificateRequestType = 0x00000001
	CertificateRequestTypePKCS_10 CertificateRequestType = 0x00000002
	CertificateRequestTypePEM     CertificateRequestType = 0x00000003
	CertificateRequestTypePGP     CertificateRequestType = 0x00000004
)

// kmip 1.1.

type SplitKeyMethod uint32

const (
	SplitKeyMethodXOR                         SplitKeyMethod = 0x00000001
	SplitKeyMethodPolynomialSharingGF216      SplitKeyMethod = 0x00000002
	SplitKeyMethodPolynomialSharingPrimeField SplitKeyMethod = 0x00000003

	// KMIP 1.2.
	SplitKeyMethodPolynomialSharingGF28 SplitKeyMethod = 0x00000004
)

type ObjectGroupMember uint32

const (
	GroupMemberFresh   ObjectGroupMember = 0x00000001
	GroupMemberDefault ObjectGroupMember = 0x00000002
)

type EncodingOption uint32

const (
	NoEncoding   EncodingOption = 0x00000001
	TTLVEncoding EncodingOption = 0x00000002
)

type DigitalSignatureAlgorithm uint32

const (
	MD2WithRSAEncryptionPKCS_1v1_5     DigitalSignatureAlgorithm = 0x00000001
	MD5WithRSAEncryptionPKCS_1v1_5     DigitalSignatureAlgorithm = 0x00000002
	SHA_1WithRSAEncryptionPKCS_1v1_5   DigitalSignatureAlgorithm = 0x00000003
	SHA_224WithRSAEncryptionPKCS_1v1_5 DigitalSignatureAlgorithm = 0x00000004
	SHA_256WithRSAEncryptionPKCS_1v1_5 DigitalSignatureAlgorithm = 0x00000005
	SHA_384WithRSAEncryptionPKCS_1v1_5 DigitalSignatureAlgorithm = 0x00000006
	SHA_512WithRSAEncryptionPKCS_1v1_5 DigitalSignatureAlgorithm = 0x00000007
	RSASSA_PSSPKCS_1v2_1               DigitalSignatureAlgorithm = 0x00000008
	DSAWithSHA_1                       DigitalSignatureAlgorithm = 0x00000009
	DSAWithSHA224                      DigitalSignatureAlgorithm = 0x0000000A
	DSAWithSHA256                      DigitalSignatureAlgorithm = 0x0000000B
	ECDSAWithSHA_1                     DigitalSignatureAlgorithm = 0x0000000C
	ECDSAWithSHA224                    DigitalSignatureAlgorithm = 0x0000000D
	ECDSAWithSHA256                    DigitalSignatureAlgorithm = 0x0000000E
	ECDSAWithSHA384                    DigitalSignatureAlgorithm = 0x0000000F
	ECDSAWithSHA512                    DigitalSignatureAlgorithm = 0x00000010

	// KMIP 1.4.
	SHA3_256WithRSAEncryption DigitalSignatureAlgorithm = 0x00000011
	SHA3_384WithRSAEncryption DigitalSignatureAlgorithm = 0x00000012
	SHA3_512WithRSAEncryption DigitalSignatureAlgorithm = 0x00000013
)

// KMIP 1.2.

type AttestationType uint32

const (
	TPMQuote           AttestationType = 0x00000001
	TCGIntegrityReport AttestationType = 0x00000002
	SAMLAssertion      AttestationType = 0x00000003
)

type AlternativeNameType uint32

const (
	AlternativeNameTypeUninterpretedTextString AlternativeNameType = 0x00000001
	AlternativeNameTypeURI                     AlternativeNameType = 0x00000002
	AlternativeNameTypeObjectSerialNumber      AlternativeNameType = 0x00000003
	AlternativeNameTypeEmailAddress            AlternativeNameType = 0x00000004
	AlternativeNameTypeDNSName                 AlternativeNameType = 0x00000005
	AlternativeNameTypeX_500DistinguishedName  AlternativeNameType = 0x00000006
	AlternativeNameTypeIPAddress               AlternativeNameType = 0x00000007
)

type KeyValueLocationType uint32

const (
	KeyValueLocationTypeUninterpretedTextString KeyValueLocationType = 0x00000001
	KeyValueLocationTypeURI                     KeyValueLocationType = 0x00000002
)

type ValidityIndicator uint32

const (
	ValidityIndicatorValid   ValidityIndicator = 0x00000001
	ValidityIndicatorInvalid ValidityIndicator = 0x00000002
	ValidityIndicatorUnknown ValidityIndicator = 0x00000003
)

// KMIP 1.3.

type RNGAlgorithm uint32

const (
	RNGAlgorithmUnspecified RNGAlgorithm = 0x00000001
	RNGAlgorithmFIPS186_2   RNGAlgorithm = 0x00000002
	RNGAlgorithmDRBG        RNGAlgorithm = 0x00000003
	RNGAlgorithmNRBG        RNGAlgorithm = 0x00000004
	RNGAlgorithmANSIX9_31   RNGAlgorithm = 0x00000005
	RNGAlgorithmANSIX9_62   RNGAlgorithm = 0x00000006
)

type DRBGAlgorithm uint32

const (
	DRBGAlgorithmUnspecified DRBGAlgorithm = 0x00000001
	DRBGAlgorithmDual_EC     DRBGAlgorithm = 0x00000002
	DRBGAlgorithmHash        DRBGAlgorithm = 0x00000003
	DRBGAlgorithmHMAC        DRBGAlgorithm = 0x00000004
	DRBGAlgorithmCTR         DRBGAlgorithm = 0x00000005
)

type FIPS186Variation uint32

const (
	FIPS186VariationUnspecified     FIPS186Variation = 0x00000001
	FIPS186VariationGPXOriginal     FIPS186Variation = 0x00000002
	FIPS186VariationGPXChangeNotice FIPS186Variation = 0x00000003
	FIPS186VariationXOriginal       FIPS186Variation = 0x00000004
	FIPS186VariationXChangeNotice   FIPS186Variation = 0x00000005
	FIPS186VariationKOriginal       FIPS186Variation = 0x00000006
	FIPS186VariationKChangeNotice   FIPS186Variation = 0x00000007
)

type ProfileName uint32

const (
	BaselineServerBasicKMIPV1_2                       ProfileName = 0x00000001
	BaselineServerTLSV1_2KMIPV1_2                     ProfileName = 0x00000002
	BaselineClientBasicKMIPV1_2                       ProfileName = 0x00000003
	BaselineClientTLSV1_2KMIPV1_2                     ProfileName = 0x00000004
	CompleteServerBasicKMIPV1_2                       ProfileName = 0x00000005
	CompleteServerTLSV1_2KMIPV1_2                     ProfileName = 0x00000006
	TapeLibraryClientKMIPV1_0                         ProfileName = 0x00000007
	TapeLibraryClientKMIPV1_1                         ProfileName = 0x00000008
	TapeLibraryClientKMIPV1_2                         ProfileName = 0x00000009
	TapeLibraryServerKMIPV1_0                         ProfileName = 0x0000000A
	TapeLibraryServerKMIPV1_1                         ProfileName = 0x0000000B
	TapeLibraryServerKMIPV1_2                         ProfileName = 0x0000000C
	SymmetricKeyLifecycleClientKMIPV1_0               ProfileName = 0x0000000D
	SymmetricKeyLifecycleClientKMIPV1_1               ProfileName = 0x0000000E
	SymmetricKeyLifecycleClientKMIPV1_2               ProfileName = 0x0000000F
	SymmetricKeyLifecycleServerKMIPV1_0               ProfileName = 0x00000010
	SymmetricKeyLifecycleServerKMIPV1_1               ProfileName = 0x00000011
	SymmetricKeyLifecycleServerKMIPV1_2               ProfileName = 0x00000012
	AsymmetricKeyLifecycleClientKMIPV1_0              ProfileName = 0x00000013
	AsymmetricKeyLifecycleClientKMIPV1_1              ProfileName = 0x00000014
	AsymmetricKeyLifecycleClientKMIPV1_2              ProfileName = 0x00000015
	AsymmetricKeyLifecycleServerKMIPV1_0              ProfileName = 0x00000016
	AsymmetricKeyLifecycleServerKMIPV1_1              ProfileName = 0x00000017
	AsymmetricKeyLifecycleServerKMIPV1_2              ProfileName = 0x00000018
	BasicCryptographicClientKMIPV1_2                  ProfileName = 0x00000019
	BasicCryptographicServerKMIPV1_2                  ProfileName = 0x0000001A
	AdvancedCryptographicClientKMIPV1_2               ProfileName = 0x0000001B
	AdvancedCryptographicServerKMIPV1_2               ProfileName = 0x0000001C
	RNGCryptographicClientKMIPV1_2                    ProfileName = 0x0000001D
	RNGCryptographicServerKMIPV1_2                    ProfileName = 0x0000001E
	BasicSymmetricKeyFoundryClientKMIPV1_0            ProfileName = 0x0000001F
	IntermediateSymmetricKeyFoundryClientKMIPV1_0     ProfileName = 0x00000020
	AdvancedSymmetricKeyFoundryClientKMIPV1_0         ProfileName = 0x00000021
	BasicSymmetricKeyFoundryClientKMIPV1_1            ProfileName = 0x00000022
	IntermediateSymmetricKeyFoundryClientKMIPV1_1     ProfileName = 0x00000023
	AdvancedSymmetricKeyFoundryClientKMIPV1_1         ProfileName = 0x00000024
	BasicSymmetricKeyFoundryClientKMIPV1_2            ProfileName = 0x00000025
	IntermediateSymmetricKeyFoundryClientKMIPV1_2     ProfileName = 0x00000026
	AdvancedSymmetricKeyFoundryClientKMIPV1_2         ProfileName = 0x00000027
	SymmetricKeyFoundryServerKMIPV1_0                 ProfileName = 0x00000028
	SymmetricKeyFoundryServerKMIPV1_1                 ProfileName = 0x00000029
	SymmetricKeyFoundryServerKMIPV1_2                 ProfileName = 0x0000002A
	OpaqueManagedObjectStoreClientKMIPV1_0            ProfileName = 0x0000002B
	OpaqueManagedObjectStoreClientKMIPV1_1            ProfileName = 0x0000002C
	OpaqueManagedObjectStoreClientKMIPV1_2            ProfileName = 0x0000002D
	OpaqueManagedObjectStoreServerKMIPV1_0            ProfileName = 0x0000002E
	OpaqueManagedObjectStoreServerKMIPV1_1            ProfileName = 0x0000002F
	OpaqueManagedObjectStoreServerKMIPV1_2            ProfileName = 0x00000030
	SuiteBMinLOS_128ClientKMIPV1_0                    ProfileName = 0x00000031
	SuiteBMinLOS_128ClientKMIPV1_1                    ProfileName = 0x00000032
	SuiteBMinLOS_128ClientKMIPV1_2                    ProfileName = 0x00000033
	SuiteBMinLOS_128ServerKMIPV1_0                    ProfileName = 0x00000034
	SuiteBMinLOS_128ServerKMIPV1_1                    ProfileName = 0x00000035
	SuiteBMinLOS_128ServerKMIPV1_2                    ProfileName = 0x00000036
	SuiteBMinLOS_192ClientKMIPV1_0                    ProfileName = 0x00000037
	SuiteBMinLOS_192ClientKMIPV1_1                    ProfileName = 0x00000038
	SuiteBMinLOS_192ClientKMIPV1_2                    ProfileName = 0x00000039
	SuiteBMinLOS_192ServerKMIPV1_0                    ProfileName = 0x0000003A
	SuiteBMinLOS_192ServerKMIPV1_1                    ProfileName = 0x0000003B
	SuiteBMinLOS_192ServerKMIPV1_2                    ProfileName = 0x0000003C
	StorageArrayWithSelfEncryptingDriveClientKMIPV1_0 ProfileName = 0x0000003D
	StorageArrayWithSelfEncryptingDriveClientKMIPV1_1 ProfileName = 0x0000003E
	StorageArrayWithSelfEncryptingDriveClientKMIPV1_2 ProfileName = 0x0000003F
	StorageArrayWithSelfEncryptingDriveServerKMIPV1_0 ProfileName = 0x00000040
	StorageArrayWithSelfEncryptingDriveServerKMIPV1_1 ProfileName = 0x00000041
	StorageArrayWithSelfEncryptingDriveServerKMIPV1_2 ProfileName = 0x00000042
	HTTPSClientKMIPV1_0                               ProfileName = 0x00000043
	HTTPSClientKMIPV1_1                               ProfileName = 0x00000044
	HTTPSClientKMIPV1_2                               ProfileName = 0x00000045
	HTTPSServerKMIPV1_0                               ProfileName = 0x00000046
	HTTPSServerKMIPV1_1                               ProfileName = 0x00000047
	HTTPSServerKMIPV1_2                               ProfileName = 0x00000048
	JSONClientKMIPV1_0                                ProfileName = 0x00000049
	JSONClientKMIPV1_1                                ProfileName = 0x0000004A
	JSONClientKMIPV1_2                                ProfileName = 0x0000004B
	JSONServerKMIPV1_0                                ProfileName = 0x0000004C
	JSONServerKMIPV1_1                                ProfileName = 0x0000004D
	JSONServerKMIPV1_2                                ProfileName = 0x0000004E
	XMLClientKMIPV1_0                                 ProfileName = 0x0000004F
	XMLClientKMIPV1_1                                 ProfileName = 0x00000050
	XMLClientKMIPV1_2                                 ProfileName = 0x00000051
	XMLServerKMIPV1_0                                 ProfileName = 0x00000052
	XMLServerKMIPV1_1                                 ProfileName = 0x00000053
	XMLServerKMIPV1_2                                 ProfileName = 0x00000054
	BaselineServerBasicKMIPV1_3                       ProfileName = 0x00000055
	BaselineServerTLSV1_2KMIPV1_3                     ProfileName = 0x00000056
	BaselineClientBasicKMIPV1_3                       ProfileName = 0x00000057
	BaselineClientTLSV1_2KMIPV1_3                     ProfileName = 0x00000058
	CompleteServerBasicKMIPV1_3                       ProfileName = 0x00000059
	CompleteServerTLSV1_2KMIPV1_3                     ProfileName = 0x0000005A
	TapeLibraryClientKMIPV1_3                         ProfileName = 0x0000005B
	TapeLibraryServerKMIPV1_3                         ProfileName = 0x0000005C
	SymmetricKeyLifecycleClientKMIPV1_3               ProfileName = 0x0000005D
	SymmetricKeyLifecycleServerKMIPV1_3               ProfileName = 0x0000005E
	AsymmetricKeyLifecycleClientKMIPV1_3              ProfileName = 0x0000005F
	AsymmetricKeyLifecycleServerKMIPV1_3              ProfileName = 0x00000060
	BasicCryptographicClientKMIPV1_3                  ProfileName = 0x00000061
	BasicCryptographicServerKMIPV1_3                  ProfileName = 0x00000062
	AdvancedCryptographicClientKMIPV1_3               ProfileName = 0x00000063
	AdvancedCryptographicServerKMIPV1_3               ProfileName = 0x00000064
	RNGCryptographicClientKMIPV1_3                    ProfileName = 0x00000065
	RNGCryptographicServerKMIPV1_3                    ProfileName = 0x00000066
	BasicSymmetricKeyFoundryClientKMIPV1_3            ProfileName = 0x00000067
	IntermediateSymmetricKeyFoundryClientKMIPV1_3     ProfileName = 0x00000068
	AdvancedSymmetricKeyFoundryClientKMIPV1_3         ProfileName = 0x00000069
	SymmetricKeyFoundryServerKMIPV1_3                 ProfileName = 0x0000006A
	OpaqueManagedObjectStoreClientKMIPV1_3            ProfileName = 0x0000006B
	OpaqueManagedObjectStoreServerKMIPV1_3            ProfileName = 0x0000006C
	SuiteBMinLOS_128ClientKMIPV1_3                    ProfileName = 0x0000006D
	SuiteBMinLOS_128ServerKMIPV1_3                    ProfileName = 0x0000006E
	SuiteBMinLOS_192ClientKMIPV1_3                    ProfileName = 0x0000006F
	SuiteBMinLOS_192ServerKMIPV1_3                    ProfileName = 0x00000070
	StorageArrayWithSelfEncryptingDriveClientKMIPV1_3 ProfileName = 0x00000071
	StorageArrayWithSelfEncryptingDriveServerKMIPV1_3 ProfileName = 0x00000072
	HTTPSClientKMIPV1_3                               ProfileName = 0x00000073
	HTTPSServerKMIPV1_3                               ProfileName = 0x00000074
	JSONClientKMIPV1_3                                ProfileName = 0x00000075
	JSONServerKMIPV1_3                                ProfileName = 0x00000076
	XMLClientKMIPV1_3                                 ProfileName = 0x00000077
	XMLServerKMIPV1_3                                 ProfileName = 0x00000078

	// KMIP 1.4.
	BaselineServerBasicKMIPV1_4                       ProfileName = 0x00000079
	BaselineServerTLSV1_2KMIPV1_4                     ProfileName = 0x0000007A
	BaselineClientBasicKMIPV1_4                       ProfileName = 0x0000007B
	BaselineClientTLSV1_2KMIPV1_4                     ProfileName = 0x0000007C
	CompleteServerBasicKMIPV1_4                       ProfileName = 0x0000007D
	CompleteServerTLSV1_2KMIPV1_4                     ProfileName = 0x0000007E
	TapeLibraryClientKMIPV1_4                         ProfileName = 0x0000007F
	TapeLibraryServerKMIPV1_4                         ProfileName = 0x00000080
	SymmetricKeyLifecycleClientKMIPV1_4               ProfileName = 0x00000081
	SymmetricKeyLifecycleServerKMIPV1_4               ProfileName = 0x00000082
	AsymmetricKeyLifecycleClientKMIPV1_4              ProfileName = 0x00000083
	AsymmetricKeyLifecycleServerKMIPV1_4              ProfileName = 0x00000084
	BasicCryptographicClientKMIPV1_4                  ProfileName = 0x00000085
	BasicCryptographicServerKMIPV1_4                  ProfileName = 0x00000086
	AdvancedCryptographicClientKMIPV1_4               ProfileName = 0x00000087
	AdvancedCryptographicServerKMIPV1_4               ProfileName = 0x00000088
	RNGCryptographicClientKMIPV1_4                    ProfileName = 0x00000089
	RNGCryptographicServerKMIPV1_4                    ProfileName = 0x0000008A
	BasicSymmetricKeyFoundryClientKMIPV1_4            ProfileName = 0x0000008B
	IntermediateSymmetricKeyFoundryClientKMIPV1_4     ProfileName = 0x0000008C
	AdvancedSymmetricKeyFoundryClientKMIPV1_4         ProfileName = 0x0000008D
	SymmetricKeyFoundryServerKMIPV1_4                 ProfileName = 0x0000008E
	OpaqueManagedObjectStoreClientKMIPV1_4            ProfileName = 0x0000008F
	OpaqueManagedObjectStoreServerKMIPV1_4            ProfileName = 0x00000090
	SuiteBMinLOS_128ClientKMIPV1_4                    ProfileName = 0x00000091
	SuiteBMinLOS_128ServerKMIPV1_4                    ProfileName = 0x00000092
	SuiteBMinLOS_192ClientKMIPV1_4                    ProfileName = 0x00000093
	SuiteBMinLOS_192ServerKMIPV1_4                    ProfileName = 0x00000094
	StorageArrayWithSelfEncryptingDriveClientKMIPV1_4 ProfileName = 0x00000095
	StorageArrayWithSelfEncryptingDriveServerKMIPV1_4 ProfileName = 0x00000096
	HTTPSClientKMIPV1_4                               ProfileName = 0x00000097
	HTTPSServerKMIPV1_4                               ProfileName = 0x00000098
	JSONClientKMIPV1_4                                ProfileName = 0x00000099
	JSONServerKMIPV1_4                                ProfileName = 0x0000009A
	XMLClientKMIPV1_4                                 ProfileName = 0x0000009B
	XMLServerKMIPV1_4                                 ProfileName = 0x0000009C
)

type ValidationAuthorityType uint32

const (
	ValidationAuthorityTypeUnspecified    ValidationAuthorityType = 0x00000001
	ValidationAuthorityTypeNISTCMVP       ValidationAuthorityType = 0x00000002
	ValidationAuthorityTypeCommonCriteria ValidationAuthorityType = 0x00000003
)

type ValidationType uint32

const (
	ValidationTypeUnspecified ValidationType = 0x00000001
	ValidationTypeHardware    ValidationType = 0x00000002
	ValidationTypeSoftware    ValidationType = 0x00000003
	ValidationTypeFirmware    ValidationType = 0x00000004
	ValidationTypeHybrid      ValidationType = 0x00000005
)

type UnwrapMode uint32

const (
	UnwrapModeUnspecified  UnwrapMode = 0x00000001
	UnwrapModeProcessed    UnwrapMode = 0x00000002
	UnwrapModeNotProcessed UnwrapMode = 0x00000003
)

type DestroyAction uint32

const (
	DestroyActionUnspecified         DestroyAction = 0x00000001
	DestroyActionKeyMaterialDeleted  DestroyAction = 0x00000002
	DestroyActionKeyMaterialShredded DestroyAction = 0x00000003
	DestroyActionMetaDataDeleted     DestroyAction = 0x00000004
	DestroyActionMetaDataShredded    DestroyAction = 0x00000005
	DestroyActionDeleted             DestroyAction = 0x00000006
	DestroyActionShredded            DestroyAction = 0x00000007
)

type ShreddingAlgorithm uint32

const (
	ShreddingAlgorithmUnspecified   ShreddingAlgorithm = 0x00000001
	ShreddingAlgorithmCryptographic ShreddingAlgorithm = 0x00000002
	ShreddingAlgorithmUnsupported   ShreddingAlgorithm = 0x00000003
)

type RNGMode uint32

const (
	RNGModeUnspecified            RNGMode = 0x00000001
	RNGModeSharedInstantiation    RNGMode = 0x00000002
	RNGModeNonSharedInstantiation RNGMode = 0x00000003
)

type ClientRegistrationMethod uint32

const (
	ClientRegistrationMethodUnspecified        ClientRegistrationMethod = 0x00000001
	ClientRegistrationMethodServerPreGenerated ClientRegistrationMethod = 0x00000002
	ClientRegistrationMethodServerOnDemand     ClientRegistrationMethod = 0x00000003
	ClientRegistrationMethodClientGenerated    ClientRegistrationMethod = 0x00000004
	ClientRegistrationMethodClientRegistered   ClientRegistrationMethod = 0x00000005
)

// KMIP 1.4.

type MaskGenerator uint32

const (
	MGF1 MaskGenerator = 0x00000001
)

// Text Marshaling for better display in json outputs.

func (enum ResultStatus) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum ResultReason) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum CredentialType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum RevocationReasonCode) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum BatchErrorContinuationOption) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum NameType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum ObjectType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum OpaqueDataType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum State) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum CryptographicAlgorithm) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum BlockCipherMode) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum PaddingMethod) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum HashingAlgorithm) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum KeyRoleType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum RecommendedCurve) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum SecretDataType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum KeyFormatType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum KeyCompressionType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum WrappingMethod) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum CertificateType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum LinkType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum QueryFunction) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum UsageLimitsUnit) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum CancellationResult) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum PutFunction) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum CertificateRequestType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum SplitKeyMethod) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum ObjectGroupMember) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum EncodingOption) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum DigitalSignatureAlgorithm) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum AttestationType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum AlternativeNameType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum KeyValueLocationType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum ValidityIndicator) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum RNGAlgorithm) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum DRBGAlgorithm) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum FIPS186Variation) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum ProfileName) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum ValidationAuthorityType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum ValidationType) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum UnwrapMode) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum DestroyAction) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum ShreddingAlgorithm) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum RNGMode) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum ClientRegistrationMethod) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
func (enum MaskGenerator) MarshalText() ([]byte, error) {
	return []byte(ttlv.EnumStr(enum)), nil
}
