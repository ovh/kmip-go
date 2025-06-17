package kmip

var (
	V1_0 = ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 0}
	V1_1 = ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 1}
	V1_2 = ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 2}
	V1_3 = ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 3}
	V1_4 = ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 4}
	V2_0 = ProtocolVersion{ProtocolVersionMajor: 2, ProtocolVersionMinor: 0}
	V2_1 = ProtocolVersion{ProtocolVersionMajor: 2, ProtocolVersionMinor: 1}
	V2_2 = ProtocolVersion{ProtocolVersionMajor: 2, ProtocolVersionMinor: 2}
)

var (
	// AES_CBC_PKCS5 defines cryptographic parameters for AES encryption using CBC mode with PKCS5 padding.
	// It specifies the AES algorithm, CBC block cipher mode, PKCS5 padding method, and an IV length of 16 bytes.
	AES_CBC_PKCS5 = CryptographicParameters{
		CryptographicAlgorithm: CryptographicAlgorithmAES,
		BlockCipherMode:        BlockCipherModeCBC,
		PaddingMethod:          PaddingMethodPKCS5,
		IVLength:               16,
	}

	// AES_GCM defines the cryptographic parameters for AES encryption using Galois/Counter Mode (GCM).
	// It specifies the use of the AES algorithm with GCM block cipher mode, an IV (Initialization Vector) length of 12 bytes,
	// and an authentication tag length of 16 bytes, which are standard values for AES-GCM operations.
	AES_GCM = CryptographicParameters{
		CryptographicAlgorithm: CryptographicAlgorithmAES,
		BlockCipherMode:        BlockCipherModeGCM,
		IVLength:               12,
		TagLength:              16,
	}

	// RSA_OAEP_SHA256 defines cryptographic parameters for RSA encryption using OAEP padding with SHA-256 as the hashing algorithm.
	// It specifies the use of the RSA cryptographic algorithm, SHA-256 for both the primary and mask generator hashing algorithms,
	// and MGF1 as the mask generation function. This configuration is commonly used for secure RSA OAEP encryption with SHA-256.
	RSA_OAEP_SHA256 = CryptographicParameters{
		CryptographicAlgorithm:        CryptographicAlgorithmRSA,
		HashingAlgorithm:              HashingAlgorithmSHA_256,
		MaskGenerator:                 MaskGeneratorMGF1,
		MaskGeneratorHashingAlgorithm: HashingAlgorithmSHA_256,
	}

	// RSA_OAEP_SHA384 defines cryptographic parameters for RSA encryption using OAEP padding with SHA-384 as the hashing algorithm.
	// It specifies the use of the RSA cryptographic algorithm, SHA-384 for both the primary and mask generator hashing algorithms,
	// and MGF1 as the mask generation function. This configuration is commonly used for secure RSA OAEP encryption with SHA-384.
	RSA_OAEP_SHA384 = CryptographicParameters{
		CryptographicAlgorithm:        CryptographicAlgorithmRSA,
		HashingAlgorithm:              HashingAlgorithmSHA_384,
		MaskGenerator:                 MaskGeneratorMGF1,
		MaskGeneratorHashingAlgorithm: HashingAlgorithmSHA_384,
	}

	// RSA_OAEP_SHA512 defines cryptographic parameters for RSA encryption using OAEP padding with SHA-512 as the hashing algorithm.
	// It specifies the use of the RSA cryptographic algorithm, SHA-512 for both the primary and mask generator hashing algorithms,
	// and MGF1 as the mask generation function. This configuration is commonly used for secure RSA OAEP encryption with SHA-512.
	RSA_OAEP_SHA512 = CryptographicParameters{
		CryptographicAlgorithm:        CryptographicAlgorithmRSA,
		HashingAlgorithm:              HashingAlgorithmSHA_512,
		MaskGenerator:                 MaskGeneratorMGF1,
		MaskGeneratorHashingAlgorithm: HashingAlgorithmSHA_512,
	}
)
