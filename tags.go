package kmip

import (
	"github.com/ovh/kmip-go/ttlv"
)

const (
	// KMIP 1.0.
	TagActivationDate                 = 0x420001
	TagApplicationData                = 0x420002
	TagApplicationNamespace           = 0x420003
	TagApplicationSpecificInformation = 0x420004
	TagArchiveDate                    = 0x420005
	TagAsynchronousCorrelationValue   = 0x420006
	TagAsynchronousIndicator          = 0x420007
	TagAttribute                      = 0x420008
	TagAttributeIndex                 = 0x420009
	TagAttributeName                  = 0x42000A
	TagAttributeValue                 = 0x42000B
	TagAuthentication                 = 0x42000C
	TagBatchCount                     = 0x42000D
	TagBatchErrorContinuationOption   = 0x42000E
	TagBatchItem                      = 0x42000F
	TagBatchOrderOption               = 0x420010
	TagBlockCipherMode                = 0x420011
	TagCancellationResult             = 0x420012
	TagCertificate                    = 0x420013
	// Deprecated: deprecated as of kmip 1.1.
	TagCertificateIdentifier = 0x420014
	// Deprecated: deprecated as of kmip 1.1.
	TagCertificateIssuer = 0x420015
	// Deprecated: deprecated as of kmip 1.1.
	TagCertificateIssuerAlternativeName = 0x420016
	// Deprecated: deprecated as of kmip 1.1.
	TagCertificateIssuerDistinguishedName = 0x420017
	TagCertificateRequest                 = 0x420018
	TagCertificateRequestType             = 0x420019
	// Deprecated: deprecated as of kmip 1.1.
	TagCertificateSubject = 0x42001A
	// Deprecated: deprecated as of kmip 1.1.
	TagCertificateSubjectAlternativeName = 0x42001B
	// Deprecated: deprecated as of kmip 1.1.
	TagCertificateSubjectDistinguishedName = 0x42001C
	TagCertificateType                     = 0x42001D
	TagCertificateValue                    = 0x42001E
	TagCommonTemplateAttribute             = 0x42001F
	TagCompromiseDate                      = 0x420020
	TagCompromiseOccurrenceDate            = 0x420021
	TagContactInformation                  = 0x420022
	TagCredential                          = 0x420023
	TagCredentialType                      = 0x420024
	TagCredentialValue                     = 0x420025
	TagCriticalityIndicator                = 0x420026
	TagCRTCoefficient                      = 0x420027
	TagCryptographicAlgorithm              = 0x420028
	TagCryptographicDomainParameters       = 0x420029
	TagCryptographicLength                 = 0x42002A
	TagCryptographicParameters             = 0x42002B
	TagCryptographicUsageMask              = 0x42002C
	TagCustomAttribute                     = 0x42002D
	TagD                                   = 0x42002E
	TagDeactivationDate                    = 0x42002F
	TagDerivationData                      = 0x420030
	TagDerivationMethod                    = 0x420031
	TagDerivationParameters                = 0x420032
	TagDestroyDate                         = 0x420033
	TagDigest                              = 0x420034
	TagDigestValue                         = 0x420035
	TagEncryptionKeyInformation            = 0x420036
	TagG                                   = 0x420037
	TagHashingAlgorithm                    = 0x420038
	TagInitialDate                         = 0x420039
	TagInitializationVector                = 0x42003A
	// Deprecated: deprecated as of kmip 1.1.
	TagIssuer                     = 0x42003B
	TagIterationCount             = 0x42003C
	TagIVCounterNonce             = 0x42003D
	TagJ                          = 0x42003E
	TagKey                        = 0x42003F
	TagKeyBlock                   = 0x420040
	TagKeyCompressionType         = 0x420041
	TagKeyFormatType              = 0x420042
	TagKeyMaterial                = 0x420043
	TagKeyPartIdentifier          = 0x420044
	TagKeyValue                   = 0x420045
	TagKeyWrappingData            = 0x420046
	TagKeyWrappingSpecification   = 0x420047
	TagLastChangeDate             = 0x420048
	TagLeaseTime                  = 0x420049
	TagLink                       = 0x42004A
	TagLinkType                   = 0x42004B
	TagLinkedObjectIdentifier     = 0x42004C
	TagMACSignature               = 0x42004D
	TagMACSignatureKeyInformation = 0x42004E
	TagMaximumItems               = 0x42004F
	TagMaximumResponseSize        = 0x420050
	TagMessageExtension           = 0x420051
	TagModulus                    = 0x420052
	TagName                       = 0x420053
	TagNameType                   = 0x420054
	TagNameValue                  = 0x420055
	TagObjectGroup                = 0x420056
	TagObjectType                 = 0x420057
	TagOffset                     = 0x420058
	TagOpaqueDataType             = 0x420059
	TagOpaqueDataValue            = 0x42005A
	TagOpaqueObject               = 0x42005B
	TagOperation                  = 0x42005C
	// Deprecated: deprecated as of kmip 1.3.
	TagOperationPolicyName         = 0x42005D
	TagP                           = 0x42005E
	TagPaddingMethod               = 0x42005F
	TagPrimeExponentP              = 0x420060
	TagPrimeExponentQ              = 0x420061
	TagPrimeFieldSize              = 0x420062
	TagPrivateExponent             = 0x420063
	TagPrivateKey                  = 0x420064
	TagPrivateKeyTemplateAttribute = 0x420065
	TagPrivateKeyUniqueIdentifier  = 0x420066
	TagProcessStartDate            = 0x420067
	TagProtectStopDate             = 0x420068
	TagProtocolVersion             = 0x420069
	TagProtocolVersionMajor        = 0x42006A
	TagProtocolVersionMinor        = 0x42006B
	TagPublicExponent              = 0x42006C
	TagPublicKey                   = 0x42006D
	TagPublicKeyTemplateAttribute  = 0x42006E
	TagPublicKeyUniqueIdentifier   = 0x42006F
	TagPutFunction                 = 0x420070
	TagQ                           = 0x420071
	TagQString                     = 0x420072
	TagQlength                     = 0x420073
	TagQueryFunction               = 0x420074
	TagRecommendedCurve            = 0x420075
	TagReplacedUniqueIdentifier    = 0x420076
	TagRequestHeader               = 0x420077
	TagRequestMessage              = 0x420078
	TagRequestPayload              = 0x420079
	TagResponseHeader              = 0x42007A
	TagResponseMessage             = 0x42007B
	TagResponsePayload             = 0x42007C
	TagResultMessage               = 0x42007D
	TagResultReason                = 0x42007E
	TagResultStatus                = 0x42007F
	TagRevocationMessage           = 0x420080
	TagRevocationReason            = 0x420081
	TagRevocationReasonCode        = 0x420082
	TagKeyRoleType                 = 0x420083
	TagSalt                        = 0x420084
	TagSecretData                  = 0x420085
	TagSecretDataType              = 0x420086
	// Deprecated: deprecated as of kmip 1.1.
	TagSerialNumber         = 0x420087
	TagServerInformation    = 0x420088
	TagSplitKey             = 0x420089
	TagSplitKeyMethod       = 0x42008A
	TagSplitKeyParts        = 0x42008B
	TagSplitKeyThreshold    = 0x42008C
	TagState                = 0x42008D
	TagStorageStatusMask    = 0x42008E
	TagSymmetricKey         = 0x42008F
	TagTemplate             = 0x420090
	TagTemplateAttribute    = 0x420091
	TagTimeStamp            = 0x420092
	TagUniqueBatchItemID    = 0x420093
	TagUniqueIdentifier     = 0x420094
	TagUsageLimits          = 0x420095
	TagUsageLimitsCount     = 0x420096
	TagUsageLimitsTotal     = 0x420097
	TagUsageLimitsUnit      = 0x420098
	TagUsername             = 0x420099
	TagValidityDate         = 0x42009A
	TagValidityIndicator    = 0x42009B
	TagVendorExtension      = 0x42009C
	TagVendorIdentification = 0x42009D
	TagWrappingMethod       = 0x42009E
	TagX                    = 0x42009F
	TagY                    = 0x4200A0
	TagPassword             = 0x4200A1

	// KMIP 1.1.
	TagDeviceIdentifier           = 0x4200A2
	TagEncodingOption             = 0x4200A3
	TagExtensionInformation       = 0x4200A4
	TagExtensionName              = 0x4200A5
	TagExtensionTag               = 0x4200A6
	TagExtensionType              = 0x4200A7
	TagFresh                      = 0x4200A8
	TagMachineIdentifier          = 0x4200A9
	TagMediaIdentifier            = 0x4200AA
	TagNetworkIdentifier          = 0x4200AB
	TagObjectGroupMember          = 0x4200AC
	TagCertificateLength          = 0x4200AD
	TagDigitalSignatureAlgorithm  = 0x4200AE
	TagCertificateSerialNumber    = 0x4200AF
	TagDeviceSerialNumber         = 0x4200B0
	TagIssuerAlternativeName      = 0x4200B1
	TagIssuerDistinguishedName    = 0x4200B2
	TagSubjectAlternativeName     = 0x4200B3
	TagSubjectDistinguishedName   = 0x4200B4
	TagX_509CertificateIdentifier = 0x4200B5
	TagX_509CertificateIssuer     = 0x4200B6
	TagX_509CertificateSubject    = 0x4200B7

	// KMIP 1.2.
	TagKeyValueLocationValue       = 0x4200B9
	TagKeyValueLocationType        = 0x4200BA
	TagKeyValuePresent             = 0x4200BB
	TagOriginalCreationDate        = 0x4200BC
	TagPGPKey                      = 0x4200BD
	TagPGPKeyVersion               = 0x4200BE
	TagAlternativeName             = 0x4200BF
	TagAlternativeNameValue        = 0x4200C0
	TagAlternativeNameType         = 0x4200C1
	TagData                        = 0x4200C2
	TagSignatureData               = 0x4200C3
	TagDataLength                  = 0x4200C4
	TagRandomIV                    = 0x4200C5
	TagMACData                     = 0x4200C6
	TagAttestationType             = 0x4200C7
	TagNonce                       = 0x4200C8
	TagNonceID                     = 0x4200C9
	TagNonceValue                  = 0x4200CA
	TagAttestationMeasurement      = 0x4200CB
	TagAttestationAssertion        = 0x4200CC
	TagIVLength                    = 0x4200CD
	TagTagLength                   = 0x4200CE
	TagFixedFieldLength            = 0x4200CF
	TagCounterLength               = 0x4200D0
	TagInitialCounterValue         = 0x4200D1
	TagInvocationFieldLength       = 0x4200D2
	TagAttestationCapableIndicator = 0x4200D3
	TagKeyValueLocation            = 0x4200B8

	// KMIP 1.3.
	TagOffsetItems                     = 0x4200D4
	TagLocatedItems                    = 0x4200D5
	TagCorrelationValue                = 0x4200D6
	TagInitIndicator                   = 0x4200D7
	TagFinalIndicator                  = 0x4200D8
	TagRNGParameters                   = 0x4200D9
	TagRNGAlgorithm                    = 0x4200DA
	TagDRBGAlgorithm                   = 0x4200DB
	TagFIPS186Variation                = 0x4200DC
	TagPredictionResistance            = 0x4200DD
	TagRandomNumberGenerator           = 0x4200DE
	TagValidationInformation           = 0x4200DF
	TagValidationAuthorityType         = 0x4200E0
	TagValidationAuthorityCountry      = 0x4200E1
	TagValidationAuthorityURI          = 0x4200E2
	TagValidationVersionMajor          = 0x4200E3
	TagValidationVersionMinor          = 0x4200E4
	TagValidationType                  = 0x4200E5
	TagValidationLevel                 = 0x4200E6
	TagValidationCertificateIdentifier = 0x4200E7
	TagValidationCertificateURI        = 0x4200E8
	TagValidationVendorURI             = 0x4200E9
	TagValidationProfile               = 0x4200EA
	TagProfileInformation              = 0x4200EB
	TagProfileName                     = 0x4200EC
	TagServerURI                       = 0x4200ED
	TagServerPort                      = 0x4200EE
	TagStreamingCapability             = 0x4200EF
	TagAsynchronousCapability          = 0x4200F0
	TagAttestationCapability           = 0x4200F1
	TagUnwrapMode                      = 0x4200F2
	TagDestroyAction                   = 0x4200F3
	TagShreddingAlgorithm              = 0x4200F4
	TagRNGMode                         = 0x4200F5
	TagClientRegistrationMethod        = 0x4200F6
	TagCapabilityInformation           = 0x4200F7

	// KMIP 1.4.
	TagKeyWrapType                           = 0x4200F8
	TagBatchUndoCapability                   = 0x4200F9
	TagBatchContinueCapability               = 0x4200FA
	TagPKCS_12FriendlyName                   = 0x4200FB
	TagDescription                           = 0x4200FC
	TagComment                               = 0x4200FD
	TagAuthenticatedEncryptionAdditionalData = 0x4200FE
	TagAuthenticatedEncryptionTag            = 0x4200FF
	TagSaltLength                            = 0x420100
	TagMaskGenerator                         = 0x420101
	TagMaskGeneratorHashingAlgorithm         = 0x420102
	TagPSource                               = 0x420103
	TagTrailerField                          = 0x420104
	TagClientCorrelationValue                = 0x420105
	TagServerCorrelationValue                = 0x420106
	TagDigestedData                          = 0x420107
	TagCertificateSubjectCN                  = 0x420108
	TagCertificateSubjectO                   = 0x420109
	TagCertificateSubjectOU                  = 0x42010A
	TagCertificateSubjectEmail               = 0x42010B
	TagCertificateSubjectC                   = 0x42010C
	TagCertificateSubjectST                  = 0x42010D
	TagCertificateSubjectL                   = 0x42010E
	TagCertificateSubjectUID                 = 0x42010F
	TagCertificateSubjectSerialNumber        = 0x420110
	TagCertificateSubjectTitle               = 0x420111
	TagCertificateSubjectDC                  = 0x420112
	TagCertificateSubjectDNQualifier         = 0x420113
	TagCertificateIssuerCN                   = 0x420114
	TagCertificateIssuerO                    = 0x420115
	TagCertificateIssuerOU                   = 0x420116
	TagCertificateIssuerEmail                = 0x420117
	TagCertificateIssuerC                    = 0x420118
	TagCertificateIssuerST                   = 0x420119
	TagCertificateIssuerL                    = 0x42011A
	TagCertificateIssuerUID                  = 0x42011B
	TagCertificateIssuerSerialNumber         = 0x42011C
	TagCertificateIssuerTitle                = 0x42011D
	TagCertificateIssuerDC                   = 0x42011E
	TagCertificateIssuerDNQualifier          = 0x42011F
	TagSensitive                             = 0x420120
	TagAlwaysSensitive                       = 0x420121
	TagExtractable                           = 0x420122
	TagNeverExtractable                      = 0x420123
	TagReplaceExisting                       = 0x420124

	// KMIP 2.0.
	TagAttributes                         = 0x420125
	TagCommonAttributes                   = 0x420126
	TagPrivateKeyAttributes               = 0x420127
	TagPublicKeyAttributes                = 0x420128
	TagExtensionEnumeration               = 0x420129
	TagExtensionAttribute                 = 0x42012A
	TagExtensionParentStructureTag        = 0x42012B
	TagExtensionDescription               = 0x42012C
	TagServerName                         = 0x42012D
	TagServerSerialNumber                 = 0x42012E
	TagServerVersion                      = 0x42012F
	TagServerLoad                         = 0x420130
	TagProductName                        = 0x420131
	TagBuildLevel                         = 0x420132
	TagBuildDate                          = 0x420133
	TagClusterInfo                        = 0x420134
	TagAlternateFailoverEndpoints         = 0x420135
	TagShortUniqueIdentifier              = 0x420136
	TagTag                                = 0x420138
	TagCertificateRequestUniqueIdentifier = 0x420139
	TagNISTKeyType                        = 0x42013A
	TagAttributeReference                 = 0x42013B
	TagCurrentAttribute                   = 0x42013C
	TagNewAttribute                       = 0x42013D
	TagCertificateRequestValue            = 0x420140
	TagLogMessage                         = 0x420141
	TagProfileVersion                     = 0x420142
	TagProfileVersionMajor                = 0x420143
	TagProfileVersionMinor                = 0x420144
	TagProtectionLevel                    = 0x420145
	TagProtectionPeriod                   = 0x420146
	TagQuantumSafe                        = 0x420147
	TagQuantumSafeCapability              = 0x420148
	TagTicket                             = 0x420149
	TagTicketType                         = 0x42014A
	TagTicketValue                        = 0x42014B
	TagRequestCount                       = 0x42014C
	TagRights                             = 0x42014D
	TagObjects                            = 0x42014E
	TagOperations                         = 0x42014F
	TagRight                              = 0x420150
	TagEndpointRole                       = 0x420151
	TagDefaultsInformation                = 0x420152
	TagObjectDefaults                     = 0x420153
	TagEphemeral                          = 0x420154
	TagServerHashedPassword               = 0x420155
	TagOneTimePassword                    = 0x420156
	TagHashedPassword                     = 0x420157
	TagAdjustmentType                     = 0x420158
	TagPKCS_11Interface                   = 0x420159
	TagPKCS_11Function                    = 0x42015A
	TagPKCS_11InputParameters             = 0x42015B
	TagPKCS_11OutputParameters            = 0x42015C
	TagPKCS_11ReturnCode                  = 0x42015D
	TagProtectionStorageMask              = 0x42015E
	TagProtectionStorageMasks             = 0x42015F
	TagInteropFunction                    = 0x420160
	TagInteropIdentifier                  = 0x420161
	TagAdjustmentValue                    = 0x420162
	TagCommonProtectionStorageMasks       = 0x420163
	TagPrivateProtectionStorageMasks      = 0x420164
	TagPublicProtectionStorageMasks       = 0x420165
)

//nolint:gosec // No hardcoded credential here, just a tag name.
var tagNames = map[int]string{
	// KMIP 1.0
	TagActivationDate:                      "ActivationDate",
	TagApplicationData:                     "ApplicationData",
	TagApplicationNamespace:                "ApplicationNamespace",
	TagApplicationSpecificInformation:      "ApplicationSpecificInformation",
	TagArchiveDate:                         "ArchiveDate",
	TagAsynchronousCorrelationValue:        "AsynchronousCorrelationValue",
	TagAsynchronousIndicator:               "AsynchronousIndicator",
	TagAttribute:                           "Attribute",
	TagAttributeIndex:                      "AttributeIndex",
	TagAttributeName:                       "AttributeName",
	TagAttributeValue:                      "AttributeValue",
	TagAuthentication:                      "Authentication",
	TagBatchCount:                          "BatchCount",
	TagBatchErrorContinuationOption:        "BatchErrorContinuationOption",
	TagBatchItem:                           "BatchItem",
	TagBatchOrderOption:                    "BatchOrderOption",
	TagBlockCipherMode:                     "BlockCipherMode",
	TagCancellationResult:                  "CancellationResult",
	TagCertificate:                         "Certificate",
	TagCertificateIdentifier:               "CertificateIdentifier",
	TagCertificateIssuer:                   "CertificateIssuer",
	TagCertificateIssuerAlternativeName:    "CertificateIssuerAlternativeName",
	TagCertificateIssuerDistinguishedName:  "CertificateIssuerDistinguishedName",
	TagCertificateRequest:                  "CertificateRequest",
	TagCertificateRequestType:              "CertificateRequestType",
	TagCertificateSubject:                  "CertificateSubject",
	TagCertificateSubjectAlternativeName:   "CertificateSubjectAlternativeName",
	TagCertificateSubjectDistinguishedName: "CertificateSubjectDistinguishedName",
	TagCertificateType:                     "CertificateType",
	TagCertificateValue:                    "CertificateValue",
	TagCommonTemplateAttribute:             "CommonTemplateAttribute",
	TagCompromiseDate:                      "CompromiseDate",
	TagCompromiseOccurrenceDate:            "CompromiseOccurrenceDate",
	TagContactInformation:                  "ContactInformation",
	TagCredential:                          "Credential",
	TagCredentialType:                      "CredentialType",
	TagCredentialValue:                     "CredentialValue",
	TagCriticalityIndicator:                "CriticalityIndicator",
	TagCRTCoefficient:                      "CRTCoefficient",
	TagCryptographicAlgorithm:              "CryptographicAlgorithm",
	TagCryptographicDomainParameters:       "CryptographicDomainParameters",
	TagCryptographicLength:                 "CryptographicLength",
	TagCryptographicParameters:             "CryptographicParameters",
	TagCryptographicUsageMask:              "CryptographicUsageMask",
	TagCustomAttribute:                     "CustomAttribute",
	TagD:                                   "D",
	TagDeactivationDate:                    "DeactivationDate",
	TagDerivationData:                      "DerivationData",
	TagDerivationMethod:                    "DerivationMethod",
	TagDerivationParameters:                "DerivationParameters",
	TagDestroyDate:                         "DestroyDate",
	TagDigest:                              "Digest",
	TagDigestValue:                         "DigestValue",
	TagEncryptionKeyInformation:            "EncryptionKeyInformation",
	TagG:                                   "G",
	TagHashingAlgorithm:                    "HashingAlgorithm",
	TagInitialDate:                         "InitialDate",
	TagInitializationVector:                "InitializationVector",
	TagIssuer:                              "Issuer",
	TagIterationCount:                      "IterationCount",
	TagIVCounterNonce:                      "IVCounterNonce",
	TagJ:                                   "J",
	TagKey:                                 "Key",
	TagKeyBlock:                            "KeyBlock",
	TagKeyCompressionType:                  "KeyCompressionType",
	TagKeyFormatType:                       "KeyFormatType",
	TagKeyMaterial:                         "KeyMaterial",
	TagKeyPartIdentifier:                   "KeyPartIdentifier",
	TagKeyValue:                            "KeyValue",
	TagKeyWrappingData:                     "KeyWrappingData",
	TagKeyWrappingSpecification:            "KeyWrappingSpecification",
	TagLastChangeDate:                      "LastChangeDate",
	TagLeaseTime:                           "LeaseTime",
	TagLink:                                "Link",
	TagLinkType:                            "LinkType",
	TagLinkedObjectIdentifier:              "LinkedObjectIdentifier",
	TagMACSignature:                        "MACSignature",
	TagMACSignatureKeyInformation:          "MACSignatureKeyInformation",
	TagMaximumItems:                        "MaximumItems",
	TagMaximumResponseSize:                 "MaximumResponseSize",
	TagMessageExtension:                    "MessageExtension",
	TagModulus:                             "Modulus",
	TagName:                                "Name",
	TagNameType:                            "NameType",
	TagNameValue:                           "NameValue",
	TagObjectGroup:                         "ObjectGroup",
	TagObjectType:                          "ObjectType",
	TagOffset:                              "Offset",
	TagOpaqueDataType:                      "OpaqueDataType",
	TagOpaqueDataValue:                     "OpaqueDataValue",
	TagOpaqueObject:                        "OpaqueObject",
	TagOperation:                           "Operation",
	TagOperationPolicyName:                 "OperationPolicyName",
	TagP:                                   "P",
	TagPaddingMethod:                       "PaddingMethod",
	TagPrimeExponentP:                      "PrimeExponentP",
	TagPrimeExponentQ:                      "PrimeExponentQ",
	TagPrimeFieldSize:                      "PrimeFieldSize",
	TagPrivateExponent:                     "PrivateExponent",
	TagPrivateKey:                          "PrivateKey",
	TagPrivateKeyTemplateAttribute:         "PrivateKeyTemplateAttribute",
	TagPrivateKeyUniqueIdentifier:          "PrivateKeyUniqueIdentifier",
	TagProcessStartDate:                    "ProcessStartDate",
	TagProtectStopDate:                     "ProtectStopDate",
	TagProtocolVersion:                     "ProtocolVersion",
	TagProtocolVersionMajor:                "ProtocolVersionMajor",
	TagProtocolVersionMinor:                "ProtocolVersionMinor",
	TagPublicExponent:                      "PublicExponent",
	TagPublicKey:                           "PublicKey",
	TagPublicKeyTemplateAttribute:          "PublicKeyTemplateAttribute",
	TagPublicKeyUniqueIdentifier:           "PublicKeyUniqueIdentifier",
	TagPutFunction:                         "PutFunction",
	TagQ:                                   "Q",
	TagQString:                             "QString",
	TagQlength:                             "Qlength",
	TagQueryFunction:                       "QueryFunction",
	TagRecommendedCurve:                    "RecommendedCurve",
	TagReplacedUniqueIdentifier:            "ReplacedUniqueIdentifier",
	TagRequestHeader:                       "RequestHeader",
	TagRequestMessage:                      "RequestMessage",
	TagRequestPayload:                      "RequestPayload",
	TagResponseHeader:                      "ResponseHeader",
	TagResponseMessage:                     "ResponseMessage",
	TagResponsePayload:                     "ResponsePayload",
	TagResultMessage:                       "ResultMessage",
	TagResultReason:                        "ResultReason",
	TagResultStatus:                        "ResultStatus",
	TagRevocationMessage:                   "RevocationMessage",
	TagRevocationReason:                    "RevocationReason",
	TagRevocationReasonCode:                "RevocationReasonCode",
	TagKeyRoleType:                         "KeyRoleType",
	TagSalt:                                "Salt",
	TagSecretData:                          "SecretData",
	TagSecretDataType:                      "SecretDataType",
	TagSerialNumber:                        "SerialNumber",
	TagServerInformation:                   "ServerInformation",
	TagSplitKey:                            "SplitKey",
	TagSplitKeyMethod:                      "SplitKeyMethod",
	TagSplitKeyParts:                       "SplitKeyParts",
	TagSplitKeyThreshold:                   "SplitKeyThreshold",
	TagState:                               "State",
	TagStorageStatusMask:                   "StorageStatusMask",
	TagSymmetricKey:                        "SymmetricKey",
	TagTemplate:                            "Template",
	TagTemplateAttribute:                   "TemplateAttribute",
	TagTimeStamp:                           "TimeStamp",
	TagUniqueBatchItemID:                   "UniqueBatchItemID",
	TagUniqueIdentifier:                    "UniqueIdentifier",
	TagUsageLimits:                         "UsageLimits",
	TagUsageLimitsCount:                    "UsageLimitsCount",
	TagUsageLimitsTotal:                    "UsageLimitsTotal",
	TagUsageLimitsUnit:                     "UsageLimitsUnit",
	TagUsername:                            "Username",
	TagValidityDate:                        "ValidityDate",
	TagValidityIndicator:                   "ValidityIndicator",
	TagVendorExtension:                     "VendorExtension",
	TagVendorIdentification:                "VendorIdentification",
	TagWrappingMethod:                      "WrappingMethod",
	TagX:                                   "X",
	TagY:                                   "Y",
	TagPassword:                            "Password",

	// KMIP 1.1
	TagDeviceIdentifier:           "DeviceIdentifier",
	TagEncodingOption:             "EncodingOption",
	TagExtensionInformation:       "ExtensionInformation",
	TagExtensionName:              "ExtensionName",
	TagExtensionTag:               "ExtensionTag",
	TagExtensionType:              "ExtensionType",
	TagFresh:                      "Fresh",
	TagMachineIdentifier:          "MachineIdentifier",
	TagMediaIdentifier:            "MediaIdentifier",
	TagNetworkIdentifier:          "NetworkIdentifier",
	TagObjectGroupMember:          "ObjectGroupMember",
	TagCertificateLength:          "CertificateLength",
	TagDigitalSignatureAlgorithm:  "DigitalSignatureAlgorithm",
	TagCertificateSerialNumber:    "CertificateSerialNumber",
	TagDeviceSerialNumber:         "DeviceSerialNumber",
	TagIssuerAlternativeName:      "IssuerAlternativeName",
	TagIssuerDistinguishedName:    "IssuerDistinguishedName",
	TagSubjectAlternativeName:     "SubjectAlternativeName",
	TagSubjectDistinguishedName:   "SubjectDistinguishedName",
	TagX_509CertificateIdentifier: "X_509CertificateIdentifier",
	TagX_509CertificateIssuer:     "X_509CertificateIssuer",
	TagX_509CertificateSubject:    "X_509CertificateSubject",

	// KMIP 1.2
	TagKeyValueLocationValue:       "KeyValueLocationValue",
	TagKeyValueLocationType:        "KeyValueLocationType",
	TagKeyValuePresent:             "KeyValuePresent",
	TagOriginalCreationDate:        "OriginalCreationDate",
	TagPGPKey:                      "PGPKey",
	TagPGPKeyVersion:               "PGPKeyVersion",
	TagAlternativeName:             "AlternativeName",
	TagAlternativeNameValue:        "AlternativeNameValue",
	TagAlternativeNameType:         "AlternativeNameType",
	TagData:                        "Data",
	TagSignatureData:               "SignatureData",
	TagDataLength:                  "DataLength",
	TagRandomIV:                    "RandomIV",
	TagMACData:                     "MACData",
	TagAttestationType:             "AttestationType",
	TagNonce:                       "Nonce",
	TagNonceID:                     "NonceID",
	TagNonceValue:                  "NonceValue",
	TagAttestationMeasurement:      "AttestationMeasurement",
	TagAttestationAssertion:        "AttestationAssertion",
	TagIVLength:                    "IVLength",
	TagTagLength:                   "TagLength",
	TagFixedFieldLength:            "FixedFieldLength",
	TagCounterLength:               "CounterLength",
	TagInitialCounterValue:         "InitialCounterValue",
	TagInvocationFieldLength:       "InvocationFieldLength",
	TagAttestationCapableIndicator: "AttestationCapableIndicator",
	TagKeyValueLocation:            "KeyValueLocation",

	// KMIP 1.3
	TagOffsetItems:                     "OffsetItems",
	TagLocatedItems:                    "LocatedItems",
	TagCorrelationValue:                "CorrelationValue",
	TagInitIndicator:                   "InitIndicator",
	TagFinalIndicator:                  "FinalIndicator",
	TagRNGParameters:                   "RNGParameters",
	TagRNGAlgorithm:                    "RNGAlgorithm",
	TagDRBGAlgorithm:                   "DRBGAlgorithm",
	TagFIPS186Variation:                "FIPS186Variation",
	TagPredictionResistance:            "PredictionResistance",
	TagRandomNumberGenerator:           "RandomNumberGenerator",
	TagValidationInformation:           "ValidationInformation",
	TagValidationAuthorityType:         "ValidationAuthorityType",
	TagValidationAuthorityCountry:      "ValidationAuthorityCountry",
	TagValidationAuthorityURI:          "ValidationAuthorityURI",
	TagValidationVersionMajor:          "ValidationVersionMajor",
	TagValidationVersionMinor:          "ValidationVersionMinor",
	TagValidationType:                  "ValidationType",
	TagValidationLevel:                 "ValidationLevel",
	TagValidationCertificateIdentifier: "ValidationCertificateIdentifier",
	TagValidationCertificateURI:        "ValidationCertificateURI",
	TagValidationVendorURI:             "ValidationVendorURI",
	TagValidationProfile:               "ValidationProfile",
	TagProfileInformation:              "ProfileInformation",
	TagProfileName:                     "ProfileName",
	TagServerURI:                       "ServerURI",
	TagServerPort:                      "ServerPort",
	TagStreamingCapability:             "StreamingCapability",
	TagAsynchronousCapability:          "AsynchronousCapability",
	TagAttestationCapability:           "AttestationCapability",
	TagUnwrapMode:                      "UnwrapMode",
	TagDestroyAction:                   "DestroyAction",
	TagShreddingAlgorithm:              "ShreddingAlgorithm",
	TagRNGMode:                         "RNGMode",
	TagClientRegistrationMethod:        "ClientRegistrationMethod",
	TagCapabilityInformation:           "CapabilityInformation",

	// KMIP 1.4
	TagKeyWrapType:                           "KeyWrapType",
	TagBatchUndoCapability:                   "BatchUndoCapability",
	TagBatchContinueCapability:               "BatchContinueCapability",
	TagPKCS_12FriendlyName:                   "PKCS_12FriendlyName",
	TagDescription:                           "Description",
	TagComment:                               "Comment",
	TagAuthenticatedEncryptionAdditionalData: "AuthenticatedEncryptionAdditionalData",
	TagAuthenticatedEncryptionTag:            "AuthenticatedEncryptionTag",
	TagSaltLength:                            "SaltLength",
	TagMaskGenerator:                         "MaskGenerator",
	TagMaskGeneratorHashingAlgorithm:         "MaskGeneratorHashingAlgorithm",
	TagPSource:                               "PSource",
	TagTrailerField:                          "TrailerField",
	TagClientCorrelationValue:                "ClientCorrelationValue",
	TagServerCorrelationValue:                "ServerCorrelationValue",
	TagDigestedData:                          "DigestedData",
	TagCertificateSubjectCN:                  "CertificateSubjectCN",
	TagCertificateSubjectO:                   "CertificateSubjectO",
	TagCertificateSubjectOU:                  "CertificateSubjectOU",
	TagCertificateSubjectEmail:               "CertificateSubjectEmail",
	TagCertificateSubjectC:                   "CertificateSubjectC",
	TagCertificateSubjectST:                  "CertificateSubjectST",
	TagCertificateSubjectL:                   "CertificateSubjectL",
	TagCertificateSubjectUID:                 "CertificateSubjectUID",
	TagCertificateSubjectSerialNumber:        "CertificateSubjectSerialNumber",
	TagCertificateSubjectTitle:               "CertificateSubjectTitle",
	TagCertificateSubjectDC:                  "CertificateSubjectDC",
	TagCertificateSubjectDNQualifier:         "CertificateSubjectDNQualifier",
	TagCertificateIssuerCN:                   "CertificateIssuerCN",
	TagCertificateIssuerO:                    "CertificateIssuerO",
	TagCertificateIssuerOU:                   "CertificateIssuerOU",
	TagCertificateIssuerEmail:                "CertificateIssuerEmail",
	TagCertificateIssuerC:                    "CertificateIssuerC",
	TagCertificateIssuerST:                   "CertificateIssuerST",
	TagCertificateIssuerL:                    "CertificateIssuerL",
	TagCertificateIssuerUID:                  "CertificateIssuerUID",
	TagCertificateIssuerSerialNumber:         "CertificateIssuerSerialNumber",
	TagCertificateIssuerTitle:                "CertificateIssuerTitle",
	TagCertificateIssuerDC:                   "CertificateIssuerDC",
	TagCertificateIssuerDNQualifier:          "CertificateIssuerDNQualifier",
	TagSensitive:                             "Sensitive",
	TagAlwaysSensitive:                       "AlwaysSensitive",
	TagExtractable:                           "Extractable",
	TagNeverExtractable:                      "NeverExtractable",
	TagReplaceExisting:                       "ReplaceExisting",

	// KMIP 2.0
	TagAttributes:                         "Attributes",
	TagCommonAttributes:                   "CommonAttributes",
	TagPrivateKeyAttributes:               "PrivateKeyAttributes",
	TagPublicKeyAttributes:                "PublicKeyAttributes",
	TagExtensionEnumeration:               "ExtensionEnumeration",
	TagExtensionAttribute:                 "ExtensionAttribute",
	TagExtensionParentStructureTag:        "ExtensionParentStructureTag",
	TagExtensionDescription:               "ExtensionDescription",
	TagServerName:                         "ServerName",
	TagServerSerialNumber:                 "ServerSerialNumber",
	TagServerVersion:                      "ServerVersion",
	TagServerLoad:                         "ServerLoad",
	TagProductName:                        "ProductName",
	TagBuildLevel:                         "BuildLevel",
	TagBuildDate:                          "BuildDate",
	TagClusterInfo:                        "ClusterInfo",
	TagAlternateFailoverEndpoints:         "AlternateFailoverEndpoints",
	TagShortUniqueIdentifier:              "ShortUniqueIdentifier",
	TagTag:                                "Tag",
	TagCertificateRequestUniqueIdentifier: "CertificateRequestUniqueIdentifier",
	TagNISTKeyType:                        "NISTKeyType",
	TagAttributeReference:                 "AttributeReference",
	TagCurrentAttribute:                   "CurrentAttribute",
	TagNewAttribute:                       "NewAttribute",
	TagCertificateRequestValue:            "CertificateRequestValue",
	TagLogMessage:                         "LogMessage",
	TagProfileVersion:                     "ProfileVersion",
	TagProfileVersionMajor:                "ProfileVersionMajor",
	TagProfileVersionMinor:                "ProfileVersionMinor",
	TagProtectionLevel:                    "ProtectionLevel",
	TagProtectionPeriod:                   "ProtectionPeriod",
	TagQuantumSafe:                        "QuantumSafe",
	TagQuantumSafeCapability:              "QuantumSafeCapability",
	TagTicket:                             "Ticket",
	TagTicketType:                         "TicketType",
	TagTicketValue:                        "TicketValue",
	TagRequestCount:                       "RequestCount",
	TagRights:                             "Rights",
	TagObjects:                            "Objects",
	TagOperations:                         "Operations",
	TagRight:                              "Right",
	TagEndpointRole:                       "EndpointRole",
	TagDefaultsInformation:                "DefaultsInformation",
	TagObjectDefaults:                     "ObjectDefaults",
	TagEphemeral:                          "Ephemeral",
	TagServerHashedPassword:               "ServerHashedPassword",
	TagOneTimePassword:                    "OneTimePassword",
	TagHashedPassword:                     "HashedPassword",
	TagAdjustmentType:                     "AdjustmentType",
	TagPKCS_11Interface:                   "PKCS_11Interface",
	TagPKCS_11Function:                    "PKCS_11Function",
	TagPKCS_11InputParameters:             "PKCS_11InputParameters",
	TagPKCS_11OutputParameters:            "PKCS_11OutputParameters",
	TagPKCS_11ReturnCode:                  "PKCS_11ReturnCode",
	TagProtectionStorageMask:              "ProtectionStorageMask",
	TagProtectionStorageMasks:             "ProtectionStorageMasks",
	TagInteropFunction:                    "InteropFunction",
	TagInteropIdentifier:                  "InteropIdentifier",
	TagAdjustmentValue:                    "AdjustmentValue",
	TagCommonProtectionStorageMasks:       "CommonProtectionStorageMasks",
	TagPrivateProtectionStorageMasks:      "PrivateProtectionStorageMasks",
	TagPublicProtectionStorageMasks:       "PublicProtectionStorageMasks",
}

func init() {
	for tag, name := range tagNames {
		ttlv.RegisterTag(name, tag)
	}
}
