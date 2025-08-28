package kmip

import (
	"bytes"
	"testing"
)

// Test MarshalText and UnmarshalText for ResultStatus
func TestResultStatus_MarshalText(t *testing.T) {
	tests := []struct {
		enum      ResultStatus
		want      []byte
		wantError bool
	}{
		{ResultStatusSuccess, []byte("Success"), false},
		{ResultStatusOperationFailed, []byte("OperationFailed"), false},
		{ResultStatusOperationPending, []byte("OperationPending"), false},
		{ResultStatusOperationUndone, []byte("OperationUndone"), false},
		{ResultStatus(100), []byte("0x00000064"), false},        // Abnormal enum value
		{ResultStatus(0xFFFFFFFF), []byte("0xFFFFFFFF"), false}, // Abnormal enum value
	}

	for _, tt := range tests {
		got, err := tt.enum.MarshalText()
		if tt.wantError {
			if err == nil {
				t.Errorf("MarshalText(%v) expected error, got nil", tt.enum)
			}
		} else {
			if err != nil {
				t.Fatalf("MarshalText error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MarshalText(%v) got %s, want %s", tt.enum, got, tt.want)
			}
		}
	}
}

func TestResultStatus_UnmarshalText(t *testing.T) {
	tests := []struct {
		input     []byte
		want      ResultStatus
		wantError bool
	}{
		{[]byte("Success"), ResultStatusSuccess, false},
		{[]byte(" Success "), ResultStatusSuccess, false},
		{[]byte("OperationFailed"), ResultStatusOperationFailed, false},
		{[]byte("Operation Failed"), ResultStatusOperationFailed, false},
		{[]byte("OperationPending"), ResultStatusOperationPending, false},
		{[]byte("Operation Pending"), ResultStatusOperationPending, false},
		{[]byte("OperationUndone"), ResultStatusOperationUndone, false},
		{[]byte("Operation Undone"), ResultStatusOperationUndone, false},
		{[]byte("0x00000064"), ResultStatus(100), false},        // Abnormal enum value
		{[]byte("0xFFFFFFFF"), ResultStatus(0xFFFFFFFF), false}, // Abnormal enum value
		{[]byte("UnknownStatus"), 0, true},                      // Non-existent enum text
	}

	for _, tt := range tests {
		var enum ResultStatus
		err := enum.UnmarshalText(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("UnmarshalText(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Fatalf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if enum != tt.want {
				t.Errorf("UnmarshalText(%q) got %d, want %d", tt.input, enum, tt.want)
			}
		}
	}
}

func TestResultReason_MarshalText(t *testing.T) {
	tests := []struct {
		enum      ResultReason
		want      []byte
		wantError bool
	}{
		{ResultReasonItemNotFound, []byte("ItemNotFound"), false},
		{ResultReasonResponseTooLarge, []byte("ResponseTooLarge"), false},
		{ResultReasonAuthenticationNotSuccessful, []byte("AuthenticationNotSuccessful"), false},
		{ResultReasonInvalidMessage, []byte("InvalidMessage"), false},
		{ResultReasonOperationNotSupported, []byte("OperationNotSupported"), false},
		{ResultReasonMissingData, []byte("MissingData"), false},
		{ResultReasonInvalidField, []byte("InvalidField"), false},
		{ResultReasonFeatureNotSupported, []byte("FeatureNotSupported"), false},
		{ResultReasonOperationCanceledByRequester, []byte("OperationCanceledByRequester"), false},
		{ResultReasonCryptographicFailure, []byte("CryptographicFailure"), false},
		{ResultReasonIllegalOperation, []byte("IllegalOperation"), false},
		{ResultReasonPermissionDenied, []byte("PermissionDenied"), false},
		{ResultReasonObjectarchived, []byte("Objectarchived"), false},
		{ResultReasonIndexOutofBounds, []byte("IndexOutofBounds"), false},
		{ResultReasonApplicationNamespaceNotSupported, []byte("ApplicationNamespaceNotSupported"), false},
		{ResultReasonKeyFormatTypeNotSupported, []byte("KeyFormatTypeNotSupported"), false},
		{ResultReasonKeyCompressionTypeNotSupported, []byte("KeyCompressionTypeNotSupported"), false},
		{ResultReasonEncodingOptionError, []byte("EncodingOptionError"), false},
		{ResultReasonKeyValueNotPresent, []byte("KeyValueNotPresent"), false},
		{ResultReasonAttestationRequired, []byte("AttestationRequired"), false},
		{ResultReasonAttestationFailed, []byte("AttestationFailed"), false},
		{ResultReasonSensitive, []byte("Sensitive"), false},
		{ResultReasonNotExtractable, []byte("NotExtractable"), false},
		{ResultReasonObjectAlreadyExists, []byte("ObjectAlreadyExists"), false},
		{ResultReasonGeneralFailure, []byte("GeneralFailure"), false},
		{ResultReason(100), []byte("0x00000064"), false},        // Abnormal enum value
		{ResultReason(0xFFFFFFFF), []byte("0xFFFFFFFF"), false}, // Abnormal enum value
	}

	for _, tt := range tests {
		got, err := tt.enum.MarshalText()
		if tt.wantError {
			if err == nil {
				t.Errorf("MarshalText(%v) expected error, got nil", tt.enum)
			}
		} else {
			if err != nil {
				t.Fatalf("MarshalText error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MarshalText(%v) got %s, want %s", tt.enum, got, tt.want)
			}
		}
	}
}

func TestResultReason_UnmarshalText(t *testing.T) {
	tests := []struct {
		input     []byte
		want      ResultReason
		wantError bool
	}{
		{[]byte("ItemNotFound"), ResultReasonItemNotFound, false},
		{[]byte(" ItemNotFound "), ResultReasonItemNotFound, false},
		{[]byte("ResponseTooLarge"), ResultReasonResponseTooLarge, false},
		{[]byte("AuthenticationNotSuccessful"), ResultReasonAuthenticationNotSuccessful, false},
		{[]byte("InvalidMessage"), ResultReasonInvalidMessage, false},
		{[]byte("OperationNotSupported"), ResultReasonOperationNotSupported, false},
		{[]byte("MissingData"), ResultReasonMissingData, false},
		{[]byte("InvalidField"), ResultReasonInvalidField, false},
		{[]byte("FeatureNotSupported"), ResultReasonFeatureNotSupported, false},
		{[]byte("OperationCanceledByRequester"), ResultReasonOperationCanceledByRequester, false},
		{[]byte("CryptographicFailure"), ResultReasonCryptographicFailure, false},
		{[]byte("IllegalOperation"), ResultReasonIllegalOperation, false},
		{[]byte("PermissionDenied"), ResultReasonPermissionDenied, false},
		{[]byte("Objectarchived"), ResultReasonObjectarchived, false},
		{[]byte("IndexOutofBounds"), ResultReasonIndexOutofBounds, false},
		{[]byte("ApplicationNamespaceNotSupported"), ResultReasonApplicationNamespaceNotSupported, false},
		{[]byte("KeyFormatTypeNotSupported"), ResultReasonKeyFormatTypeNotSupported, false},
		{[]byte("KeyCompressionTypeNotSupported"), ResultReasonKeyCompressionTypeNotSupported, false},
		{[]byte("EncodingOptionError"), ResultReasonEncodingOptionError, false},
		{[]byte("KeyValueNotPresent"), ResultReasonKeyValueNotPresent, false},
		{[]byte("AttestationRequired"), ResultReasonAttestationRequired, false},
		{[]byte("AttestationFailed"), ResultReasonAttestationFailed, false},
		{[]byte("Sensitive"), ResultReasonSensitive, false},
		{[]byte("NotExtractable"), ResultReasonNotExtractable, false},
		{[]byte("ObjectAlreadyExists"), ResultReasonObjectAlreadyExists, false},
		{[]byte("GeneralFailure"), ResultReasonGeneralFailure, false},
		{[]byte("0x00000064"), ResultReason(100), false},        // Abnormal enum value
		{[]byte("0xFFFFFFFF"), ResultReason(0xFFFFFFFF), false}, // Abnormal enum value
		{[]byte("UnknownReason"), 0, true},                      // Non-existent enum text
	}

	for _, tt := range tests {
		var enum ResultReason
		err := enum.UnmarshalText(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("UnmarshalText(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Fatalf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if enum != tt.want {
				t.Errorf("UnmarshalText(%q) got %d, want %d", tt.input, enum, tt.want)
			}
		}
	}
}

func TestCredentialType_MarshalText(t *testing.T) {
	tests := []struct {
		enum      CredentialType
		want      []byte
		wantError bool
	}{
		{CredentialTypeUsernameAndPassword, []byte("UsernameAndPassword"), false},
		{CredentialTypeDevice, []byte("Device"), false},
		{CredentialTypeAttestation, []byte("Attestation"), false},
		{CredentialType(100), []byte("0x00000064"), false},        // Abnormal enum value
		{CredentialType(0xFFFFFFFF), []byte("0xFFFFFFFF"), false}, // Abnormal enum value
	}

	for _, tt := range tests {
		got, err := tt.enum.MarshalText()
		if tt.wantError {
			if err == nil {
				t.Errorf("MarshalText(%v) expected error, got nil", tt.enum)
			}
		} else {
			if err != nil {
				t.Fatalf("MarshalText error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MarshalText(%v) got %s, want %s", tt.enum, got, tt.want)
			}
		}
	}
}

func TestCredentialType_UnmarshalText(t *testing.T) {
	tests := []struct {
		input     []byte
		want      CredentialType
		wantError bool
	}{
		{[]byte("UsernameAndPassword"), CredentialTypeUsernameAndPassword, false},
		{[]byte(" UsernameAndPassword "), CredentialTypeUsernameAndPassword, false},
		{[]byte("Device"), CredentialTypeDevice, false},
		{[]byte("Attestation"), CredentialTypeAttestation, false},
		{[]byte("0x00000064"), CredentialType(100), false},        // Abnormal enum value
		{[]byte("0xFFFFFFFF"), CredentialType(0xFFFFFFFF), false}, // Abnormal enum value
		{[]byte("UnknownCredential"), 0, true},                    // Non-existent enum text
	}

	for _, tt := range tests {
		var enum CredentialType
		err := enum.UnmarshalText(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("UnmarshalText(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Fatalf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if enum != tt.want {
				t.Errorf("UnmarshalText(%q) got %d, want %d", tt.input, enum, tt.want)
			}
		}
	}
}
func TestRevocationReasonCode_MarshalText(t *testing.T) {
	tests := []struct {
		enum      RevocationReasonCode
		want      []byte
		wantError bool
	}{
		{RevocationReasonCodeUnspecified, []byte("Unspecified"), false},
		{RevocationReasonCodeKeyCompromise, []byte("KeyCompromise"), false},
		{RevocationReasonCodeCACompromise, []byte("CACompromise"), false},
		{RevocationReasonCodeAffiliationChanged, []byte("AffiliationChanged"), false},
		{RevocationReasonCodeSuperseded, []byte("Superseded"), false},
		{RevocationReasonCodeCessationOfOperation, []byte("CessationOfOperation"), false},
		{RevocationReasonCodePrivilegeWithdrawn, []byte("PrivilegeWithdrawn"), false},
		{RevocationReasonCode(100), []byte("0x00000064"), false},        // Abnormal enum value
		{RevocationReasonCode(0xFFFFFFFF), []byte("0xFFFFFFFF"), false}, // Abnormal enum value
	}

	for _, tt := range tests {
		got, err := tt.enum.MarshalText()
		if tt.wantError {
			if err == nil {
				t.Errorf("MarshalText(%v) expected error, got nil", tt.enum)
			}
		} else {
			if err != nil {
				t.Fatalf("MarshalText error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MarshalText(%v) got %s, want %s", tt.enum, got, tt.want)
			}
		}
	}
}

func TestRevocationReasonCode_UnmarshalText(t *testing.T) {
	tests := []struct {
		input     []byte
		want      RevocationReasonCode
		wantError bool
	}{
		{[]byte("Unspecified"), RevocationReasonCodeUnspecified, false},
		{[]byte(" Unspecified "), RevocationReasonCodeUnspecified, false},
		{[]byte("KeyCompromise"), RevocationReasonCodeKeyCompromise, false},
		{[]byte("Key Compromise"), RevocationReasonCodeKeyCompromise, false},
		{[]byte("CACompromise"), RevocationReasonCodeCACompromise, false},
		{[]byte("CA Compromise"), RevocationReasonCodeCACompromise, false},
		{[]byte("AffiliationChanged"), RevocationReasonCodeAffiliationChanged, false},
		{[]byte("Affiliation Changed"), RevocationReasonCodeAffiliationChanged, false},
		{[]byte("Superseded"), RevocationReasonCodeSuperseded, false},
		{[]byte("CessationOfOperation"), RevocationReasonCodeCessationOfOperation, false},
		{[]byte("Cessation Of Operation"), RevocationReasonCodeCessationOfOperation, false},
		{[]byte("PrivilegeWithdrawn"), RevocationReasonCodePrivilegeWithdrawn, false},
		{[]byte("Privilege Withdrawn"), RevocationReasonCodePrivilegeWithdrawn, false},
		{[]byte("0x00000064"), RevocationReasonCode(100), false},        // Abnormal enum value
		{[]byte("0xFFFFFFFF"), RevocationReasonCode(0xFFFFFFFF), false}, // Abnormal enum value
		{[]byte("UnknownReason"), 0, true},                              // Non-existent enum text
	}

	for _, tt := range tests {
		var enum RevocationReasonCode
		err := enum.UnmarshalText(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("UnmarshalText(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Fatalf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if enum != tt.want {
				t.Errorf("UnmarshalText(%q) got %d, want %d", tt.input, enum, tt.want)
			}
		}
	}
}
func TestBatchErrorContinuationOption_MarshalText(t *testing.T) {
	tests := []struct {
		enum      BatchErrorContinuationOption
		want      []byte
		wantError bool
	}{
		{BatchErrorContinuationOptionContinue, []byte("Continue"), false},
		{BatchErrorContinuationOptionStop, []byte("Stop"), false},
		{BatchErrorContinuationOptionUndo, []byte("Undo"), false},
		{BatchErrorContinuationOption(100), []byte("0x00000064"), false},        // Abnormal enum value
		{BatchErrorContinuationOption(0xFFFFFFFF), []byte("0xFFFFFFFF"), false}, // Abnormal enum value
	}

	for _, tt := range tests {
		got, err := tt.enum.MarshalText()
		if tt.wantError {
			if err == nil {
				t.Errorf("MarshalText(%v) expected error, got nil", tt.enum)
			}
		} else {
			if err != nil {
				t.Fatalf("MarshalText error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MarshalText(%v) got %s, want %s", tt.enum, got, tt.want)
			}
		}
	}
}

func TestBatchErrorContinuationOption_UnmarshalText(t *testing.T) {
	tests := []struct {
		input     []byte
		want      BatchErrorContinuationOption
		wantError bool
	}{
		{[]byte("Continue"), BatchErrorContinuationOptionContinue, false},
		{[]byte(" Continue "), BatchErrorContinuationOptionContinue, false},
		{[]byte("Stop"), BatchErrorContinuationOptionStop, false},
		{[]byte("Undo"), BatchErrorContinuationOptionUndo, false},
		{[]byte("0x00000064"), BatchErrorContinuationOption(100), false},        // Abnormal enum value
		{[]byte("0xFFFFFFFF"), BatchErrorContinuationOption(0xFFFFFFFF), false}, // Abnormal enum value
		{[]byte("UnknownOption"), 0, true},                                      // Non-existent enum text
	}

	for _, tt := range tests {
		var enum BatchErrorContinuationOption
		err := enum.UnmarshalText(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("UnmarshalText(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Fatalf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if enum != tt.want {
				t.Errorf("UnmarshalText(%q) got %d, want %d", tt.input, enum, tt.want)
			}
		}
	}
}

func TestNameType_MarshalText(t *testing.T) {
	tests := []struct {
		enum      NameType
		want      []byte
		wantError bool
	}{
		{NameTypeUninterpretedTextString, []byte("UninterpretedTextString"), false},
		{NameTypeUri, []byte("Uri"), false},
		{NameType(100), []byte("0x00000064"), false},        // Abnormal enum value
		{NameType(0xFFFFFFFF), []byte("0xFFFFFFFF"), false}, // Abnormal enum value
	}

	for _, tt := range tests {
		got, err := tt.enum.MarshalText()
		if tt.wantError {
			if err == nil {
				t.Errorf("MarshalText(%v) expected error, got nil", tt.enum)
			}
		} else {
			if err != nil {
				t.Fatalf("MarshalText error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MarshalText(%v) got %s, want %s", tt.enum, got, tt.want)
			}
		}
	}
}

func TestNameType_UnmarshalText(t *testing.T) {
	tests := []struct {
		input     []byte
		want      NameType
		wantError bool
	}{
		{[]byte("UninterpretedTextString"), NameTypeUninterpretedTextString, false},
		{[]byte(" UninterpretedTextString "), NameTypeUninterpretedTextString, false},
		{[]byte("Uri"), NameTypeUri, false},
		{[]byte("0x00000064"), NameType(100), false},        // Abnormal enum value
		{[]byte("0xFFFFFFFF"), NameType(0xFFFFFFFF), false}, // Abnormal enum value
		{[]byte("UnknownNameType"), 0, true},                // Non-existent enum text
	}

	for _, tt := range tests {
		var enum NameType
		err := enum.UnmarshalText(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("UnmarshalText(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Fatalf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if enum != tt.want {
				t.Errorf("UnmarshalText(%q) got %d, want %d", tt.input, enum, tt.want)
			}
		}
	}
}
func TestObjectType_MarshalText(t *testing.T) {
	tests := []struct {
		enum      ObjectType
		want      []byte
		wantError bool
	}{
		{ObjectTypeCertificate, []byte("Certificate"), false},
		{ObjectTypeSymmetricKey, []byte("SymmetricKey"), false},
		{ObjectTypePublicKey, []byte("PublicKey"), false},
		{ObjectTypePrivateKey, []byte("PrivateKey"), false},
		{ObjectTypeSplitKey, []byte("SplitKey"), false},
		{ObjectTypeTemplate, []byte("Template"), false},
		{ObjectTypeSecretData, []byte("SecretData"), false},
		{ObjectTypeOpaqueObject, []byte("OpaqueObject"), false},
		{ObjectType(100), []byte("0x00000064"), false},        // Abnormal enum value
		{ObjectType(0xFFFFFFFF), []byte("0xFFFFFFFF"), false}, // Abnormal enum value
	}

	for _, tt := range tests {
		got, err := tt.enum.MarshalText()
		if tt.wantError {
			if err == nil {
				t.Errorf("MarshalText(%v) expected error, got nil", tt.enum)
			}
		} else {
			if err != nil {
				t.Fatalf("MarshalText error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MarshalText(%v) got %s, want %s", tt.enum, got, tt.want)
			}
		}
	}
}

func TestObjectType_UnmarshalText(t *testing.T) {
	tests := []struct {
		input     []byte
		want      ObjectType
		wantError bool
	}{
		{[]byte("Certificate"), ObjectTypeCertificate, false},
		{[]byte(" Certificate "), ObjectTypeCertificate, false},
		{[]byte("SymmetricKey"), ObjectTypeSymmetricKey, false},
		{[]byte("Symmetric Key"), ObjectTypeSymmetricKey, false},
		{[]byte("PublicKey"), ObjectTypePublicKey, false},
		{[]byte("Public Key"), ObjectTypePublicKey, false},
		{[]byte("PrivateKey"), ObjectTypePrivateKey, false},
		{[]byte("Private Key"), ObjectTypePrivateKey, false},
		{[]byte("SplitKey"), ObjectTypeSplitKey, false},
		{[]byte("Split Key"), ObjectTypeSplitKey, false},
		{[]byte("Template"), ObjectTypeTemplate, false},
		{[]byte("SecretData"), ObjectTypeSecretData, false},
		{[]byte("Secret Data"), ObjectTypeSecretData, false},
		{[]byte("OpaqueObject"), ObjectTypeOpaqueObject, false},
		{[]byte("Opaque Object"), ObjectTypeOpaqueObject, false},
		{[]byte("0x00000064"), ObjectType(100), false},        // Abnormal enum value
		{[]byte("0xFFFFFFFF"), ObjectType(0xFFFFFFFF), false}, // Abnormal enum value
		{[]byte("UnknownObjectType"), 0, true},                // Non-existent enum text
	}

	for _, tt := range tests {
		var enum ObjectType
		err := enum.UnmarshalText(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("UnmarshalText(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Fatalf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if enum != tt.want {
				t.Errorf("UnmarshalText(%q) got %d, want %d", tt.input, enum, tt.want)
			}
		}
	}
}
func TestOpaqueDataType_MarshalText(t *testing.T) {
	tests := []struct {
		enum      OpaqueDataType
		want      []byte
		wantError bool
	}{
		{OpaqueDataType(100), []byte("0x00000064"), false},        // Abnormal enum value
		{OpaqueDataType(0xFFFFFFFF), []byte("0xFFFFFFFF"), false}, // Abnormal enum value
	}

	for _, tt := range tests {
		got, err := tt.enum.MarshalText()
		if tt.wantError {
			if err == nil {
				t.Errorf("MarshalText(%v) expected error, got nil", tt.enum)
			}
		} else {
			if err != nil {
				t.Fatalf("MarshalText error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MarshalText(%v) got %s, want %s", tt.enum, got, tt.want)
			}
		}
	}
}

func TestOpaqueDataType_UnmarshalText(t *testing.T) {
	tests := []struct {
		input     []byte
		want      OpaqueDataType
		wantError bool
	}{
		{[]byte("0x00000064"), OpaqueDataType(100), false},        // Abnormal enum value
		{[]byte("0xFFFFFFFF"), OpaqueDataType(0xFFFFFFFF), false}, // Abnormal enum value
		{[]byte("UnknownOpaqueType"), 0, true},                    // Non-existent enum text
	}

	for _, tt := range tests {
		var enum OpaqueDataType
		err := enum.UnmarshalText(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("UnmarshalText(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Fatalf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if enum != tt.want {
				t.Errorf("UnmarshalText(%q) got %d, want %d", tt.input, enum, tt.want)
			}
		}
	}
}

func TestState_MarshalText(t *testing.T) {
	tests := []struct {
		enum      State
		want      []byte
		wantError bool
	}{
		{StatePreActive, []byte("PreActive"), false},
		{StateActive, []byte("Active"), false},
		{StateDeactivated, []byte("Deactivated"), false},
		{StateCompromised, []byte("Compromised"), false},
		{StateDestroyed, []byte("Destroyed"), false},
		{State(100), []byte("0x00000064"), false},        // Abnormal enum value
		{State(0xFFFFFFFF), []byte("0xFFFFFFFF"), false}, // Abnormal enum value
	}

	for _, tt := range tests {
		got, err := tt.enum.MarshalText()
		if tt.wantError {
			if err == nil {
				t.Errorf("MarshalText(%v) expected error, got nil", tt.enum)
			}
		} else {
			if err != nil {
				t.Fatalf("MarshalText error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MarshalText(%v) got %s, want %s", tt.enum, got, tt.want)
			}
		}
	}
}

func TestState_UnmarshalText(t *testing.T) {
	tests := []struct {
		input     []byte
		want      State
		wantError bool
	}{
		{[]byte("PreActive"), StatePreActive, false},
		{[]byte(" PreActive "), StatePreActive, false},
		{[]byte("Active"), StateActive, false},
		{[]byte("Deactivated"), StateDeactivated, false},
		{[]byte("Compromised"), StateCompromised, false},
		{[]byte("Destroyed"), StateDestroyed, false},
		{[]byte("0x00000064"), State(100), false},        // Abnormal enum value
		{[]byte("0xFFFFFFFF"), State(0xFFFFFFFF), false}, // Abnormal enum value
		{[]byte("UnknownState"), 0, true},                // Non-existent enum text
	}

	for _, tt := range tests {
		var enum State
		err := enum.UnmarshalText(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("UnmarshalText(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Fatalf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if enum != tt.want {
				t.Errorf("UnmarshalText(%q) got %d, want %d", tt.input, enum, tt.want)
			}
		}
	}
}
func TestCryptographicAlgorithm_MarshalText_AllCases(t *testing.T) {
	cases := []struct {
		enum CryptographicAlgorithm
		want []byte
	}{
		{CryptographicAlgorithmDES, []byte("DES")},
		{CryptographicAlgorithm3DES, []byte("DES3")},
		{CryptographicAlgorithmAES, []byte("AES")},
		{CryptographicAlgorithmRSA, []byte("RSA")},
		{CryptographicAlgorithmDSA, []byte("DSA")},
		{CryptographicAlgorithmECDSA, []byte("ECDSA")},
		{CryptographicAlgorithmHMACSHA1, []byte("HMAC_SHA1")},
		{CryptographicAlgorithmHMACSHA224, []byte("HMAC_SHA224")},
		{CryptographicAlgorithmHMACSHA256, []byte("HMAC_SHA256")},
		{CryptographicAlgorithmHMACSHA384, []byte("HMAC_SHA384")},
		{CryptographicAlgorithmHMACSHA512, []byte("HMAC_SHA512")},
		{CryptographicAlgorithmHMACMD5, []byte("HMAC_MD5")},
		{CryptographicAlgorithmDH, []byte("DH")},
		{CryptographicAlgorithmECDH, []byte("ECDH")},
		{CryptographicAlgorithmECMQV, []byte("ECMQV")},
		{CryptographicAlgorithmBlowfish, []byte("Blowfish")},
		{CryptographicAlgorithmCamellia, []byte("Camellia")},
		{CryptographicAlgorithmCAST5, []byte("CAST5")},
		{CryptographicAlgorithmIDEA, []byte("IDEA")},
		{CryptographicAlgorithmMARS, []byte("MARS")},
		{CryptographicAlgorithmRC2, []byte("RC2")},
		{CryptographicAlgorithmRC4, []byte("RC4")},
		{CryptographicAlgorithmRC5, []byte("RC5")},
		{CryptographicAlgorithmSKIPJACK, []byte("SKIPJACK")},
		{CryptographicAlgorithmTwofish, []byte("Twofish")},
		{CryptographicAlgorithmEC, []byte("EC")},
		{CryptographicAlgorithmOneTimePad, []byte("OneTimePad")},
		{CryptographicAlgorithmChaCha20, []byte("ChaCha20")},
		{CryptographicAlgorithmPoly1305, []byte("Poly1305")},
		{CryptographicAlgorithmChaCha20Poly1305, []byte("ChaCha20Poly1305")},
		{CryptographicAlgorithmSHA3_224, []byte("SHA3_224")},
		{CryptographicAlgorithmSHA3_256, []byte("SHA3_256")},
		{CryptographicAlgorithmSHA3_384, []byte("SHA3_384")},
		{CryptographicAlgorithmSHA3_512, []byte("SHA3_512")},
		{CryptographicAlgorithmHMAC_SHA3_224, []byte("HMAC_SHA3_224")},
		{CryptographicAlgorithmHMAC_SHA3_256, []byte("HMAC_SHA3_256")},
		{CryptographicAlgorithmHMAC_SHA3_384, []byte("HMAC_SHA3_384")},
		{CryptographicAlgorithmHMAC_SHA3_512, []byte("HMAC_SHA3_512")},
		{CryptographicAlgorithmSHAKE_128, []byte("SHAKE_128")},
		{CryptographicAlgorithmSHAKE_256, []byte("SHAKE_256")},
		{CryptographicAlgorithm(100), []byte("0x00000064")},
		{CryptographicAlgorithm(0xFFFFFFFF), []byte("0xFFFFFFFF")},
	}
	for _, tt := range cases {
		got, err := tt.enum.MarshalText()
		if err != nil {
			t.Errorf("MarshalText(%v) error: %v", tt.enum, err)
		}
		if !bytes.Equal(got, tt.want) {
			t.Errorf("MarshalText(%v) got %s, want %s", tt.enum, got, tt.want)
		}
	}
}

func TestCryptographicAlgorithm_UnmarshalText_AllCases(t *testing.T) {
	cases := []struct {
		input []byte
		want  CryptographicAlgorithm
	}{
		{[]byte("DES"), CryptographicAlgorithmDES},
		{[]byte("DES3"), CryptographicAlgorithm3DES},
		{[]byte("AES"), CryptographicAlgorithmAES},
		{[]byte("RSA"), CryptographicAlgorithmRSA},
		{[]byte("DSA"), CryptographicAlgorithmDSA},
		{[]byte("ECDSA"), CryptographicAlgorithmECDSA},
		{[]byte("HMAC_SHA1"), CryptographicAlgorithmHMACSHA1},
		{[]byte("HMAC_SHA224"), CryptographicAlgorithmHMACSHA224},
		{[]byte("HMAC_SHA256"), CryptographicAlgorithmHMACSHA256},
		{[]byte("HMAC_SHA384"), CryptographicAlgorithmHMACSHA384},
		{[]byte("HMAC_SHA512"), CryptographicAlgorithmHMACSHA512},
		{[]byte("HMAC_MD5"), CryptographicAlgorithmHMACMD5},
		{[]byte("DH"), CryptographicAlgorithmDH},
		{[]byte("ECDH"), CryptographicAlgorithmECDH},
		{[]byte("ECMQV"), CryptographicAlgorithmECMQV},
		{[]byte("Blowfish"), CryptographicAlgorithmBlowfish},
		{[]byte("Camellia"), CryptographicAlgorithmCamellia},
		{[]byte("CAST5"), CryptographicAlgorithmCAST5},
		{[]byte("IDEA"), CryptographicAlgorithmIDEA},
		{[]byte("MARS"), CryptographicAlgorithmMARS},
		{[]byte("RC2"), CryptographicAlgorithmRC2},
		{[]byte("RC4"), CryptographicAlgorithmRC4},
		{[]byte("RC5"), CryptographicAlgorithmRC5},
		{[]byte("SKIPJACK"), CryptographicAlgorithmSKIPJACK},
		{[]byte("Twofish"), CryptographicAlgorithmTwofish},
		{[]byte("EC"), CryptographicAlgorithmEC},
		{[]byte("OneTimePad"), CryptographicAlgorithmOneTimePad},
		{[]byte("ChaCha20"), CryptographicAlgorithmChaCha20},
		{[]byte("Poly1305"), CryptographicAlgorithmPoly1305},
		{[]byte("ChaCha20Poly1305"), CryptographicAlgorithmChaCha20Poly1305},
		{[]byte("SHA3_224"), CryptographicAlgorithmSHA3_224},
		{[]byte("SHA3_256"), CryptographicAlgorithmSHA3_256},
		{[]byte("SHA3_384"), CryptographicAlgorithmSHA3_384},
		{[]byte("SHA3_512"), CryptographicAlgorithmSHA3_512},
		{[]byte("HMAC_SHA3_224"), CryptographicAlgorithmHMAC_SHA3_224},
		{[]byte("HMAC_SHA3_256"), CryptographicAlgorithmHMAC_SHA3_256},
		{[]byte("HMAC_SHA3_384"), CryptographicAlgorithmHMAC_SHA3_384},
		{[]byte("HMAC_SHA3_512"), CryptographicAlgorithmHMAC_SHA3_512},
		{[]byte("SHAKE_128"), CryptographicAlgorithmSHAKE_128},
		{[]byte("SHAKE_256"), CryptographicAlgorithmSHAKE_256},
		{[]byte("0x00000064"), CryptographicAlgorithm(100)},
		{[]byte("0xFFFFFFFF"), CryptographicAlgorithm(0xFFFFFFFF)},
		{[]byte("UnknownAlgorithm"), 0},
	}
	for _, tt := range cases {
		var enum CryptographicAlgorithm
		err := enum.UnmarshalText(tt.input)
		if tt.input[0] == 'U' { // UnknownAlgorithm
			if err == nil {
				t.Errorf("UnmarshalText(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if enum != tt.want {
				t.Errorf("UnmarshalText(%q) got %d, want %d", tt.input, enum, tt.want)
			}
		}
	}
}

func TestBlockCipherMode_MarshalText_AllCases(t *testing.T) {
	cases := []struct {
		enum BlockCipherMode
		want []byte
	}{
		{BlockCipherModeCBC, []byte("CBC")},
		{BlockCipherModeECB, []byte("ECB")},
		{BlockCipherModePCBC, []byte("PCBC")},
		{BlockCipherModeCFB, []byte("CFB")},
		{BlockCipherModeOFB, []byte("OFB")},
		{BlockCipherModeCTR, []byte("CTR")},
		{BlockCipherModeCMAC, []byte("CMAC")},
		{BlockCipherModeCCM, []byte("CCM")},
		{BlockCipherModeGCM, []byte("GCM")},
		{BlockCipherModeCBCMAC, []byte("CBC_MAC")},
		{BlockCipherModeXTS, []byte("XTS")},
		{BlockCipherModeAESKeyWrapPadding, []byte("AESKeyWrapPadding")},
		{BlockCipherModeNISTKeyWrap, []byte("NISTKeyWrap")},
		{BlockCipherModeX9_102AESKW, []byte("X9_102AESKW")},
		{BlockCipherModeX9_102TDKW, []byte("X9_102TDKW")},
		{BlockCipherModeX9_102AKW1, []byte("X9_102AKW1")},
		{BlockCipherModeX9_102AKW2, []byte("X9_102AKW2")},
		{BlockCipherModeAEAD, []byte("AEAD")},
		{BlockCipherMode(100), []byte("0x00000064")},
		{BlockCipherMode(0xFFFFFFFF), []byte("0xFFFFFFFF")},
	}
	for _, tt := range cases {
		got, err := tt.enum.MarshalText()
		if err != nil {
			t.Errorf("MarshalText(%v) error: %v", tt.enum, err)
		}
		if !bytes.Equal(got, tt.want) {
			t.Errorf("MarshalText(%v) got %s, want %s", tt.enum, got, tt.want)
		}
	}
}

func TestBlockCipherMode_UnmarshalText_AllCases(t *testing.T) {
	cases := []struct {
		input []byte
		want  BlockCipherMode
	}{
		{[]byte("CBC"), BlockCipherModeCBC},
		{[]byte("ECB"), BlockCipherModeECB},
		{[]byte("PCBC"), BlockCipherModePCBC},
		{[]byte("CFB"), BlockCipherModeCFB},
		{[]byte("OFB"), BlockCipherModeOFB},
		{[]byte("CTR"), BlockCipherModeCTR},
		{[]byte("CMAC"), BlockCipherModeCMAC},
		{[]byte("CCM"), BlockCipherModeCCM},
		{[]byte("GCM"), BlockCipherModeGCM},
		{[]byte("CBC_MAC"), BlockCipherModeCBCMAC},
		{[]byte("XTS"), BlockCipherModeXTS},
		{[]byte("AESKeyWrapPadding"), BlockCipherModeAESKeyWrapPadding},
		{[]byte("NISTKeyWrap"), BlockCipherModeNISTKeyWrap},
		{[]byte("X9_102AESKW"), BlockCipherModeX9_102AESKW},
		{[]byte("X9_102TDKW"), BlockCipherModeX9_102TDKW},
		{[]byte("X9_102AKW1"), BlockCipherModeX9_102AKW1},
		{[]byte("X9_102AKW2"), BlockCipherModeX9_102AKW2},
		{[]byte("AEAD"), BlockCipherModeAEAD},
		{[]byte("0x00000064"), BlockCipherMode(100)},
		{[]byte("0xFFFFFFFF"), BlockCipherMode(0xFFFFFFFF)},
		{[]byte("UnknownCipherMode"), 0},
	}
	for _, tt := range cases {
		var enum BlockCipherMode
		err := enum.UnmarshalText(tt.input)
		if string(tt.input) == "UnknownCipherMode" {
			if err == nil {
				t.Errorf("UnmarshalText(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if enum != tt.want {
				t.Errorf("UnmarshalText(%q) got %d, want %d", tt.input, enum, tt.want)
			}
		}
	}
}

func TestPaddingMethod_MarshalText(t *testing.T) {
	tests := []struct {
		enum      PaddingMethod
		want      []byte
		wantError bool
	}{
		{PaddingMethodNone, []byte("None"), false},
		{PaddingMethodPKCS5, []byte("PKCS5"), false},
		{PaddingMethodOAEP, []byte("OAEP"), false},
		{PaddingMethodSSL3, []byte("SSL3"), false},
		{PaddingMethodANSIX9_23, []byte("ANSIX9_23"), false},
		{PaddingMethodISO10126, []byte("ISO10126"), false},
		{PaddingMethodPKCS1V1_5, []byte("PKCS1V1_5"), false},
		{PaddingMethod(100), []byte("0x00000064"), false},
		{PaddingMethod(0xFFFFFFFF), []byte("0xFFFFFFFF"), false},
	}
	for _, tt := range tests {
		got, err := tt.enum.MarshalText()
		if tt.wantError {
			if err == nil {
				t.Errorf("MarshalText(%v) expected error, got nil", tt.enum)
			}
		} else {
			if err != nil {
				t.Fatalf("MarshalText error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MarshalText(%v) got %s, want %s", tt.enum, got, tt.want)
			}
		}
	}
}

func TestPaddingMethod_UnmarshalText(t *testing.T) {
	tests := []struct {
		input     []byte
		want      PaddingMethod
		wantError bool
	}{
		{[]byte("None"), PaddingMethodNone, false},
		{[]byte(" None "), PaddingMethodNone, false},
		{[]byte("PKCS5"), PaddingMethodPKCS5, false},
		{[]byte("OAEP"), PaddingMethodOAEP, false},
		{[]byte("SSL3"), PaddingMethodSSL3, false},
		{[]byte("ANSIX9_23"), PaddingMethodANSIX9_23, false},
		{[]byte("ISO10126"), PaddingMethodISO10126, false},
		{[]byte("PKCS1V1_5"), PaddingMethodPKCS1V1_5, false},
		{[]byte("0x00000064"), PaddingMethod(100), false},
		{[]byte("0xFFFFFFFF"), PaddingMethod(0xFFFFFFFF), false},
		{[]byte("UnknownPadding"), 0, true},
	}
	for _, tt := range tests {
		var enum PaddingMethod
		err := enum.UnmarshalText(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("UnmarshalText(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Fatalf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if enum != tt.want {
				t.Errorf("UnmarshalText(%q) got %d, want %d", tt.input, enum, tt.want)
			}
		}
	}
}

func TestHashingAlgorithm_MarshalText(t *testing.T) {
	tests := []struct {
		enum      HashingAlgorithm
		want      []byte
		wantError bool
	}{
		{HashingAlgorithmMD5, []byte("MD5"), false},
		{HashingAlgorithm(100), []byte("0x00000064"), false},
		{HashingAlgorithm(0xFFFFFFFF), []byte("0xFFFFFFFF"), false},
	}
	for _, tt := range tests {
		got, err := tt.enum.MarshalText()
		if tt.wantError {
			if err == nil {
				t.Errorf("MarshalText(%v) expected error, got nil", tt.enum)
			}
		} else {
			if err != nil {
				t.Fatalf("MarshalText error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MarshalText(%v) got %s, want %s", tt.enum, got, tt.want)
			}
		}
	}
}

func TestHashingAlgorithm_UnmarshalText(t *testing.T) {
	tests := []struct {
		input     []byte
		want      HashingAlgorithm
		wantError bool
	}{
		{[]byte("MD5"), HashingAlgorithmMD5, false},
		{[]byte(" MD5 "), HashingAlgorithmMD5, false},
		{[]byte("0x00000064"), HashingAlgorithm(100), false},
		{[]byte("0xFFFFFFFF"), HashingAlgorithm(0xFFFFFFFF), false},
		{[]byte("UnknownHash"), 0, true},
	}
	for _, tt := range tests {
		var enum HashingAlgorithm
		err := enum.UnmarshalText(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("UnmarshalText(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Fatalf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if enum != tt.want {
				t.Errorf("UnmarshalText(%q) got %d, want %d", tt.input, enum, tt.want)
			}
		}
	}
}

func TestKeyRoleType_MarshalText(t *testing.T) {
	tests := []struct {
		enum      KeyRoleType
		want      []byte
		wantError bool
	}{
		{KeyRoleTypeBDK, []byte("BDK"), false},
		{KeyRoleTypeCVK, []byte("CVK"), false},
		{KeyRoleTypeDEK, []byte("DEK"), false},
		{KeyRoleTypeKEK, []byte("KEK"), false},
		{KeyRoleTypeMKAC, []byte("MKAC"), false},
		{KeyRoleTypeMKSMC, []byte("MKSMC"), false},
		{KeyRoleTypeMKSMI, []byte("MKSMI"), false},
		{KeyRoleType(100), []byte("0x00000064"), false},
		{KeyRoleType(0xFFFFFFFF), []byte("0xFFFFFFFF"), false},
	}
	for _, tt := range tests {
		got, err := tt.enum.MarshalText()
		if tt.wantError {
			if err == nil {
				t.Errorf("MarshalText(%v) expected error, got nil", tt.enum)
			}
		} else {
			if err != nil {
				t.Fatalf("MarshalText error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MarshalText(%v) got %s, want %s", tt.enum, got, tt.want)
			}
		}
	}
}

func TestKeyRoleType_UnmarshalText(t *testing.T) {
	tests := []struct {
		input     []byte
		want      KeyRoleType
		wantError bool
	}{
		{[]byte("BDK"), KeyRoleTypeBDK, false},
		{[]byte(" BDK "), KeyRoleTypeBDK, false},
		{[]byte("CVK"), KeyRoleTypeCVK, false},
		{[]byte("DEK"), KeyRoleTypeDEK, false},
		{[]byte("KEK"), KeyRoleTypeKEK, false},
		{[]byte("MKAC"), KeyRoleTypeMKAC, false},
		{[]byte("MKSMC"), KeyRoleTypeMKSMC, false},
		{[]byte("MKSMI"), KeyRoleTypeMKSMI, false},
		{[]byte("0x00000064"), KeyRoleType(100), false},
		{[]byte("0xFFFFFFFF"), KeyRoleType(0xFFFFFFFF), false},
		{[]byte("UnknownKeyRole"), 0, true},
	}
	for _, tt := range tests {
		var enum KeyRoleType
		err := enum.UnmarshalText(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("UnmarshalText(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Fatalf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if enum != tt.want {
				t.Errorf("UnmarshalText(%q) got %d, want %d", tt.input, enum, tt.want)
			}
		}
	}
}
