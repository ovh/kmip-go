package kmip

import (
	"encoding/json"
	"testing"
)

func TestBitmasks(t *testing.T) {
	t.Run("CryptographicUsageMask", func(t *testing.T) {
		testBitmaskMarshal(t, `"Sign | Encrypt"`, CryptographicUsageSign|CryptographicUsageEncrypt)
		testBitmaskMarshal(t, `"Sign"`, CryptographicUsageSign)
		testBitmaskMarshal(t, `"0x01000000 | 0x02000000 | 0x04000000 | 0x08000000"`, CryptographicUsageMask(0x0F000000))

		testBitmaskUnmarshal(t, `"Sign | Encrypt"`, CryptographicUsageSign|CryptographicUsageEncrypt)
		testBitmaskUnmarshal(t, `"Sign | | Encrypt"`, CryptographicUsageSign|CryptographicUsageEncrypt)
		testBitmaskUnmarshal(t, `"Sign|Encrypt"`, CryptographicUsageSign|CryptographicUsageEncrypt)
		testBitmaskUnmarshal(t, `"1 | 4"`, CryptographicUsageSign|CryptographicUsageEncrypt)
		testBitmaskUnmarshal(t, `"0x00000001 | 0x00000004"`, CryptographicUsageSign|CryptographicUsageEncrypt)
		testBitmaskUnmarshal(t, `"Sign"`, CryptographicUsageSign)
		testBitmaskUnmarshal(t, `""`, CryptographicUsageMask(0))
		testBitmaskUnmarshal(t, `" "`, CryptographicUsageMask(0))

		// KMIP 2.0
		testBitmaskMarshal(t, `"Authenticate | FPEDecrypt"`, CryptographicUsageAuthenticate|CryptographicUsageFPEDecrypt)
		testBitmaskUnmarshal(t, `"Unrestricted | FPEEncrypt"`, CryptographicUsageUnrestricted|CryptographicUsageFPEEncrypt)
		testBitmaskUnmarshal(t, `"0x00100000 | 0x00800000"`, CryptographicUsageAuthenticate|CryptographicUsageFPEDecrypt)
	})

	t.Run("StorageStatusMask", func(t *testing.T) {
		if StorageStatusDestroyedStorage != 0x00000004 {
			t.Errorf("Destroyed Storage is 0x%08X, want 0x00000004", int32(StorageStatusDestroyedStorage))
		}
		testBitmaskMarshal(t, `"OnLineStorage | DestroyedStorage"`, StorageStatusOnlineStorage|StorageStatusDestroyedStorage)
		testBitmaskUnmarshal(t, `"DestroyedStorage"`, StorageStatusDestroyedStorage)
	})

	t.Run("ProtectionStorageMask", func(t *testing.T) {
		testBitmaskMarshal(t, `"Software | Hardware"`, ProtectionStorageSoftware|ProtectionStorageHardware)
		testBitmaskMarshal(t, `"SameJurisdiction"`, ProtectionStorageSameJurisdiction)
		testBitmaskMarshal(t, `"0x01000000 | 0x02000000 | 0x04000000 | 0x08000000"`, ProtectionStorageMask(0x0F000000))

		testBitmaskUnmarshal(t, `"Software | Hardware"`, ProtectionStorageSoftware|ProtectionStorageHardware)
		testBitmaskUnmarshal(t, `"Software | | Hardware"`, ProtectionStorageSoftware|ProtectionStorageHardware)
		testBitmaskUnmarshal(t, `"Software|Hardware"`, ProtectionStorageSoftware|ProtectionStorageHardware)
		testBitmaskUnmarshal(t, `"1 | 2"`, ProtectionStorageSoftware|ProtectionStorageHardware)
		testBitmaskUnmarshal(t, `"0x00000100 | 0x00002000"`, ProtectionStorageOnPremises|ProtectionStorageSameJurisdiction)
		testBitmaskUnmarshal(t, `"OnPremises"`, ProtectionStorageOnPremises)
		testBitmaskUnmarshal(t, `""`, ProtectionStorageMask(0))
		testBitmaskUnmarshal(t, `" "`, ProtectionStorageMask(0))
	})

	t.Run("StorageStatusMask", func(t *testing.T) {
		testBitmaskMarshal(t, `"OnLineStorage | ArchivalStorage"`, StorageStatusOnlineStorage|StorageStatusArchivalStorage)
		testBitmaskMarshal(t, `"OnLineStorage"`, StorageStatusOnlineStorage)
		testBitmaskMarshal(t, `"0x01000000 | 0x02000000 | 0x04000000 | 0x08000000"`, StorageStatusMask(0x0F000000))

		testBitmaskUnmarshal(t, `"OnLineStorage | ArchivalStorage"`, StorageStatusOnlineStorage|StorageStatusArchivalStorage)
		testBitmaskUnmarshal(t, `"OnLineStorage | | ArchivalStorage"`, StorageStatusOnlineStorage|StorageStatusArchivalStorage)
		testBitmaskUnmarshal(t, `"OnLineStorage|ArchivalStorage"`, StorageStatusOnlineStorage|StorageStatusArchivalStorage)
		testBitmaskUnmarshal(t, `"1 | 2"`, StorageStatusOnlineStorage|StorageStatusArchivalStorage)
		testBitmaskUnmarshal(t, `"0x00000001 | 0x00000002"`, StorageStatusOnlineStorage|StorageStatusArchivalStorage)
		testBitmaskUnmarshal(t, `"OnLineStorage"`, StorageStatusOnlineStorage)
		testBitmaskUnmarshal(t, `""`, StorageStatusMask(0))
		testBitmaskUnmarshal(t, `" "`, StorageStatusMask(0))
	})
}

func testBitmaskMarshal[T ~int32](t *testing.T, name string, mask T) {
	got, err := json.Marshal(mask)
	if err != nil {
		t.Errorf("Marshal(%d) error: %v", mask, err)
		return
	}

	if string(got) != name {
		t.Errorf("Marshal(%d) = %s, want %s", mask, string(got), name)
		return
	}
}
func testBitmaskUnmarshal[T ~int32](t *testing.T, name string, mask T) {
	var got T
	err := json.Unmarshal([]byte(name), &got)
	if err != nil {
		t.Fatalf("Unmarshal(%s) error: %v", name, err)
	}

	if got != mask {
		t.Errorf("Unmarshal(%s) got %d, want %d", name, got, mask)
		return
	}
}

/*
func testBitmask[T ~int32](t *testing.T, name string, mask T) {
	gotName, err := json.Marshal(mask)
	if err != nil {
		t.Errorf("Marshal(%d) error: %v", mask, err)
		return
	}

	wantName := `"` + name + `"`
	if string(gotName) != wantName && wantName != "\"UnknownValue\"" {
		t.Errorf("Marshal(%d) = %s, want %s", mask, gotName, wantName)
		return
	}

	var gotMask T
	err = json.Unmarshal(gotName, &gotMask)
	if err != nil {
		t.Fatalf("Unmarshal(%s) error: %v", gotName, err)
	}

	if gotMask != mask {
		t.Errorf("Unmarshal(%s) got %d, want %d", gotName, gotMask, mask)
		return
	}
}
*/
