package ttlv

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnumValuesByTag(t *testing.T) {
	type EN uint32

	names := map[EN]string{
		0x000000FD: "Foo",
		0x000000FE: "Bar",
		0x000000FF: "FooBar",
	}
	RegisterEnum(0x420020, names)

	for en, name := range EnumValuesByTag(0x420020) {
		v, ok := names[EN(en)]
		if !ok {
			t.Errorf("Unexpected enum value: %d", en)
		}
		if v != name {
			t.Errorf("Unexpected enum name: %s", name)
		}
	}

	if got := EnumValuesByTag(0); got == nil {
		t.Errorf("Unexpected nil")
	}
}

func TestEnumValuesByName(t *testing.T) {
	type EN uint32

	names := map[EN]string{
		0x000000FD: "Foo",
		0x000000FE: "Bar",
		0x000000FF: "FooBar",
	}
	RegisterEnum(0x420020, names)

	RegisterTag("EN", 0x420020, reflect.TypeFor[EN]())

	for en, name := range EnumValuesByName("EN") {
		v, ok := names[EN(en)]
		if !ok {
			t.Errorf("Unexpected enum value: %d", en)
		}
		if v != name {
			t.Errorf("Unexpected enum name: %s", name)
		}
	}

	if got := EnumValuesByName(""); got == nil {
		t.Errorf("Unexpected nil")
	}
	if got := EnumValuesByName("CH"); got == nil {
		t.Errorf("Unexpected nil")
	}
}

func TestEnumByName(t *testing.T) {
	type EN uint32

	names := map[EN]string{
		0x000000FF: "Foo",
	}
	RegisterEnum(0x420021, names)

	got, err := EnumByName(0x420021, "Foo")
	require.NoError(t, err)
	require.Equal(t, uint32(0x000000FF), got)

	_, err = EnumByName(0x420021, "Bar")
	require.Error(t, err)
}

func TestBitmaskByStr(t *testing.T) {
	type BM int32
	RegisterBitmask[BM](0x420030, "One", "Two", "Four")

	got, err := BitmaskByStr(0x420030, "One")
	require.NoError(t, err)
	require.Equal(t, int32(0x00000001), got)

	_, err = BitmaskByStr(0x420030, "Eight")
	require.Error(t, err)
}
