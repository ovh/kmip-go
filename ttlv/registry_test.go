package ttlv

import (
	"reflect"
	"testing"
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
