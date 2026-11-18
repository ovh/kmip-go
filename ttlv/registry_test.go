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
	RegisterEnum(0x42FF20, names)

	for en, name := range EnumValuesByTag(0x42FF20) {
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
	RegisterEnum(0x42FF21, names)

	RegisterTag("EN", 0x42FF21, reflect.TypeFor[EN]())

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
	RegisterEnum(0x42FF22, names)

	got, err := EnumByName(0x42FF22, "Foo")
	require.NoError(t, err)
	require.Equal(t, uint32(0x000000FF), got)

	_, err = EnumByName(0x42FF22, "Bar")
	require.Error(t, err)
}

func TestBitmaskByStr(t *testing.T) {
	type BM int32
	RegisterBitmask[BM](0x42FF30, "One", "Two", "Four")

	got, err := BitmaskByStr(0x42FF30, "One")
	require.NoError(t, err)
	require.Equal(t, int32(0x00000001), got)

	_, err = BitmaskByStr(0x42FF30, "Eight")
	require.Error(t, err)
}

// getTagForType benchmarks

type benchStruct struct {
	Field1 int32
	Field2 string
}

func BenchmarkGetTagForType_Cached(b *testing.B) {
	ty := reflect.TypeFor[benchStruct]()
	// Register and pre-warm cache
	RegisterTag("BenchStruct", 0x420AA, ty)
	_, _ = getTagForType(ty)

	b.ResetTimer()
	for i := range b.N {
		tag, err := getTagForType(ty)
		if err != nil {
			b.Fatal(err)
		}
		_ = tag
		_ = i
	}
}

func BenchmarkGetTagForType(b *testing.B) {
	b.ReportAllocs()
	for i := range b.N {
		ty := reflect.TypeFor[benchStruct]()
		tag, err := getTagForType(ty)
		if err != nil {
			b.Fatal(err)
		}
		_ = tag
		_ = i
	}
}

// getTagForValue benchmarks

// benchProtocolVersion is a registered type for benchmarking
type benchProtocolVersion struct {
	Major int32
	Minor int32
}

func (benchProtocolVersion) TagEncodeTTLV(e *Encoder, tag int)        {}
func (*benchProtocolVersion) TagDecodeTTLV(d *Decoder, tag int) error { return nil }

func BenchmarkGetTagForValue_RegisteredType(b *testing.B) {
	val := benchProtocolVersion{
		Major: 1,
		Minor: 4,
	}
	RegisterTag("BenchProtocolVersion", 0x420AB, reflect.TypeFor[benchProtocolVersion]())

	b.ResetTimer()
	for i := range b.N {
		tag, err := getTagForValue(val)
		if err != nil {
			b.Fatal(err)
		}
		_ = tag
		_ = i
	}
}

func BenchmarkGetTagForValue_Pointer(b *testing.B) {
	val := &benchProtocolVersion{
		Major: 1,
		Minor: 4,
	}
	RegisterTag("BenchProtocolVersion", 0x420AB, reflect.TypeFor[benchProtocolVersion]())

	b.ResetTimer()
	for i := range b.N {
		tag, err := getTagForValue(val)
		if err != nil {
			b.Fatal(err)
		}
		_ = tag
		_ = i
	}
}

func BenchmarkGetTagForValue_Struct(b *testing.B) {
	val := benchStruct{
		Field1: 42,
		Field2: "test",
	}
	ty := reflect.TypeOf(val)
	RegisterTag("BenchStruct", 0x420AA, ty)

	// Pre-warm cache
	_, _ = getTagForType(ty)

	b.ResetTimer()
	for i := range b.N {
		tag, err := getTagForValue(val)
		if err != nil {
			b.Fatal(err)
		}
		_ = tag
		_ = i
	}
}

func BenchmarkGetTagForValue_Primitive(b *testing.B) {
	b.Run("Int32", func(b *testing.B) {
		RegisterTag("BenchInt32", 0x420AC, reflect.TypeFor[int32]())
		val := int32(42)
		for i := range b.N {
			tag, err := getTagForValue(val)
			if err != nil {
				b.Fatal(err)
			}
			_ = tag
			_ = i
		}
	})

	b.Run("String", func(b *testing.B) {
		RegisterTag("BenchString", 0x420AD, reflect.TypeFor[string]())
		val := "test"
		for i := range b.N {
			tag, err := getTagForValue(val)
			if err != nil {
				b.Fatal(err)
			}
			_ = tag
			_ = i
		}
	})
}
