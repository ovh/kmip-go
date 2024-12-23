package ttlv

import (
	"reflect"
	"testing"
	"time"
)

func init() {
	RegisterTag("Foo", 0x1234)
	RegisterTag("Bar", 0x2222)
	RegisterTag("Toto", 0x6666, reflect.TypeFor[Baz]())
	RegisterTag("MyStruct", 1, reflect.TypeFor[MyStruct]())

	RegisterEnum[TheEnum](0x9999, nil)
	// ttlv.RegisterType[MyStruct]()
}

type TheEnum uint32

const (
	Enum12 TheEnum = 12
)

type Foo int32
type Baz int32

type MyStruct struct {
	Skipped  bool `ttlv:"-"`
	Enum     TheEnum
	Int      int32 `ttlv:"Foo"`
	Foo      int32
	Oof      Foo
	Baz      Baz
	Bool     bool          `ttlv:"0x1111"`
	Bar      []string      `ttlv:""`
	Time     time.Time     `ttlv:"0x3333"`
	Duration time.Duration `ttlv:"0x4444"`
	// Any      any           `ttlv:"0x0000"`
	OptionalPtr *string `ttlv:"0x0002"`
	Optional    string  `ttlv:"0x0002,omitempty"`
}

var v = &MyStruct{
	Enum:     Enum12,
	Int:      12,
	Foo:      13,
	Oof:      14,
	Baz:      15,
	Bool:     true,
	Bar:      []string{"foo", "bar"},
	Time:     time.Now().Round(time.Second),
	Duration: time.Hour,
	// Any:      "abcd",
}

func (m *MyStruct) encodeTTLV(e *Encoder) {
	e.Struct(1, func(e *Encoder) {
		e.Enum(0, 0x9999, uint32(m.Enum))
		// e.Any(m.Enum)
		e.Integer(0x1234, m.Int)
		e.Integer(0x1234, m.Foo)
		e.Integer(0x1234, int32(m.Oof))
		e.Integer(0x6666, int32(m.Baz))

		e.Bool(0x1111, m.Bool)
		for _, s := range m.Bar {
			e.TextString(0x2222, s)
		}
		e.DateTime(0x3333, m.Time)
		e.Interval(0x4444, m.Duration)
		// e.TagAny(0x0000, m.Any)
	})
}

func TestDecoderReflect(t *testing.T) {
	// data := MarshalTTLV(&v)
	enc := NewTTLVEncoder()
	v.encodeTTLV(&enc)
	data := enc.Bytes()
	// f := decodeFunc(reflect.TypeFor[*MyStruct]())
	// dec, err := NewDecoder(data)
	// if err != nil {
	// 	panic(err)
	// }
	val := MyStruct{}
	if err := UnmarshalTTLV(data, &val); err != nil {
		panic(err)
	}
	// if err := f(&dec, 1, reflect.ValueOf(&val)); err != nil {
	// 	panic(err)
	// }
	// assert.Equal(t, v, &val)
}
