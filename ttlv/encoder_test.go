package ttlv_test

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ovh/kmip-go/ttlv"

	"github.com/stretchr/testify/assert"
)

func init() {
	ttlv.RegisterTag("Foo", 0x1234)
	ttlv.RegisterTag("Bar", 0x2222)
	ttlv.RegisterTag("Toto", 0x6666, reflect.TypeFor[Baz]())

	ttlv.RegisterEnum[TheEnum](0x9999, nil)
	// ttlv.RegisterType[MyStruct]()
}

type TheEnum uint32

const (
	Enum12 TheEnum = 12
)

type Foo int32
type Baz int32

type MyStruct struct {
	Skipped     bool `ttlv:"-"`
	Enum        TheEnum
	Int         int32 `ttlv:"Foo"`
	Foo         int32
	Oof         Foo
	Baz         Baz
	Bool        bool          `ttlv:"0x1111"`
	Bar         []string      `ttlv:""`
	Time        time.Time     `ttlv:"0x3333"`
	Duration    time.Duration `ttlv:"0x4444"`
	Any         any           `ttlv:"0x0001"`
	OptionalPtr *string       `ttlv:"0x0002"`
	Optional    string        `ttlv:"0x0002,omitempty"`
}

var v = &MyStruct{
	Enum:     Enum12,
	Int:      12,
	Foo:      13,
	Oof:      14,
	Baz:      15,
	Bool:     true,
	Bar:      []string{"foo", "bar"},
	Time:     time.Now(),
	Duration: time.Hour,
	Any:      "abcd",
}

func (m *MyStruct) encodeTTLV(e *ttlv.Encoder) {
	e.Struct(1, func(e *ttlv.Encoder) {
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
		e.TagAny(0x0001, m.Any)
	})
}

// func TestEncoderReflect(t *testing.T) {
// 	enc := Encoder{}
// 	v := &MyStruct{Int: 12, Bool: true, Str: []string{"foo", "bar"}}
// 	enc.reflectEncode(1, reflect.ValueOf(v))

// 	expectedEnc := Encoder{}
// 	v.encodeTTLV(&expectedEnc)

// 	assert.Equal(t, strings.ToUpper(hex.EncodeToString(expectedEnc.buf)), strings.ToUpper(hex.EncodeToString(enc.buf)))
// }

func TestEncoderReflectFunc(t *testing.T) {
	enc := ttlv.MarshalTTLV(v)

	expectedEnc := ttlv.NewTTLVEncoder()
	v.encodeTTLV(&expectedEnc)

	assert.Equal(t, strings.ToUpper(hex.EncodeToString(expectedEnc.Bytes())), strings.ToUpper(hex.EncodeToString(enc)))
}

func BenchmarkEncodeManual(b *testing.B) {
	enc := ttlv.NewTTLVEncoder()
	b.ResetTimer()
	for range b.N {
		enc.Clear()
		v.encodeTTLV(&enc)
	}
}

func BenchmarkEncodeAny(b *testing.B) {
	enc := ttlv.NewTTLVEncoder()
	b.ResetTimer()
	for range b.N {
		enc.Clear()
		enc.TagAny(1, v)
	}
}
