package ttlv

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTextEncoding(t *testing.T) {
	dt := time.Date(2024, time.September, 16, 15, 7, 42, 0, time.UTC)
	w := newTextWriter()
	w.Struct(0x6666, func(w writer) {
		w.Integer(0x2341, 12)
		w.LongInteger(0x7634, 1234567890)
		w.Bool(0x7777, true)
		w.Struct(0x3333, func(w writer) {})
		w.TextString(0x8888, "hello world")
		w.ByteString(0x9999, []byte{1, 2, 3, 4})
		w.DateTime(0x3456, dt)
		w.Interval(0x8724, 3*time.Minute+42*time.Second)
		w.BigInteger(0x872573, big.NewInt(-123456789101112))
		w.Bitmask(0, 0x5642, 1|2)
		w.Enum(0, 0x67342, 12)
	})
	expect := `Toto (Structure): 
    0x002341 (Integer): 12
    0x007634 (LongInteger): 1234567890
    0x007777 (Boolean): true
    0x003333 (Structure): 
        ... empty ...
    0x008888 (TextString): hello world
    0x009999 (ByteString): 01020304
    0x003456 (DateTime): 2024-09-16T15:07:42Z
    0x008724 (Interval): 3m42s
    0x872573 (BigInteger): -123456789101112
    0x005642 (Integer): 0x00000001 | 0x00000002
    0x067342 (Enumeration): 0x0000000C`
	assert.Equal(t, expect, string(w.Bytes()))
	w.Clear()
	assert.Empty(t, w.Bytes())
	//TODO: Test named tags, named enums and named bitmasks
}

func TestTextEncoding_Hide(t *testing.T) {
	RegisterHideTag(0x3333)
	RegisterHideTag(0x8888)
	RegisterHideTag(0x9999)

	dt := time.Date(2024, time.September, 16, 15, 7, 42, 0, time.UTC)
	w := newTextWriter(true)
	w.Struct(0x6666, func(w writer) {
		w.Integer(0x2341, 12)
		w.LongInteger(0x7634, 1234567890)
		w.Bool(0x7777, true)
		w.Struct(0x3333, func(w writer) {})
		w.TextString(0x8888, "hello world")
		w.ByteString(0x9999, []byte{1, 2, 3, 4})
		w.DateTime(0x3456, dt)
		w.Interval(0x8724, 3*time.Minute+42*time.Second)
		w.BigInteger(0x872573, big.NewInt(-123456789101112))
		w.Bitmask(0, 0x5642, 1|2)
		w.Enum(0, 0x67342, 12)
	})
	expect := `Toto (Structure): 
    0x002341 (Integer): 12
    0x007634 (LongInteger): 1234567890
    0x007777 (Boolean): true
    0x003333 (Structure): ******
    0x008888 (TextString): ******
    0x009999 (ByteString): ******
    0x003456 (DateTime): 2024-09-16T15:07:42Z
    0x008724 (Interval): 3m42s
    0x872573 (BigInteger): -123456789101112
    0x005642 (Integer): 0x00000001 | 0x00000002
    0x067342 (Enumeration): 0x0000000C`
	assert.Equal(t, expect, string(w.Bytes()))
	w.Clear()
	assert.Empty(t, w.Bytes())
	//TODO: Test named tags, named enums and named bitmasks
}
