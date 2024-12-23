package ttlv

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type JsonEncodingSuite struct {
	suite.Suite
	enc *jsonWriter
}

func TestJsonEncoding(t *testing.T) {
	suite.Run(t, new(JsonEncodingSuite))
}

func (s *JsonEncodingSuite) SetupTest() {
	s.enc = newJSONWriter()
}

func (s *JsonEncodingSuite) TestEncodeNamedTag() {
	RegisterTag("NamedTag", 0x42FFFF)
	s.enc.Integer(0x42FFFF, 8)
	expected := `{"tag": "NamedTag", "type": "Integer", "value": 8}`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *JsonEncodingSuite) TestEncodeInteger() {
	s.enc.Integer(0x420020, 8)
	expected := `{"tag": "0x420020", "type": "Integer", "value": 8}`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *JsonEncodingSuite) TestEncodeLongInteger() {
	s.Run("small", func() {
		s.enc.Clear()
		s.enc.LongInteger(0x420020, -42)
		expected := `{"tag": "0x420020", "type": "LongInteger", "value": -42}`
		s.Equal(expected, string(s.enc.Bytes()))
	})
	s.Run("large-positive", func() {
		s.enc.Clear()
		s.enc.LongInteger(0x420020, 123456789000000000)
		expected := `{"tag": "0x420020", "type": "LongInteger", "value": "0x01b69b4ba5749200"}`
		s.Equal(expected, string(s.enc.Bytes()))
	})
	s.Run("large-negactive", func() {
		s.enc.Clear()
		s.enc.LongInteger(0x420020, -123456789000000000)
		expected := `{"tag": "0x420020", "type": "LongInteger", "value": "0xfe4964b45a8b6e00"}`
		s.Equal(expected, string(s.enc.Bytes()))
	})
}

func (s *JsonEncodingSuite) TestEncodeBigInteger() {
	s.Run("large-positive", func() {
		s.enc.Clear()
		b := big.NewInt(0)
		b.SetString("1234567890000000000000000000", 10)
		s.enc.BigInteger(0x420020, b)
		expected := `{"tag": "0x420020", "type": "BigInteger", "value": "0x0000000003fd35eb6bc2df4618080000"}`
		s.Equal(expected, string(s.enc.Bytes()))
	})
	s.Run("small-positive", func() {
		s.enc.Clear()
		b := big.NewInt(0)
		b.SetString("42", 10)
		s.enc.BigInteger(0x420020, b)
		expected := `{"tag": "0x420020", "type": "BigInteger", "value": 42}`
		s.Equal(expected, string(s.enc.Bytes()))
	})
	s.Run("zero", func() {
		s.enc.Clear()
		b := big.NewInt(0)
		s.enc.BigInteger(0x420020, b)
		expected := `{"tag": "0x420020", "type": "BigInteger", "value": 0}`
		s.Equal(expected, string(s.enc.Bytes()))
	})
	s.Run("large-negative", func() {
		s.enc.Clear()
		b := big.NewInt(0)
		b.SetString("-1234567890000000000000000000", 10)
		s.enc.BigInteger(0x420020, b)
		expected := `{"tag": "0x420020", "type": "BigInteger", "value": "0xfffffffffc02ca14943d20b9e7f80000"}`
		s.Equal(expected, string(s.enc.Bytes()))
	})
	s.Run("small-negative", func() {
		s.enc.Clear()
		b := big.NewInt(0)
		b.SetString("-42", 10)
		s.enc.BigInteger(0x420020, b)
		expected := `{"tag": "0x420020", "type": "BigInteger", "value": -42}`
		s.Equal(expected, string(s.enc.Bytes()))
	})
}

func (s *JsonEncodingSuite) TestEncodeEnum() {
	s.enc.Enum(0, 0x420012, 0xFF)
	expected := `{"tag": "0x420012", "type": "Enumeration", "value": "0x000000FF"}`
	s.Equal(expected, string(s.enc.Bytes()))

	type EN uint32
	RegisterEnum(0x420012, map[EN]string{
		0x000000FF: "FooBar",
	})
	s.enc.Clear()
	s.enc.Enum(0, 0x420012, 0xFF)
	expected = `{"tag": "0x420012", "type": "Enumeration", "value": "FooBar"}`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *JsonEncodingSuite) TestEncodeBoolean() {
	s.Run("true", func() {
		s.enc.Clear()
		s.enc.Bool(0x420020, true)
		expected := `{"tag": "0x420020", "type": "Boolean", "value": true}`
		s.Equal(expected, string(s.enc.Bytes()))
	})
	s.Run("false", func() {
		s.enc.Clear()
		s.enc.Bool(0x420020, false)
		expected := `{"tag": "0x420020", "type": "Boolean", "value": false}`
		s.Equal(expected, string(s.enc.Bytes()))
	})
}

func (s *JsonEncodingSuite) TestEncodeTextString() {
	s.enc.TextString(0x420020, "Hello World")
	expected := `{"tag": "0x420020", "type": "TextString", "value": "Hello World"}`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *JsonEncodingSuite) TestEncodeByteString() {
	s.enc.ByteString(0x420020, []byte{0x01, 0x02, 0x03})
	expected := `{"tag": "0x420020", "type": "ByteString", "value": "010203"}`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *JsonEncodingSuite) TestEncodeDateTime() {
	dt := time.Date(2008, time.March, 14, 11, 56, 40, 0, time.UTC)
	s.enc.DateTime(0x420020, dt)
	expected := `{"tag": "0x420020", "type": "DateTime", "value": "2008-03-14T11:56:40Z"}`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *JsonEncodingSuite) TestEncodeInterval() {
	s.Run("positive", func() {
		s.enc.Clear()
		s.enc.Interval(0x420020, 10*24*time.Hour)
		expected := `{"tag": "0x420020", "type": "Interval", "value": 864000}`
		s.Equal(expected, string(s.enc.Bytes()))
	})
	s.Run("negative", func() {
		s.enc.Clear()
		s.Panics(func() {
			s.enc.Interval(0x420020, -10*24*time.Hour)
		})
	})
}

func (s *JsonEncodingSuite) TestEncodeStruct() {
	s.enc.Struct(0x420020, func(w writer) {
		w.Enum(0, 0x420004, 254)
		w.Integer(0x420005, 255)
		w.Struct(0x420006, func(w writer) {})
	})
	expected := `{"tag": "0x420020", "value": [
    {"tag": "0x420004", "type": "Enumeration", "value": "0x000000FE"},
    {"tag": "0x420005", "type": "Integer", "value": 255},
    {"tag": "0x420006", "value": []}
]}`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *JsonEncodingSuite) TestEncodeBitmask() {
	s.enc.Bitmask(0, 0x420013, 1|2)
	expected := `{"tag": "0x420013", "type": "Integer", "value": "0x00000001|0x00000002"}`

	s.Equal(expected, string(s.enc.Bytes()))

	type BM int32
	RegisterBitmask[BM](0x420013, "Foo", "Bar")
	s.enc.Clear()
	s.enc.Bitmask(0, 0x420013, 1|2|4)
	expected = `{"tag": "0x420013", "type": "Integer", "value": "Foo|Bar|0x00000004"}`
	s.Equal(expected, string(s.enc.Bytes()))
}

type JsonDecodingSuite struct {
	suite.Suite
}

func TestJsonDecoding(t *testing.T) {
	suite.Run(t, new(JsonDecodingSuite))
}

func (s *JsonDecodingSuite) newReader(data string) *jsonReader {
	r, err := newJSONReader([]byte(data))
	s.NoError(err)
	return r
}

func (s *JsonDecodingSuite) TestDecodeNamedTag() {
	RegisterTag("NamedTag", 0x42FFFF)
	// data := `<NamedTag type="Integer" value="8"/><NamedTag type="Integer" value="8"/>`
	data := `{"tag": "NamedTag", "type": "Integer", "value": 8}`
	r := s.newReader(data)
	n, err := r.Integer(0x42FFFF)
	s.NoError(err)
	s.EqualValues(8, n)
	// n, err = r.Integer(0x42FFFF)
	// s.NoError(err)
	// s.EqualValues(8, n)
}

func (s *JsonDecodingSuite) TestDecodeEOF() {
	data := `{"tag": "0x420020", "type": "Integer", "value": 8}`
	r := s.newReader(data)
	n, err := r.Integer(0x420020)
	s.NoError(err)
	s.EqualValues(8, n)

	n, err = r.Integer(0x420020)
	s.Zero(n)
	s.ErrorIs(err, ErrEOF)
}

func (s *JsonDecodingSuite) TestDecodeInteger() {
	data := `{"tag": "0x420020", "type": "Integer", "value": 8}`
	r := s.newReader(data)
	n, err := r.Integer(0x420020)
	s.NoError(err)
	s.EqualValues(8, n)

	n, err = r.Integer(0x420020)
	s.Zero(n)
	s.ErrorIs(err, ErrEOF)
}

func (s *JsonDecodingSuite) TestDecodeLongInteger() {
	s.Run("large-plain", func() {
		data := `{"tag": "0x420020", "type": "LongInteger", "value": 123456789000000000}`
		r := s.newReader(data)
		n, err := r.LongInteger(0x420020)
		s.NoError(err)
		s.EqualValues(123456789000000000, n)
	})
	s.Run("small-plain", func() {
		data := `{"tag": "0x420020", "type": "LongInteger", "value": -42}`
		r := s.newReader(data)
		n, err := r.LongInteger(0x420020)
		s.NoError(err)
		s.EqualValues(-42, n)
	})
	s.Run("large-positive", func() {
		data := `{"tag": "0x420020", "type": "LongInteger", "value": "0x01b69b4ba5749200"}`
		r := s.newReader(data)
		n, err := r.LongInteger(0x420020)
		s.NoError(err)
		s.EqualValues(123456789000000000, n)
	})
	s.Run("large-negactive", func() {
		data := `{"tag": "0x420020", "type": "LongInteger", "value": "0xfe4964b45a8b6e00"}`
		r := s.newReader(data)
		n, err := r.LongInteger(0x420020)
		s.NoError(err)
		s.EqualValues(-123456789000000000, n)
	})
}

func (s *JsonDecodingSuite) TestDecodeBigInteger() {
	s.Run("positive", func() {
		data := `{"tag": "0x420020", "type": "BigInteger", "value": "0x03FD35EB6BC2DF4618080000"}`
		r := s.newReader(data)
		n, err := r.BigInteger(0x420020)
		s.NoError(err)
		s.EqualValues("1234567890000000000000000000", n.String())
	})
	s.Run("zero", func() {
		data := `{"tag": "0x420020", "type": "BigInteger", "value": 0}`
		r := s.newReader(data)
		n, err := r.BigInteger(0x420020)
		s.NoError(err)
		s.EqualValues(0, n.Int64())
	})
	s.Run("negative", func() {
		data := `{"tag": "0x420020", "type": "BigInteger", "value": "0xFC02CA14943D20B9E7F80000"}`
		r := s.newReader(data)
		n, err := r.BigInteger(0x420020)
		s.NoError(err)
		s.EqualValues("-1234567890000000000000000000", n.String())
	})
}

func (s *JsonDecodingSuite) TestDecodeEnum() {
	data := `{"tag": "0x420020", "type": "Enumeration", "value": "0x000000FF"}`
	r := s.newReader(data)
	n, err := r.Enum(0, 0x420020)
	s.NoError(err)
	s.EqualValues(0xFF, n)

	type EN uint32
	RegisterEnum(0x420020, map[EN]string{
		0x000000FF: "FooBar",
	})
	data = `{"tag": "0x420020", "type": "Enumeration", "value": "FooBar"}`
	r = s.newReader(data)
	n, err = r.Enum(0, 0x420020)
	s.NoError(err)
	s.EqualValues(uint32(0xFF), n)
}

func (s *JsonDecodingSuite) TestDecodeBoolean() {
	s.Run("true", func() {
		data := `{"tag": "0x420020", "type": "Boolean", "value": true}`
		r := s.newReader(data)
		n, err := r.Bool(0x420020)
		s.NoError(err)
		s.True(n)
	})
	s.Run("false", func() {
		data := `{"tag": "0x420020", "type": "Boolean", "value": false}`
		r := s.newReader(data)
		n, err := r.Bool(0x420020)
		s.NoError(err)
		s.False(n)
	})
	s.Run("true-hex", func() {
		data := `{"tag": "0x420020", "type": "Boolean", "value": "0x000001"}`
		r := s.newReader(data)
		n, err := r.Bool(0x420020)
		s.NoError(err)
		s.True(n)
	})
	s.Run("false-hex", func() {
		data := `{"tag": "0x420020", "type": "Boolean", "value": "0x00000"}`
		r := s.newReader(data)
		n, err := r.Bool(0x420020)
		s.NoError(err)
		s.False(n)
	})
}

func (s *JsonDecodingSuite) TestDecodeTextString() {
	data := `{"tag": "0x420020", "type": "TextString", "value": "Hello World"}`
	r := s.newReader(data)
	n, err := r.TextString(0x420020)
	s.NoError(err)
	s.EqualValues("Hello World", n)
}

func (s *JsonDecodingSuite) TestDecodeByteString() {
	data := `{"tag": "0x420020", "type": "ByteString", "value": "010203"}`
	r := s.newReader(data)
	n, err := r.ByteString(0x420020)
	s.NoError(err)
	s.EqualValues([]byte{0x01, 0x02, 0x03}, n)
}

func (s *JsonDecodingSuite) TestDecodeDateTime() {
	data := `{"tag": "0x420020", "type": "DateTime", "value": "2008-03-14T11:56:40Z"}`
	r := s.newReader(data)
	n, err := r.DateTime(0x420020)
	s.NoError(err)
	s.EqualValues(time.Date(2008, time.March, 14, 11, 56, 40, 0, time.UTC), n.UTC())
}

func (s *JsonDecodingSuite) TestDecodeInterval() {
	data := `{"tag": "0x420020", "type": "Interval", "value": 864000}`
	r := s.newReader(data)
	n, err := r.Interval(0x420020)
	s.NoError(err)
	s.EqualValues(10*24*time.Hour, n)
}

func (s *JsonDecodingSuite) TestDecodeStruct() {
	data := `{"tag": "0x420020", "value": [
    {"tag": "0x420005", "type": "Integer", "value": 255},
    {"tag": "0x420006", "value": []}
]}`
	r := s.newReader(data)
	err := r.Struct(0x420020, func(r reader) error {
		if _, err := r.Integer(0x420005); err != nil {
			return err
		}
		return r.Struct(0x420006, func(r reader) error { return nil })
	})
	s.NoError(err)
	// _, err = r.Integer(0x420006)
	// s.NoError(err)
}

func (s *JsonDecodingSuite) TestDecodeBitmask() {
	data := `{"tag": "0x420004", "type": "Integer", "value": "0x00000001|0x00000002"}`
	r := s.newReader(data)
	bm, err := r.Bitmask(0, 0x420004)
	s.NoError(err)
	s.Equal(int32(1|2), bm)

	type BM int32
	RegisterBitmask[BM](0x420004, "Foo", "Bar")
	data = `{"tag": "0x420004", "type": "Integer", "value": "Foo|Bar|0x00000004"}`
	r = s.newReader(data)
	bm, err = r.Bitmask(0, 0x420004)
	s.NoError(err)
	s.Equal(int32(1|2|4), bm)
}
