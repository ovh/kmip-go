package ttlv

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type XmlEncodingSuite struct {
	suite.Suite
	enc *xmlWriter
}

func TestXmlEncoding(t *testing.T) {
	suite.Run(t, new(XmlEncodingSuite))
}

func (s *XmlEncodingSuite) SetupTest() {
	s.enc = newXMLWriter()
}

func (s *XmlEncodingSuite) TestEncodeNamedTag() {
	RegisterTag("NamedTag", 0x42FFFF)
	s.enc.Integer(0x42FFFF, 8)
	expected := `<NamedTag type="Integer" value="8"/>`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *XmlEncodingSuite) TestEncodeInteger() {
	s.enc.Integer(0x420020, 8)
	expected := `<TTLV tag="0x420020" type="Integer" value="8"/>`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *XmlEncodingSuite) TestEncodeLongInteger() {
	s.enc.LongInteger(0x420020, 123456789000000000)
	expected := `<TTLV tag="0x420020" type="LongInteger" value="123456789000000000"/>`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *XmlEncodingSuite) TestEncodeBigInteger() {
	s.Run("positive", func() {
		s.enc.Clear()
		b := big.NewInt(0)
		b.SetString("1234567890000000000000000000", 10)
		s.enc.BigInteger(0x420020, b)
		expected := `<TTLV tag="0x420020" type="BigInteger" value="03FD35EB6BC2DF4618080000"/>`
		s.Equal(expected, string(s.enc.Bytes()))
	})
	s.Run("zero", func() {
		s.enc.Clear()
		b := big.NewInt(0)
		s.enc.BigInteger(0x420020, b)
		expected := `<TTLV tag="0x420020" type="BigInteger" value="00"/>`
		s.Equal(expected, string(s.enc.Bytes()))
	})
	s.Run("negative", func() {
		s.enc.Clear()
		b := big.NewInt(0)
		b.SetString("-1234567890000000000000000000", 10)
		s.enc.BigInteger(0x420020, b)
		expected := `<TTLV tag="0x420020" type="BigInteger" value="FC02CA14943D20B9E7F80000"/>`
		s.Equal(expected, string(s.enc.Bytes()))
	})
}

func (s *XmlEncodingSuite) TestEncodeEnum() {
	s.enc.Enum(0, 0x420004, 0xFF)
	expected := `<TTLV tag="0x420004" type="Enumeration" value="0x000000FF"/>`
	s.Equal(expected, string(s.enc.Bytes()))

	type EN uint32
	RegisterEnum(0x420004, map[EN]string{
		0x000000FF: "FooBar",
	})
	s.enc.Clear()
	s.enc.Enum(0, 0x420004, 0xFF)
	expected = `<TTLV tag="0x420004" type="Enumeration" value="FooBar"/>`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *XmlEncodingSuite) TestEncodeBoolean() {
	s.Run("true", func() {
		s.enc.Clear()
		s.enc.Bool(0x420020, true)
		expected := `<TTLV tag="0x420020" type="Boolean" value="true"/>`
		s.Equal(expected, string(s.enc.Bytes()))
	})
	s.Run("false", func() {
		s.enc.Clear()
		s.enc.Bool(0x420020, false)
		expected := `<TTLV tag="0x420020" type="Boolean" value="false"/>`
		s.Equal(expected, string(s.enc.Bytes()))
	})
}

func (s *XmlEncodingSuite) TestEncodeTextString() {
	s.enc.TextString(0x420020, "Hello World")
	expected := `<TTLV tag="0x420020" type="TextString" value="Hello World"/>`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *XmlEncodingSuite) TestEncodeByteString() {
	s.enc.ByteString(0x420020, []byte{0x01, 0x02, 0x03})
	expected := `<TTLV tag="0x420020" type="ByteString" value="010203"/>`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *XmlEncodingSuite) TestEncodeDateTime() {
	dt := time.Date(2008, time.March, 14, 11, 56, 40, 0, time.UTC)
	s.enc.DateTime(0x420020, dt)
	expected := `<TTLV tag="0x420020" type="DateTime" value="2008-03-14T11:56:40Z"/>`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *XmlEncodingSuite) TestEncodeInterval() {
	s.enc.Interval(0x420020, 10*24*time.Hour)
	expected := `<TTLV tag="0x420020" type="Interval" value="864000"/>`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *XmlEncodingSuite) TestEncodeStruct() {
	s.enc.Struct(0x420020, func(e writer) {
		e.Enum(0, 0x420004, 254)
		e.Integer(0x420005, 255)
	})
	expected := `<TTLV tag="0x420020">
    <TTLV tag="0x420004" type="Enumeration" value="0x000000FE"/>
    <TTLV tag="0x420005" type="Integer" value="255"/>
</TTLV>`
	s.Equal(expected, string(s.enc.Bytes()))
}

func (s *XmlEncodingSuite) TestEncodeBitmask() {
	s.enc.Bitmask(0, 0x420014, 1|2)
	expected := `<TTLV tag="0x420014" type="Integer" value="0x00000001 0x00000002"/>`
	s.Equal(expected, string(s.enc.Bytes()))

	type BM int32
	RegisterBitmask[BM](0x420014, "Foo", "Bar")
	s.enc.Clear()
	s.enc.Bitmask(0, 0x420014, 1|2|4)
	expected = `<TTLV tag="0x420014" type="Integer" value="Foo Bar 0x00000004"/>`
	s.Equal(expected, string(s.enc.Bytes()))
}

type XmlDecodingSuite struct {
	suite.Suite
}

func TestXmlDecoding(t *testing.T) {
	suite.Run(t, new(XmlDecodingSuite))
}

func (s *XmlDecodingSuite) newReader(data string) *xmlReader {
	r, err := newXMLReader([]byte(data))
	s.NoError(err)
	return r
}

func (s *XmlDecodingSuite) TestDecodeNamedTag() {
	RegisterTag("NamedTag", 0x42FFFF)
	data := `<NamedTag type="Integer" value="8"/><NamedTag type="Integer" value="8"/>`
	r := s.newReader(data)
	n, err := r.Integer(0x42FFFF)
	s.NoError(err)
	s.EqualValues(8, n)
	n, err = r.Integer(0x42FFFF)
	s.NoError(err)
	s.EqualValues(8, n)
}

func (s *XmlDecodingSuite) TestDecodeEOF() {
	data := `<TTLV tag="0x420020" type="Integer" value="8"/>`
	r := s.newReader(data)
	n, err := r.Integer(0x420020)
	s.NoError(err)
	s.EqualValues(8, n)

	n, err = r.Integer(0x420020)
	s.Zero(n)
	s.ErrorIs(err, ErrEOF)
}

func (s *XmlDecodingSuite) TestDecodeInteger() {
	data := `<TTLV tag="0x420020" type="Integer" value="8"/>`
	r := s.newReader(data)
	n, err := r.Integer(0x420020)
	s.NoError(err)
	s.EqualValues(8, n)

	n, err = r.Integer(0x420020)
	s.Zero(n)
	s.ErrorIs(err, ErrEOF)
}

func (s *XmlDecodingSuite) TestDecodeLongInteger() {
	data := `<TTLV tag="0x420020" type="LongInteger" value="123456789000000000"/>`
	r := s.newReader(data)
	n, err := r.LongInteger(0x420020)
	s.NoError(err)
	s.EqualValues(123456789000000000, n)
}

func (s *XmlDecodingSuite) TestDecodeBigInteger() {
	s.Run("positive", func() {
		data := `<TTLV tag="0x420020" type="BigInteger" value="03FD35EB6BC2DF4618080000"/>`
		r := s.newReader(data)
		n, err := r.BigInteger(0x420020)
		s.NoError(err)
		s.EqualValues("1234567890000000000000000000", n.String())
	})
	s.Run("zero", func() {
		data := `<TTLV tag="0x420020" type="BigInteger" value="00"/>`
		r := s.newReader(data)
		n, err := r.BigInteger(0x420020)
		s.NoError(err)
		s.EqualValues(0, n.Int64())
	})
	s.Run("negative", func() {
		data := `<TTLV tag="0x420020" type="BigInteger" value="FC02CA14943D20B9E7F80000"/>`
		r := s.newReader(data)
		n, err := r.BigInteger(0x420020)
		s.NoError(err)
		s.EqualValues("-1234567890000000000000000000", n.String())
	})
}

func (s *XmlDecodingSuite) TestDecodeEnum() {
	data := `<TTLV tag="0x420020" type="Enumeration" value="0x000000FF"/>`
	r := s.newReader(data)
	n, err := r.Enum(0, 0x420020)
	s.NoError(err)
	s.EqualValues(0xFF, n)

	type EN uint32
	RegisterEnum(0x420020, map[EN]string{
		0x000000FF: "FooBar",
	})
	data = `<TTLV tag="0x420020" type="Enumeration" value="FooBar"/>`
	r = s.newReader(data)
	n, err = r.Enum(0, 0x420020)
	s.NoError(err)
	s.EqualValues(uint32(0xFF), n)
}

func (s *XmlDecodingSuite) TestDecodeBoolean() {
	s.Run("true", func() {
		data := `<TTLV tag="0x420020" type="Boolean" value="true"/>`
		r := s.newReader(data)
		n, err := r.Bool(0x420020)
		s.NoError(err)
		s.True(n)
	})
	s.Run("false", func() {
		data := `<TTLV tag="0x420020" type="Boolean" value="false"/>`
		r := s.newReader(data)
		n, err := r.Bool(0x420020)
		s.NoError(err)
		s.False(n)
	})
}

func (s *XmlDecodingSuite) TestDecodeTextString() {
	data := `<TTLV tag="0x420020" type="TextString" value="Hello World"/>`
	r := s.newReader(data)
	n, err := r.TextString(0x420020)
	s.NoError(err)
	s.EqualValues("Hello World", n)
}

func (s *XmlDecodingSuite) TestDecodeByteString() {
	data := `<TTLV tag="0x420020" type="ByteString" value="010203"/>`
	r := s.newReader(data)
	n, err := r.ByteString(0x420020)
	s.NoError(err)
	s.EqualValues([]byte{0x01, 0x02, 0x03}, n)
}

func (s *XmlDecodingSuite) TestDecodeDateTime() {
	data := `<TTLV tag="0x420020" type="DateTime" value="2008-03-14T11:56:40Z"/>`
	r := s.newReader(data)
	n, err := r.DateTime(0x420020)
	s.NoError(err)
	s.EqualValues(time.Date(2008, time.March, 14, 11, 56, 40, 0, time.UTC), n.UTC())
}

func (s *XmlDecodingSuite) TestDecodeInterval() {
	data := `<TTLV tag="0x420020" type="Interval" value="864000"/>`
	r := s.newReader(data)
	n, err := r.Interval(0x420020)
	s.NoError(err)
	s.EqualValues(10*24*time.Hour, n)
}

func (s *XmlDecodingSuite) TestDecodeStruct() {
	data := `<TTLV tag="0x420020">
    <TTLV tag="0x420004" type="Enumeration" value="0x000000FE"/>
    <TTLV tag="0x420005" type="Integer" value="255"/>
</TTLV>
<TTLV tag="0x420006" type="Integer" value="255"/>`
	r := s.newReader(data)
	err := r.Struct(0x420020, func(r reader) error {
		if _, err := r.Enum(0, 0x420004); err != nil {
			return err
		}
		_, err := r.Integer(0x420005)
		return err
	})
	s.NoError(err)
	_, err = r.Integer(0x420006)
	s.NoError(err)

	r = s.newReader(data)
	err = r.Struct(0x420020, func(r reader) error {
		if _, err := r.Enum(0, 0x420004); err != nil {
			return err
		}
		if _, err := r.Integer(0x420005); err != nil {
			return err
		}
		_, err := r.Integer(0x420006)
		return err
	})
	s.ErrorIs(err, ErrEOF)
	_, err = r.Integer(0x420006)
	s.Error(err)
}

func (s *XmlDecodingSuite) TestDecodeBitmask() {
	data := `<TTLV tag="0x420004" type="Integer" value="0x00000001 0x00000002"/>`
	r := s.newReader(data)
	bm, err := r.Bitmask(0, 0x420004)
	s.NoError(err)
	s.Equal(int32(1|2), bm)

	type BM int32
	RegisterBitmask[BM](0x420004, "Foo", "Bar")
	data = `<TTLV tag="0x420004" type="Integer" value="Foo Bar 0x00000004"/>`
	r = s.newReader(data)
	bm, err = r.Bitmask(0, 0x420004)
	s.NoError(err)
	s.Equal(int32(1|2|4), bm)
}
