package ttlv

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

func expectedHex(in string) string {
	return strings.ToUpper(strings.NewReplacer(" ", "", "|", "").Replace(in))
}

func decodeHex(in string) *ttlvReader {
	bytes, err := hex.DecodeString(strings.NewReplacer(" ", "", "|", "").Replace(in))
	if err != nil {
		panic(err)
	}
	reader, err := newTTLVReader(bytes)
	if err != nil {
		panic(err)
	}
	return reader
}

type TtlvEncodingSuite struct {
	suite.Suite
	enc *ttlvWriter
}

func TestTtlvEncoding(t *testing.T) {
	suite.Run(t, new(TtlvEncodingSuite))
}

func (s *TtlvEncodingSuite) SetupTest() {
	s.enc = newTTLVWriter()
}

func (s *TtlvEncodingSuite) TestEncodeInteger() {
	s.enc.Integer(0x420020, 8)
	expected := expectedHex("42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00")
	s.Equal(expected, strings.ToUpper(hex.EncodeToString(s.enc.Bytes())))
}

func (s *TtlvEncodingSuite) TestEncodeLongInteger() {
	s.enc.LongInteger(0x420020, 123456789000000000)
	expected := expectedHex("42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00")
	s.Equal(expected, strings.ToUpper(hex.EncodeToString(s.enc.Bytes())))
}

func (s *TtlvEncodingSuite) TestEncodeBigInteger() {
	s.Run("positive", func() {
		s.enc.Clear()
		b := big.NewInt(0)
		b.SetString("1234567890000000000000000000", 10)
		s.enc.BigInteger(0x420020, b)
		expected := expectedHex("42 00 20 | 04 | 00 00 00 10 | 00 00 00 00 03 FD 35 EB 6B C2 DF 46 18 08 00 00")
		s.Equal(expected, strings.ToUpper(hex.EncodeToString(s.enc.Bytes())))
	})
	s.Run("zero", func() {
		s.enc.Clear()
		b := big.NewInt(0)
		s.enc.BigInteger(0x420020, b)
		expected := expectedHex("42 00 20 | 04 | 00 00 00 08 | 00 00 00 00 00 00 00 00")
		s.Equal(expected, strings.ToUpper(hex.EncodeToString(s.enc.Bytes())))
	})
	s.Run("negative", func() {
		s.enc.Clear()
		b := big.NewInt(0)
		b.SetString("-1234567890000000000000000000", 10)
		s.enc.BigInteger(0x420020, b)
		expected := expectedHex("42 00 20 | 04 | 00 00 00 10 | FF FF FF FF FC 02 CA 14 94 3D 20 B9 E7 F8 00 00")
		s.Equal(expected, strings.ToUpper(hex.EncodeToString(s.enc.Bytes())))
	})
}

func (s *TtlvEncodingSuite) TestEncodeEnum() {
	s.enc.Enum(0, 0x420020, 255)
	expected := expectedHex("42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00")
	s.Equal(expected, strings.ToUpper(hex.EncodeToString(s.enc.Bytes())))
}

func (s *TtlvEncodingSuite) TestEncodeBoolean() {
	s.Run("true", func() {
		s.enc.Clear()
		s.enc.Bool(0x420020, true)
		expected := expectedHex("42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 01")
		s.Equal(expected, strings.ToUpper(hex.EncodeToString(s.enc.Bytes())))
	})
	s.Run("false", func() {
		s.enc.Clear()
		s.enc.Bool(0x420020, false)
		expected := expectedHex("42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 00")
		s.Equal(expected, strings.ToUpper(hex.EncodeToString(s.enc.Bytes())))
	})
}

func (s *TtlvEncodingSuite) TestEncodeTextString() {
	s.enc.TextString(0x420020, "Hello World")
	expected := expectedHex("42 00 20 | 07 | 00 00 00 0B | 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 00 00 00")
	s.Equal(expected, strings.ToUpper(hex.EncodeToString(s.enc.Bytes())))
}

func (s *TtlvEncodingSuite) TestEncodeByteString() {
	s.enc.ByteString(0x420020, []byte{0x01, 0x02, 0x03})
	expected := expectedHex("42 00 20 | 08 | 00 00 00 03 | 01 02 03 00 00 00 00 00")
	s.Equal(expected, strings.ToUpper(hex.EncodeToString(s.enc.Bytes())))
}

func (s *TtlvEncodingSuite) TestEncodeDateTime() {
	dt := time.Date(2008, time.March, 14, 11, 56, 40, 0, time.UTC)
	s.enc.DateTime(0x420020, dt)
	expected := expectedHex("42 00 20 | 09 | 00 00 00 08 | 00 00 00 00 47 DA 67 F8")
	s.Equal(expected, strings.ToUpper(hex.EncodeToString(s.enc.Bytes())))
}

func (s *TtlvEncodingSuite) TestEncodeInterval() {
	s.enc.Interval(0x420020, 10*24*time.Hour)
	expected := expectedHex("42 00 20 | 0A | 00 00 00 04 | 00 0D 2F 00 00 00 00 00")
	s.Equal(expected, strings.ToUpper(hex.EncodeToString(s.enc.Bytes())))
}

func (s *TtlvEncodingSuite) TestEncodeStruct() {
	s.enc.Struct(0x420020, func(e writer) {
		e.Enum(0, 0x420004, 254)
		e.Integer(0x420005, 255)
	})
	expected := expectedHex("42 00 20 | 01 | 00 00 00 20 | 42 00 04 | 05 | 00 00 00 04 | 00 00 00 FE 00 00 00 00 | 42 00 05 | 02 | 00 00 00 04 | 00 00 00 FF 00 00 00 00")
	s.Equal(expected, strings.ToUpper(hex.EncodeToString(s.enc.Bytes())))
}

type TtlvDecodingSuite struct {
	suite.Suite
}

func TestTtlvDecoding(t *testing.T) {
	suite.Run(t, new(TtlvDecodingSuite))
}

func (s *TtlvDecodingSuite) TestDecodeInteger() {
	dec := decodeHex("42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00")
	v, err := dec.Integer(0x420020)
	s.NoError(err)
	s.Equal(int32(8), v)
}

func (s *TtlvDecodingSuite) TestDecodeLongInteger() {
	dec := decodeHex("42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00")
	v, err := dec.LongInteger(0x420020)
	s.NoError(err)
	s.Equal(int64(123456789000000000), v)
}

func (s *TtlvDecodingSuite) TestDecodeBigInteger() {
	s.Run("positive", func() {
		b := big.NewInt(0)
		b.SetString("1234567890000000000000000000", 10)

		dec := decodeHex("42 00 20 | 04 | 00 00 00 10 | 00 00 00 00 03 FD 35 EB 6B C2 DF 46 18 08 00 00")
		v, err := dec.BigInteger(0x420020)
		s.NoError(err)
		s.Equal(b, v)
	})
	s.Run("zero", func() {
		dec := decodeHex("42 00 20 | 04 | 00 00 00 08 | 00 00 00 00 00 00 00 00")
		v, err := dec.BigInteger(0x420020)
		s.NoError(err)
		s.Equal("0", v.String())
	})
	s.Run("negative", func() {
		b := big.NewInt(0)
		b.SetString("-1234567890000000000000000000", 10)

		dec := decodeHex("42 00 20 | 04 | 00 00 00 10 | FF FF FF FF FC 02 CA 14 94 3D 20 B9 E7 F8 00 00")
		v, err := dec.BigInteger(0x420020)
		s.NoError(err)
		s.Equal(b, v)
	})
}

func (s *TtlvDecodingSuite) TestDecodeEnum() {
	dec := decodeHex("42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00")
	v, err := dec.Enum(0, 0x420020)
	s.NoError(err)
	s.Equal(uint32(255), v)
}

func (s *TtlvDecodingSuite) TestDecodeBoolean() {
	s.Run("true", func() {
		dec := decodeHex("42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 01")
		v, err := dec.Bool(0x420020)
		s.NoError(err)
		s.Equal(true, v)
	})
	s.Run("false", func() {
		dec := decodeHex("42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 00")
		v, err := dec.Bool(0x420020)
		s.NoError(err)
		s.Equal(false, v)
	})
}

func (s *TtlvDecodingSuite) TestDecodeTextString() {
	dec := decodeHex("42 00 20 | 07 | 00 00 00 0B | 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 00 00 00")
	v, err := dec.TextString(0x420020)
	s.NoError(err)
	s.Equal("Hello World", v)
}

func (s *TtlvDecodingSuite) TestDecodeByteString() {
	dec := decodeHex("42 00 20 | 08 | 00 00 00 03 | 01 02 03 00 00 00 00 00")
	v, err := dec.ByteString(0x420020)
	s.NoError(err)
	s.Equal([]byte{0x01, 0x02, 0x03}, v)
}

func (s *TtlvDecodingSuite) TestDecodeDateTime() {
	dt := time.Date(2008, time.March, 14, 11, 56, 40, 0, time.UTC)
	dec := decodeHex("42 00 20 | 09 | 00 00 00 08 | 00 00 00 00 47 DA 67 F8")
	v, err := dec.DateTime(0x420020)
	s.NoError(err)
	s.Equal(dt, v.UTC())
}

func (s *TtlvDecodingSuite) TestDecodeInterval() {
	dec := decodeHex("42 00 20 | 0A | 00 00 00 04 | 00 0D 2F 00 00 00 00 00")
	v, err := dec.Interval(0x420020)
	s.NoError(err)
	s.Equal(10*24*time.Hour, v)
}

func (s *TtlvDecodingSuite) TestDecodeStruct() {
	dec := decodeHex("42 00 20 | 01 | 00 00 00 20 | 42 00 04 | 05 | 00 00 00 04 | 00 00 00 FE 00 00 00 00 | 42 00 05 | 02 | 00 00 00 04 | 00 00 00 FF 00 00 00 00")
	var a uint32
	var b int32
	err := dec.Struct(0x420020, func(r reader) error {
		var err error
		a, err = r.Enum(0, 0x420004)
		if err != nil {
			return err
		}
		b, err = r.Integer(0x420005)
		return err
	})
	s.NoError(err)
	s.Equal(uint32(254), a)
	s.Equal(int32(255), b)
}
