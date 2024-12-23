package ttlv

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDecodeValue(t *testing.T) {
	for _, tc := range []struct {
		name      string
		enc       func() Encoder
		marshal   func(any) []byte
		unmarshal func([]byte, any) error
	}{
		{"TTLV", NewTTLVEncoder, MarshalTTLV, UnmarshalTTLV},
		{"XML", NewXMLEncoder, MarshalXML, UnmarshalXML},
	} {

		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().Round(time.Second)
			enc := tc.enc()
			enc.Struct(12, func(e *Encoder) {
				enc.Integer(1, 1)
				enc.BigInteger(2, big.NewInt(2))
				enc.LongInteger(3, 3)
				enc.Bool(4, true)
				enc.ByteString(5, []byte{5})
				enc.TextString(6, "6")
				enc.DateTime(7, now)
				enc.Interval(8, 8*time.Second)
				enc.Enum(0, 9, 9)
			})

			bytes := enc.Bytes()

			val := Value{}
			err := tc.unmarshal(bytes, &val)
			assert.NoError(t, err)
			marsh := tc.marshal(val)
			assert.Equal(t, bytes, marsh)
		})
	}
}
