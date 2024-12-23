package kmip

import (
	"testing"

	"github.com/ovh/kmip-go/ttlv"

	"github.com/stretchr/testify/require"
)

func TestAttribute_EncodeDecode(t *testing.T) {
	attr := Attribute{
		AttributeName: AttributeNameName,
		AttributeValue: Name{
			NameType:  UninterpretedTextString,
			NameValue: "foobar",
		},
	}
	bytes := ttlv.MarshalTTLV(&attr)

	newAttr := Attribute{}
	err := ttlv.UnmarshalTTLV(bytes, &newAttr)
	require.NoError(t, err)
	require.EqualValues(t, attr, newAttr)

	index := int32(12)
	attr.AttributeIndex = &index
	bytes = ttlv.MarshalTTLV(&attr)

	newAttr = Attribute{}
	err = ttlv.UnmarshalTTLV(bytes, &newAttr)
	require.NoError(t, err)
	require.EqualValues(t, attr, newAttr)
}
