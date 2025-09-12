package payloads

import (
	"testing"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"
	"github.com/stretchr/testify/require"
)

func TestObjectTypes(t *testing.T) {
	for ot := range objectTypes {
		t.Run(ttlv.EnumStr(ot), func(t *testing.T) {
			obj, err := newObjectForType(ot)
			require.NoError(t, err)
			require.Equal(t, ot, obj.ObjectType())
		})
	}
	t.Run("invalid", func(t *testing.T) {
		obj, err := newObjectForType(kmip.ObjectType(999))
		require.Error(t, err)
		require.Nil(t, obj)
	})
}

type CustomObject struct{}

func (o *CustomObject) ObjectType() kmip.ObjectType {
	return kmip.ObjectType(100)
}

func TestObject(t *testing.T) {
	RegisterObject(kmip.ObjectType(100), &CustomObject{})

	t.Run("custom", func(t *testing.T) {
		obj, err := newObjectForType(kmip.ObjectType(100))
		require.NoError(t, err)
		require.Equal(t, kmip.ObjectType(100), obj.ObjectType())
	})
}
