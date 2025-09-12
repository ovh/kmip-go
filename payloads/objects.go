package payloads

import (
	"fmt"
	"reflect"

	"github.com/ovh/kmip-go"
)

var objectTypes = map[kmip.ObjectType]reflect.Type{
	kmip.ObjectTypeSecretData:   reflect.TypeFor[kmip.SecretData](),
	kmip.ObjectTypeCertificate:  reflect.TypeFor[kmip.Certificate](),
	kmip.ObjectTypeSymmetricKey: reflect.TypeFor[kmip.SymmetricKey](),
	kmip.ObjectTypePublicKey:    reflect.TypeFor[kmip.PublicKey](),
	kmip.ObjectTypePrivateKey:   reflect.TypeFor[kmip.PrivateKey](),
	kmip.ObjectTypeSplitKey:     reflect.TypeFor[kmip.SplitKey](),
	kmip.ObjectTypeOpaqueObject: reflect.TypeFor[kmip.OpaqueObject](),
	//nolint:staticcheck // for backward compatibility
	kmip.ObjectTypeTemplate: reflect.TypeFor[kmip.Template](),
	kmip.ObjectTypePGPKey:   reflect.TypeFor[kmip.PGPKey](),
}

// RegisterObjectType allows to register a new KMIP object type with its corresponding struct.
// This is useful to extend the library with custom object types or to add support for new KMIP object types.
// Parameters:
//   - objType: The KMIP object type to register.
//   - obj: An instance of the struct that implements the kmip.Object interface for the given object type.
func RegisterObjectType(objType kmip.ObjectType, obj kmip.Object) {
	objectTypes[objType] = reflect.TypeOf(obj).Elem()
}

func newObjectForType(objType kmip.ObjectType) (kmip.Object, error) {
	ty, ok := objectTypes[objType]
	if !ok {
		return nil, fmt.Errorf("Invalid object type %X", objType)
	}
	return reflect.New(ty).Interface().(kmip.Object), nil
}
