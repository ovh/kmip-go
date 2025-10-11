package ttlv

import (
	"fmt"
	"iter"
	"reflect"
)

var (
	tagByName = map[string]int{}
	tagByType = map[reflect.Type]int{}
	tagNames  = map[int]string{}

	enums       = map[reflect.Type]int{}
	enumNames   = map[int]map[uint32]string{}
	enumsByName = map[int]map[string]uint32{}

	bitmasks      = map[reflect.Type]int{}
	bitmaskNames  = map[int][]string{}
	bitmaskByName = map[int]map[string]int32{}
)

func getTagByName(name string) (int, error) {
	if tag, ok := tagByName[name]; ok {
		return tag, nil
	}
	return 0, fmt.Errorf("Unknown tag %q", name)
}

func getTagName(tag int) string {
	n := tagNames[tag]
	return n
}

// TagString returns the string representation of a given tag.
// If the tag exists in the tagNames map, its corresponding name is returned.
// Otherwise, the tag is formatted as a zero-padded 6-digit hexadecimal string prefixed with "0x".
func TagString(tag int) string {
	if name, ok := tagNames[tag]; ok {
		return name
	}
	//nolint:gosec // this cast is safe as we are appending a hex value
	return fmt.Sprintf("0x%06X", uint(tag))
}

func getTagForType(ty reflect.Type) (int, error) {
	for ty.Kind() == reflect.Pointer {
		ty = ty.Elem()
	}
	if ty.Kind() == reflect.Array || ty.Kind() == reflect.Slice {
		return getTagForType(ty.Elem())
	}
	if tag, ok := tagByType[ty]; ok {
		return tag, nil
	}
	if tag, ok := tagByName[ty.Name()]; ok {
		return tag, nil
	}
	return 0, fmt.Errorf("No default tag found for type %q", ty.Name())
}

// getTagForValue attempts to retrieve a tag integer associated with the type of the provided reflect.Value.
// It first tries to get the tag for the value's type directly. If that fails and the value is a pointer,
// it dereferences the pointer(s) until it reaches a non-pointer type. If the resulting value is an interface,
// it attempts to get the tag for the underlying concrete type. Returns the tag and any error encountered.
func getTagForValue(val reflect.Value) (int, error) {
	tag, err := getTagForType(val.Type())
	if err != nil {
		for val.Kind() == reflect.Pointer {
			val = val.Elem()
		}
		if val.Kind() == reflect.Interface {
			tag, err = getTagForType(val.Elem().Type())
		}
	}
	return tag, err
}

// RegisterTag registers a new named tag and save the mapping between name and interger value for later usage
// by encoder and decoders.
// An optional list of types can be provided to also register a mapping between the types and the default tag used
// for serializing/deserializing them.
func RegisterTag(name string, value int, ty ...reflect.Type) {
	tagByName[name] = value
	tagNames[value] = name
	for _, t := range ty {
		tagByType[t] = value
	}
}

// RegisterEnum registers an enum tag with its tag and all its string values.
func RegisterEnum[T ~uint32](tag int, names map[T]string) {
	//TODO: Merge new registration with previous registrations. Panic on overwrite
	ty := reflect.TypeFor[T]()
	enums[ty] = tag
	tagByType[ty] = tag

	if names == nil {
		return
	}

	if enumNames[tag] == nil {
		enumNames[tag] = make(map[uint32]string, len(names))
	}
	if enumsByName[tag] == nil {
		enumsByName[tag] = make(map[string]uint32, len(names))
	}
	for enum, name := range names {
		enumNames[tag][uint32(enum)] = name
		enumsByName[tag][name] = uint32(enum)
	}
}

// EnumValues returns an iterator over registered enum values and names
// for the given type T. If T is not a known enum, then the iterator will
// yield an empty result set.
func EnumValues[T ~uint32]() iter.Seq2[T, string] {
	tag, ok := enums[reflect.TypeFor[T]()]
	if !ok {
		return func(yield func(T, string) bool) {}
	}
	return func(yield func(T, string) bool) {
		for id, name := range enumNames[tag] {
			if !yield(T(id), name) {
				return
			}
		}
	}
}

func EnumValuesByName(name string) iter.Seq2[uint32, string] {
	tag, ok := tagByName[name]
	if !ok {
		return func(yield func(uint32, string) bool) {}
	}
	return EnumValuesByTag(tag)
}

// EnumValuesByTag returns an iterator over registered enum values and names
// for the given tag. If tag is not a known enum, then the iterator will yield
// an empty result set.
func EnumValuesByTag(tag int) iter.Seq2[uint32, string] {
	return func(yield func(uint32, string) bool) {
		for id, name := range enumNames[tag] {
			if !yield(id, name) {
				return
			}
		}
	}
}

func isEnum(ty reflect.Type) bool {
	_, ok := enums[ty]
	return ok
}

// EnumName returns the string representation of an enum value. If it's known,
// the string is the normalized name, otherwise it's an empty string.
func EnumName(tag int, value uint32) string {
	if reg := enumNames[tag]; reg != nil {
		n := reg[value]
		return n
	}
	return ""
}

// EnumStr returns the string representation of an enum. If it's known,
// the string is the normalized name, otherwise it's the 0x prefixed hex value.
func EnumStr[T ~uint32](value T) string {
	if tag := enums[reflect.TypeFor[T]()]; tag != 0 {
		name := EnumName(tag, uint32(value))
		return name
	}
	return fmt.Sprintf("0x%08X", uint32(value))
}

// EnumByName returns enum of a normalized name.
func EnumByName(tag int, name string) (uint32, error) {
	if reg := enumsByName[tag]; reg != nil {
		n, ok := reg[name]
		if ok {
			return n, nil
		}
	}
	return 0, fmt.Errorf("Unknown enum value %q", name)
}

// RegisterBitmask registers a bitmask types with it's tag and string values.
func RegisterBitmask[T ~int32](tag int, names ...string) {
	ty := reflect.TypeFor[T]()
	tagByType[ty] = tag
	bitmasks[reflect.TypeFor[T]()] = tag
	bitmaskNames[tag] = names
	bitmaskByName[tag] = make(map[string]int32, len(names))
	for i, name := range names {
		bitmaskByName[tag][name] = 1 << i
	}
}

// BitmaskStr returns the string representation of a bitmask value, consisting of
// a concatenation of all the flags values separated by `sep`. If it's known,
// the flag string value is the normalized name, otherwise it's the 0x prefixed hex value.
func BitmaskStr[T ~int32](value T, sep string) string {
	return bitmaskString(bitmasks[reflect.TypeFor[T]()], value, sep)
}

// bitmaskString returns a string representation of a bitmask value of type T,
// formatted with the specified separator. The tag parameter is used to identify
// the bitmask, and value is the bitmask value to be converted. The sep parameter
// specifies the separator to use between bitmask components in the resulting string.
// T must be a type whose underlying type is int32.
func bitmaskString[T ~int32](tag int, value T, sep string) string {
	return string(AppendBitmaskString([]byte{}, tag, value, sep))
}

// AppendBitmaskString appends a string representation of a bitmask value to the given byte slice.
// For each set bit in the value, it looks up a human-readable name from the bitmaskNames map using the provided tag.
// If a name is not found for a set bit, it appends the bit's value as a hexadecimal string prefixed with "0x".
// Multiple set bits are separated by the specified separator string.
// The function returns the resulting byte slice with the appended string representation.
//
// Type Parameters:
//   - T: an integer type based on int32.
//
// Parameters:
//   - dst: the destination byte slice to append to.
//   - tag: an integer key used to look up bit names in the bitmaskNames map.
//   - value: the bitmask value to convert to a string representation.
//   - sep: the separator string to use between multiple set bits.
//
// Returns:
//   - []byte: the resulting byte slice with the appended string representation.
func AppendBitmaskString[T ~int32](dst []byte, tag int, value T, sep string) []byte {
	if value == 0 {
		return dst
	}
	bsep := []byte(sep)
	mapper := bitmaskNames[tag]
	wrote := false
	for i := range 32 {
		v := int32(value & (1 << i))
		if v == 0 {
			continue
		}
		if i < len(mapper) && mapper[i] == "" {
			continue
		}
		if wrote {
			dst = append(dst, bsep...)
		}
		wrote = true
		if i < len(mapper) {
			dst = append(dst, []byte(mapper[i])...)
			continue
		}
		// Handle case where it's not registered
		// by writing 0x prefixed hex value
		//nolint:gosec // this cast is safe as we are appending a hex value
		dst = fmt.Appendf(dst, "0x%08X", uint32(v))
	}
	return dst
}

// BitmaskByStr returns bitmask of a normalized name.
func BitmaskByStr(tag int, name string) (int32, error) {
	if reg := bitmaskByName[tag]; reg != nil {
		n, ok := reg[name]
		if ok {
			return n, nil
		}
	}
	return 0, fmt.Errorf("Unknown bitmask value %q", name)
}

func isBitmask(ty reflect.Type) bool {
	_, ok := bitmasks[ty]
	return ok
}
