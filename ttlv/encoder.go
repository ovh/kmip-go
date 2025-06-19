package ttlv

import (
	"fmt"
	"math/big"
	"reflect"
	"sync"
	"time"
)

type writer interface {
	Bytes() []byte
	Clear()
	Integer(tag int, value int32)
	LongInteger(tag int, value int64)
	BigInteger(tag int, value *big.Int)
	Enum(realtag, tag int, value uint32)
	Bool(tag int, value bool)
	Struct(tag int, f func(writer))
	TextString(tag int, str string)
	ByteString(tag int, str []byte)
	DateTime(tag int, date time.Time)
	Interval(tag int, interval time.Duration)
	Bitmask(realtag, tag int, value int32)
}

// Encoder exposes methods to write TTLV tagged values to an internal buffer.
// It supports multiple formats like binary TTLV or xml TTLV.
type Encoder struct {
	*extension
	w writer
}

func newEncoder(w writer) Encoder {
	return Encoder{new(extension), w}
}

// NewTTLVEncoder create a new [Encoder] to encode values to
// the binary TTLV format.
func NewTTLVEncoder() Encoder {
	return newEncoder(newTTLVWriter())
}

// NewXMLEncoder create a new [Encoder] to encode values to
// the xml TTLV format.
func NewXMLEncoder() Encoder {
	return newEncoder(newXMLWriter())
}

// NewJSONEncoder create a new [Encoder] to encode values to
// the json TTLV format.
func NewJSONEncoder() Encoder {
	return newEncoder(newJSONWriter())
}

// NewTextEncoder create a new [Encoder] to print TTLV values into
// a textual and human-friendly form. Mainly useful for debugging.
func NewTextEncoder() Encoder {
	return newEncoder(newTextWriter())
}

// Bytes returns the internal byte array holding the encoded content.
func (enc *Encoder) Bytes() []byte {
	return enc.w.Bytes()
}

// Clear clears the internal buffer without deallocating it, making the encoder
// reusable for encoding another value.
func (enc *Encoder) Clear() {
	enc.extension.version = nil
	enc.w.Clear()
}

// Integer writes an integer to the internal buffer.
func (enc *Encoder) Integer(tag int, value int32) {
	enc.w.Integer(tag, value)
}

// LongInteger writes a long integer to the internal buffer.
func (enc *Encoder) LongInteger(tag int, value int64) {
	enc.w.LongInteger(tag, value)
}

// BigInteger writes a big integer to the internal buffer.
func (enc *Encoder) BigInteger(tag int, value *big.Int) {
	enc.w.BigInteger(tag, value)
}

// Enum writes an enum to the internal buffer.
// While `tag` is the tag to write with the value, which may differ from the enum's default tag,
// `realtag` can optionally be set to non-zero to identify the real default tag associated to the enum type.
// It's useful for serializing the enum value to its text representation.
func (enc *Encoder) Enum(realtag, tag int, value uint32) {
	enc.w.Enum(realtag, tag, value)
}

// Bool writes a boolean  to the internal buffer.
func (enc *Encoder) Bool(tag int, value bool) {
	enc.w.Bool(tag, value)
}

// Struct writes a structure to the internal buffer.
// It calls the provided callback `f` with an Encoder to use for writing
// struct's fields.
func (enc *Encoder) Struct(tag int, f func(*Encoder)) {
	enc.w.Struct(tag, func(w writer) {
		f(&Encoder{enc.extension, w})
	})
}

// TextString writes a string to the internal buffer.
func (enc *Encoder) TextString(tag int, str string) {
	enc.w.TextString(tag, str)
}

// ByteString writes a byte array to the internal buffer.
func (enc *Encoder) ByteString(tag int, str []byte) {
	enc.w.ByteString(tag, str)
}

// DateTime writes a date-time value to the internal buffer.
func (enc *Encoder) DateTime(tag int, date time.Time) {
	enc.w.DateTime(tag, date)
}

// Interval writes a duration to the internal buffer.
func (enc *Encoder) Interval(tag int, interval time.Duration) {
	enc.w.Interval(tag, interval)
}

// Bitmaks writes a bitmask value to the internal buffer.
// While `tag` is the tag to write with the value, which may differ from the bitmask's default tag,
// `realtag` can optionally be set to non-zero to identify the real default tag associated to the bitmask type.
// It's useful for serializing the bitmask value to its text representation.
func (enc *Encoder) Bitmask(realtag, tag int, value int32) {
	enc.w.Bitmask(realtag, tag, value)
}

// TagAny encodes a value of any supported type with the specified tag.
// It determines the type of the provided value and delegates encoding to the appropriate method.
// Supported types include byte, int8, int16, int32, int64, bool, string, []byte, time.Duration,
// time.Time, *big.Int, and types implementing the TagEncodable interface. If the value is nil,
// the method returns without encoding. For unsupported types, it falls back to reflection-based encoding.
//
// Parameters:
//   - tag: The tag to associate with the encoded value.
//   - value: The value to encode, which can be of any supported type.
func (enc *Encoder) TagAny(tag int, value any) {
	if value == nil {
		return
	}
	switch v := value.(type) {
	case byte:
		enc.Integer(tag, int32(v))
	case int8:
		enc.Integer(tag, int32(v))
	case int16:
		enc.Integer(tag, int32(v))
	case int32:
		enc.Integer(tag, v)
	case int64:
		enc.LongInteger(tag, v)
	case bool:
		enc.Bool(tag, v)
	case string:
		enc.TextString(tag, v)
	case []byte:
		enc.ByteString(tag, v)
	case time.Duration:
		enc.Interval(tag, v)
	case time.Time:
		enc.DateTime(tag, v)
	case *big.Int:
		enc.BigInteger(tag, v)
	case TagEncodable:
		v.TagEncodeTTLV(enc, tag)
	default:
		enc.encodeValue(tag, reflect.ValueOf(v))
	}
}

// Any encodes `value` and writes it to the internal buffer using value's type default tag.
// If the value implements the Encodable interface, its EncodeTTLV method is called directly.
// Otherwise, the encoder attempts to determine the appropriate tag for the value's type using reflection.
// If no tag can be found for the value, or if the value does not implement Encodable, the function panics.
// This method is the main entry point for encoding arbitrary Go values into TTLV format.
func (enc *Encoder) Any(value any) {
	if value == nil {
		return
	}
	switch v := value.(type) {
	case Encodable:
		v.EncodeTTLV(enc)
	default:
		tag, err := getTagForValue(reflect.ValueOf(value))
		if err != nil {
			panic(err)
		}
		enc.TagAny(tag, value)
	}
}

func (enc *Encoder) encodeValue(tag int, value reflect.Value) {
	f := encodeFuncFor(value.Type())
	f(enc, tag, value)
}

var encodeFuncsCache = new(sync.Map)

func encodeFuncFor(ty reflect.Type) func(*Encoder, int, reflect.Value) {
	if f, ok := encodeFuncsCache.Load(ty); ok {
		return f.(func(*Encoder, int, reflect.Value))
	}
	f := encodeFunc(ty)
	encodeFuncsCache.Store(ty, f)
	return f
}

func buildTagDecodableEncodeFunc() func(*Encoder, int, reflect.Value) {
	return func(e *Encoder, tag int, v reflect.Value) {
		if (v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer) && v.IsNil() {
			return
		}
		v.Interface().(TagEncodable).TagEncodeTTLV(e, tag)
	}
}

func buildPtrTagDecodableEncodeFunc(ty reflect.Type) func(*Encoder, int, reflect.Value) {
	return func(e *Encoder, tag int, v reflect.Value) {
		if v.Kind() == reflect.Interface && v.IsNil() {
			return
		}
		if !v.CanAddr() {
			panic(ty.Name() + " Implements ttlv.Encodable but its value cannot be addressed")
		}
		v.Addr().Interface().(TagEncodable).TagEncodeTTLV(e, tag)
	}
}

func buildEnumEncodeFunc(ty reflect.Type) func(*Encoder, int, reflect.Value) {
	enumtag, _ := getTagForType(ty)
	return func(e *Encoder, tag int, v reflect.Value) {
		//nolint:gosec // enums are uint32 already.
		e.Enum(enumtag, tag, uint32(v.Uint()))
	}
}

func buildBitmaskEncodeFunc(ty reflect.Type) func(*Encoder, int, reflect.Value) {
	bitmasktag, _ := getTagForType(ty)
	return func(e *Encoder, tag int, v reflect.Value) {
		//nolint:gosec // bitmasks are int32 already.
		e.Bitmask(bitmasktag, tag, int32(v.Int()))
	}
}

func buildDurationEncodeFunc() func(*Encoder, int, reflect.Value) {
	return func(e *Encoder, tag int, v reflect.Value) {
		e.Interval(tag, time.Duration(v.Int()))
	}
}

func buildTimeEncodeFunc() func(*Encoder, int, reflect.Value) {
	return func(e *Encoder, tag int, v reflect.Value) {
		// if v.CanAddr() {
		// 	e.DateTime(tag, *v.Addr().Interface().(*time.Time))
		// 	return
		// }
		e.DateTime(tag, v.Interface().(time.Time))
	}
}

func buildBigIntEncodeFunc() func(*Encoder, int, reflect.Value) {
	return func(e *Encoder, tag int, v reflect.Value) {
		// if v.CanAddr() {
		// 	e.BigInteger(tag, v.Addr().Interface().(*big.Int))
		// 	return
		// }
		n := v.Interface().(big.Int)
		e.BigInteger(tag, &n)
	}
}

func buildPointerEncodeFunc(ty reflect.Type) func(*Encoder, int, reflect.Value) {
	for ty.Kind() == reflect.Pointer {
		ty = ty.Elem()
	}
	f := encodeFuncFor(ty)
	return func(e *Encoder, tag int, v reflect.Value) {
		for v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return
			}
			v = v.Elem()
		}
		f(e, tag, v)
	}
}

func buildSliceEncodeFunc(ty reflect.Type) func(*Encoder, int, reflect.Value) {
	if ty.Elem().Kind() == reflect.Uint8 {
		return func(e *Encoder, tag int, v reflect.Value) {
			e.ByteString(tag, v.Bytes())
		}
	}
	// 	fallthrough
	// case reflect.Array:
	ff := encodeFuncFor(ty.Elem())
	return func(e *Encoder, tag int, v reflect.Value) {
		for i := range v.Len() {
			ff(e, tag, v.Index(i))
		}
	}
}

// encodeFunc returns an encoding function for the provided reflect.Type.
// The returned function takes an Encoder, a tag (int), and a reflect.Value, and encodes
// the value according to its type. The encoding logic is determined by the type's
// implementation of TagEncodable, pointer status, enum/bitmask status, or by its
// concrete kind (e.g., integer, string, struct, etc.).
// If the type is not supported, the function panics.
// This function is used internally to dynamically select the appropriate encoding
// strategy for different Go types when serializing to TTLV format.
func encodeFunc(ty reflect.Type) func(*Encoder, int, reflect.Value) {
	if ty.Implements(reflect.TypeFor[TagEncodable]()) {
		return buildTagDecodableEncodeFunc()
	} else if reflect.PointerTo(ty).Implements(reflect.TypeFor[TagEncodable]()) {
		return buildPtrTagDecodableEncodeFunc(ty)
	} else if isEnum(ty) {
		return buildEnumEncodeFunc(ty)
	} else if isBitmask(ty) {
		return buildBitmaskEncodeFunc(ty)
	}

	switch ty {
	case reflect.TypeFor[time.Duration]():
		return buildDurationEncodeFunc()
	case reflect.TypeFor[time.Time]():
		return buildTimeEncodeFunc()
	case reflect.TypeFor[big.Int]():
		return buildBigIntEncodeFunc()
	}
	switch ty.Kind() {
	case reflect.Pointer:
		return buildPointerEncodeFunc(ty)
	case reflect.Uint8, reflect.Uint16:
		return func(e *Encoder, tag int, v reflect.Value) {
			//nolint:gosec // cast is safe as we already checked the type.
			e.Integer(tag, int32(v.Uint()))
		}
	case reflect.Uint32:
		return func(e *Encoder, tag int, v reflect.Value) {
			//nolint:gosec // cast is safe as we already checked the type to be uint32.
			e.LongInteger(tag, int64(v.Uint()))
		}
	case reflect.Int8, reflect.Int16, reflect.Int32:
		return func(e *Encoder, tag int, v reflect.Value) {
			//nolint:gosec // cast is safe as we already checked the type.
			e.Integer(tag, int32(v.Int()))
		}
	case reflect.Int64:
		return func(e *Encoder, tag int, v reflect.Value) {
			e.LongInteger(tag, v.Int())
		}
	case reflect.Bool:
		return func(e *Encoder, tag int, v reflect.Value) {
			e.Bool(tag, v.Bool())
		}
	case reflect.String:
		return func(e *Encoder, tag int, v reflect.Value) {
			e.TextString(tag, v.String())
		}
	case reflect.Slice:
		return buildSliceEncodeFunc(ty)
	case reflect.Struct:
		return buildStructEncodeFunc(ty)
	case reflect.Interface:
		return func(e *Encoder, tag int, v reflect.Value) {
			if v.IsNil() {
				return
			}
			e.encodeValue(tag, v.Elem())
		}
	default:
		panic("Unsupported type: " + ty.String())
	}
}

func applyOmitEmptyEncode(ffunc func(*Encoder, int, reflect.Value)) func(*Encoder, int, reflect.Value) {
	return func(e *Encoder, i int, v reflect.Value) {
		if v.IsZero() {
			return
		}
		ffunc(e, i, v)
	}
}

func applyVersionRangeEncode(vrange versionRange, ffunc func(*Encoder, int, reflect.Value)) func(*Encoder, int, reflect.Value) {
	return func(e *Encoder, tag int, v reflect.Value) {
		if !e.versionIn(vrange) {
			return
		}
		ffunc(e, tag, v)
	}
}

// applySetVersionEncode returns a wrapper function that first sets the version on the Encoder
// using the provided struct field's value, and then calls the given encoding function.
// It panics if the struct field's type does not implement the Version interface.
//
// Parameters:
//   - fldT: The struct field to check for Version interface implementation.
//   - ffunc: The encoding function to wrap.
//
// Returns:
//   - A function that takes an Encoder, an index, and a reflect.Value, sets the version on the Encoder,
//     and then calls the provided encoding function.
func applySetVersionEncode(fldT reflect.StructField, ffunc func(*Encoder, int, reflect.Value)) func(*Encoder, int, reflect.Value) {
	// Check that field type implements Version interface (major / minor)
	if !fldT.Type.Implements(reflect.TypeFor[Version]()) {
		panic(fmt.Sprintf("Type %s does not implement ttlv.Version", fldT.Type.String()))
	}
	return func(e *Encoder, i int, v reflect.Value) {
		e.setVersion(v.Interface().(Version))
		ffunc(e, i, v)
	}
}

// buildStructEncodeFunc generates an encoding function for a given struct type.
// The returned function encodes the struct's exported fields using the provided Encoder,
// applying field tags, omitempty, version range, and set version logic as specified by field metadata.
// Fields with a tag of "-" or that are unexported are skipped. If a field is an interface and has no tag,
// it attempts to determine the tag dynamically based on the concrete type at runtime.
// Panics if a required tag is missing for a non-interface field.
// The generated function encodes the struct as a tagged structure using the Encoder.
func buildStructEncodeFunc(ty reflect.Type) func(*Encoder, int, reflect.Value) {
	fieldsEncode := []func(e *Encoder, v reflect.Value){}

	for i := range ty.NumField() {
		fldT := ty.Field(i)
		if !fldT.IsExported() {
			continue
		}
		info := getFieldInfo(fldT)
		if info.tag == "-" {
			continue
		}

		numTag := getFieldTag(fldT, info.tag)

		if numTag == 0 {
			if fldT.Type.Kind() == reflect.Interface {
				fieldsEncode = append(fieldsEncode, func(e *Encoder, value reflect.Value) {
					value = value.Field(i)
					if value.IsNil() {
						return
					}
					tag, err := getTagForType(value.Elem().Type())
					if err != nil {
						panic(err)
					}
					e.encodeValue(tag, value.Elem())
				})
				continue
			}
			panic(fmt.Sprintf("Missing tag for field %s of type %s", fldT.Name, ty.Name()))
		}

		ffunc := encodeFuncFor(fldT.Type)
		if info.omitempty {
			ffunc = applyOmitEmptyEncode(ffunc)
		}
		if info.vrange != nil {
			ffunc = applyVersionRangeEncode(*info.vrange, ffunc)
		}
		if info.setVersion {
			ffunc = applySetVersionEncode(fldT, ffunc)
		}
		fieldsEncode = append(fieldsEncode, func(e *Encoder, v reflect.Value) {
			ffunc(e, numTag, v.Field(i))
		})
	}
	return func(e *Encoder, tag int, v reflect.Value) {
		e.Struct(tag, func(e *Encoder) {
			for _, fe := range fieldsEncode {
				fe(e, v)
			}
		})
	}
}
