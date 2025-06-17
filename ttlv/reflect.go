package ttlv

import (
	"reflect"
	"strconv"
	"strings"
)

// fieldInfo holds metadata about a struct field for TTLV (Tag-Type-Length-Value) processing,
// including the tag name, omitempty flag, applicable version range, and whether the version is set.
type fieldInfo struct {
	tag        string
	omitempty  bool
	vrange     *versionRange
	setVersion bool
}

// getFieldInfo extracts the "ttlv" struct tag value from the provided StructField
// and parses it into a fieldInfo struct. It returns the parsed fieldInfo.
// If the "ttlv" tag is not present, an empty string is passed to parseFieldInfo.
func getFieldInfo(fldT reflect.StructField) fieldInfo {
	tagVal, _ := fldT.Tag.Lookup("ttlv")
	return parseFieldInfo(tagVal)
}

// parseFieldInfo parses a struct field tag string and returns a fieldInfo struct
// containing the parsed tag information. The tag string is expected to be a
// comma-separated list, where the first part is the main tag, and subsequent
// parts are options or key-value pairs (e.g., "omitempty", "set-version",
// "version=1-3"). Recognized options are "omitempty", "set-version", and
// "version=<range>". If an invalid sub-tag is encountered, the function panics.
func parseFieldInfo(s string) fieldInfo {
	parts := strings.Split(s, ",")
	ann := fieldInfo{tag: parts[0]}

	for _, part := range parts[1:] {
		if part == "omitempty" {
			ann.omitempty = true
			continue
		}
		if part == "set-version" {
			ann.setVersion = true
			continue
		}
		parts := strings.Split(part, "=")
		if len(parts) != 2 {
			panic("invalid sub-tag " + part)
		}
		if parts[0] == "version" {
			vrange, err := parseVersionRange(parts[1])
			if err != nil {
				panic("Invalid sub-tag version range: " + err.Error())
			}
			ann.vrange = &vrange
			continue
		}
		panic("invalid sub-tag " + part)
	}

	return ann
}

// getFieldTag returns the integer tag value associated with a struct field based on the provided tagVal string.
// If tagVal is empty, it attempts to resolve the tag by the field's name or type using getTagByName and getTagForType.
// If tagVal starts with "0x", it parses the hexadecimal value as the tag, ensuring it is strictly positive and fits in 3 bytes.
// Otherwise, it treats tagVal as a tag name and resolves it using getTagByName.
// Panics if tagVal is invalid or cannot be resolved.
func getFieldTag(fldT reflect.StructField, tagVal string) int {
	if tagVal == "" {
		// if fldT.Type.Implements(reflect.TypeFor[Encodable]()) {
		// 	// FIXME: How to pass a custom tag if any ?
		// 	fieldsEncode = append(fieldsEncode, func(e *Encoder, v reflect.Value) {
		// 		if encodable := v.Field(i).Interface(); encodable != nil {
		// 			encodable.(Encodable).EncodeTTLV(e)
		// 		}
		// 	})
		// 	continue
		// }
		if tg, err := getTagByName(fldT.Name); err == nil {
			// Check if we already know a tag with the same name as the field
			return tg
		} else if tg, err := getTagForType(fldT.Type); err == nil {
			// if not check if we know the default tag for this type (either explicitly registered, or fallback to type name)
			return tg
		}
		return 0
	}

	if strings.HasPrefix(tagVal, "0x") {
		n, err := strconv.ParseInt(tagVal[2:], 16, 0)
		if err != nil {
			panic(err)
		}
		if n <= 0 {
			panic("the tag must be strictly positive")
		}
		if n > 0xFFFFFF {
			panic("the tag cannot be bigger than 3 bytes")
		}
		return int(n)
	}

	numTag, err := getTagByName(tagVal)
	if err != nil {
		panic(err)
	}
	return numTag
}
