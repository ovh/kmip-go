package ttlv

import (
	"fmt"
	"reflect"
)

func ExampleEnumValuesByTag() {
	type EN uint32
	RegisterEnum(0x420020, map[EN]string{
		0x000000FF: "FooBar",
	})

	for en, value := range EnumValuesByTag(0x420020) {
		fmt.Println(en, value)
	}

	// Output:
	// 255 FooBar
}

func ExampleEnumValuesByName() {
	type EN uint32
	RegisterEnum(0x420020, map[EN]string{
		0x000000FF: "FooBar",
	})

	RegisterTag("EN", 0x420020, reflect.TypeFor[EN]())

	for en, value := range EnumValuesByName("EN") {
		fmt.Println(en, value)
	}

	// Output:
	// 255 FooBar
}
