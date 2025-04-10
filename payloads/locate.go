package payloads

import "github.com/ovh/kmip-go"

func init() {
	kmip.RegisterOperationPayload[LocateRequestPayload, LocateResponsePayload](kmip.OperationLocate)
}

// This operation requests that the server search for one or more Managed Objects, depending on the attributes specified in the request.
// All attributes are allowed to be used. However, Attribute Index values SHOULD NOT be specified in the request.
// Attribute Index values that are provided SHALL be ignored by the server. The request MAY contain a Maximum Items field,
// which specifies the maximum number of objects to be returned. If the Maximum Items field is omitted, then the server MAY return all objects matched,
// or MAY impose an internal maximum limit due to resource limitations.
//
// The request MAY contain an Offset Items field, which specifies the number of objects to skip that satisfy the identification criteria specified in the request.
// An Offset Items field of 0 is the same as omitting the Offset Items field. If both Offset Items and Maximum Items are specified in the request,
// the server skips Offset Items objects and returns up to Maximum Items objects.
//
// If more than one object satisfies the identification criteria specified in the request, then the response MAY contain Unique Identifiers
// for multiple Managed Objects. Returned objects SHALL match all of the attributes in the request. If no objects match, then an empty response payload is returned.
// If no attribute is specified in the request, any object SHALL be deemed to match the Locate request. The response MAY include Located Items
// which is the count of all objects that satisfy the identification criteria.
//
// The server returns a list of Unique Identifiers of the found objects, which then MAY be retrieved using the Get operation. If the objects are archived,
// then the Recover and Get operations are REQUIRED to be used to obtain those objects.
// If a single Unique Identifier is returned to the client, then the server SHALL copy the Unique Identifier returned by this operation into the ID Placeholder variable.
//
// If the Locate operation matches more than one object, and the Maximum Items value is omitted in the request, or is set to a value larger than one,
//
// then the server SHALL empty the ID Placeholder, causing any subsequent operations that are batched with the Locate, and which do not specify a Unique Identifier explicitly,
// to fail. This ensures that these batched operations SHALL proceed only if a single object is returned by Locate.
//
// Wild-cards or regular expressions (defined, e.g., in [ISO/IEC 9945-2]) MAY be supported by specific key management system implementations for matching attribute fields
// when the field type is a Text String or a Byte String.
//
// The Date attributes in the Locate request (e.g., Initial Date, Activation Date, etc.) are used to specify a time or a time range for the search.
// If a single instance of a given Date attribute is used in the request (e.g., the Activation Date), then objects with the same Date attribute are
// considered to be matching candidate objects. If two instances of the same Date attribute are used (i.e., with two different values specifying a range),
// then objects for which the Date attribute is inside or at a limit of the range are considered to be matching candidate objects.
// If a Date attribute is set to its largest possible value, then it is equivalent to an undefined attribute. The KMIP Usage Guide [KMIP-UG] provides examples.
//
// When the Cryptographic Usage Mask attribute is specified in the request, candidate objects are compared against this field via an operation that consists of
// a logical AND of the requested mask with the mask in the candidate object, and then a comparison of the resulting value with the requested mask.
// For example, if the request contains a mask value of 10001100010000, and a candidate object mask contains 10000100010000, then the logical AND of
// the two masks is 10000100010000, which is compared against the mask value in the request (10001100010000) and the match fails.
// This means that a matching candidate object has all of the bits set in its mask that are set in the requested mask, but MAY have additional bits set.
//
// When the Usage Limits attribute is specified in the request, matching candidate objects SHALL have a Usage Limits Count and Usage Limits Total equal
// to or larger than the values specified in the request.
//
// When an attribute that is defined as a structure is specified, all of the structure fields are not REQUIRED to be specified.
// For instance, for the Link attribute, if the Linked Object Identifier value is specified without the Link Type value, then matching candidate objects
// have the Linked Object Identifier as specified, irrespective of their Link Type.
//
// When the Object Group attribute and the Object Group Member flag are specified in the request, and the value specified for Object Group Member
// is ‘Group Member Fresh’, matching candidate objects SHALL be fresh objects (see 3.34) from the object group. If there are no more fresh objects in the group,
// the server MAY choose to generate a new object on-the-fly, based on server policy. If the value specified for Object Group Member is ‘Group Member Default’,
// the server locates the default object as defined by server policy.
//
// The Storage Status Mask field (see Section 9.1.3.3.2) is used to indicate whether only on-line objects, only archived objects, or both on-line and archived
// objects are to be searched. Note that the server MAY store attributes of archived objects in order to expedite Locate operations that search through archived objects.
type LocateRequestPayload struct {
	// An Integer object that indicates the maximum number of object identifiers the server MAY return.
	MaximumItems int32 `ttlv:",omitempty"`
	// An Integer object that indicates the number of object identifiers to skip that satisfy the identification criteria specified in the request.
	OffsetItems int32 `ttlv:",omitempty,version=1.3.."`
	// An Integer object (used as a bit mask) that indicates whether only on-line objects, only archived objects,
	// or both on-line and archived objects are to be searched. If omitted, then on-line only is assumed.
	StorageStatusMask kmip.StorageStatusMask `ttlv:",omitempty"`
	// An Enumeration object that indicates the object group member type.
	ObjectGroupMember kmip.ObjectGroupMember `ttlv:",omitempty,version=1.1.."`
	// Specifies an attribute and its value(s) that are REQUIRED to match those in a candidate object (according to the matching rules defined above).
	Attribute []kmip.Attribute
}

func (a *LocateRequestPayload) Operation() kmip.Operation {
	return kmip.OperationLocate
}

type LocateResponsePayload struct {
	// An Integer object that indicates the number of object identifiers that satisfy the identification criteria specified in the request.
	// A server MAY elect to omit this value from the Response if it is unable or unwilling to determine the total count of matched items.
	//
	// A server MAY elect to return the Located Items value even if Offset Items is not present in the Request.
	LocatedItems *int32 `ttlv:",version=1.3.."`
	// The Unique Identifier of the located objects.
	UniqueIdentifier []string
}

func (a *LocateResponsePayload) Operation() kmip.Operation {
	return kmip.OperationLocate
}
