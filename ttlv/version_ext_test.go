package ttlv

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

type testVersion struct {
	VMajor int32 `ttlv:"0x7002"`
	VMinor int32 `ttlv:"0x7003"`
}

func (v testVersion) Major() int { return int(v.VMajor) }
func (v testVersion) Minor() int { return int(v.VMinor) }

// versionedPayload has 2 twin fields sharing the same tag, with different types and disjoint version ranges.
type versionedPayload struct {
	V1     *bool  `ttlv:"0x7010,version=..v1.4"`
	V2     uint32 `ttlv:"0x7010,omitempty,version=v2.0.."`
	OnlyV2 string `ttlv:"0x7011,omitempty,version=v2.0.."`
	Always int32  `ttlv:"0x7012"`
}

type versionedMsg struct {
	Version testVersion      `ttlv:"0x7001,set-version"`
	Payload versionedPayload `ttlv:"0x7004"`
}

func init() {
	RegisterTag("VersionedMsg", 0x7000, reflect.TypeFor[versionedMsg]())
}

func TestEncoderDecoder_VersionAccessors(t *testing.T) {
	enc := NewTTLVEncoder()
	require.Nil(t, enc.Version())
	require.True(t, enc.VersionIn(testVersion{2, 0}, nil))

	enc.SetVersion(testVersion{1, 4})
	require.Equal(t, 1, enc.Version().Major())
	require.Equal(t, 4, enc.Version().Minor())
	require.True(t, enc.VersionIn(nil, testVersion{1, 4}))
	require.False(t, enc.VersionIn(testVersion{2, 0}, nil))

	enc.SetVersion(nil)
	require.Nil(t, enc.Version())

	enc.SetVersion(testVersion{2, 0})
	enc.Clear()
	require.Nil(t, enc.Version())
}

func TestDecoder_VersionSetFromHeader(t *testing.T) {
	msg := versionedMsg{Version: testVersion{2, 0}, Payload: versionedPayload{V2: 3, Always: 1}}
	dec, err := NewTTLVDecoder(MarshalTTLV(&msg))
	require.NoError(t, err)
	require.Nil(t, dec.Version())
	var out versionedMsg
	require.NoError(t, dec.Any(&out))
	require.Equal(t, 2, dec.Version().Major())
}

func TestTwinFields(t *testing.T) {
	tru := true
	for _, tc := range []struct {
		name string
		msg  versionedMsg
	}{
		{"v1.4", versionedMsg{Version: testVersion{1, 4}, Payload: versionedPayload{V1: &tru, Always: 1}}},
		{"v2.0", versionedMsg{Version: testVersion{2, 0}, Payload: versionedPayload{V2: 3, OnlyV2: "foo", Always: 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out versionedMsg
			require.NoError(t, UnmarshalTTLV(MarshalTTLV(&tc.msg), &out))
			require.Equal(t, tc.msg, out)
		})
	}

	t.Run("out-of-range-fields-not-encoded", func(t *testing.T) {
		msg := versionedMsg{Version: testVersion{1, 4}, Payload: versionedPayload{V1: &tru, V2: 3, OnlyV2: "foo", Always: 1}}
		var out versionedMsg
		require.NoError(t, UnmarshalTTLV(MarshalTTLV(&msg), &out))
		require.Equal(t, versionedPayload{V1: &tru, Always: 1}, out.Payload)
	})
}

func TestDecoder_OutOfRangeFieldAccepted(t *testing.T) {
	// A 1.4 message holding a 2.0 only field
	enc := NewTTLVEncoder()
	enc.Struct(0x7000, func(e *Encoder) {
		e.TagAny(0x7001, testVersion{1, 4})
		e.Struct(0x7004, func(e *Encoder) {
			e.TextString(0x7011, "foo")
			e.Integer(0x7012, 1)
		})
	})

	var out versionedMsg
	require.NoError(t, UnmarshalTTLV(enc.Bytes(), &out))
	require.Equal(t, "foo", out.Payload.OnlyV2)
}
