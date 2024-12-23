package ttlv

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVersion(t *testing.T) {
	_, err := parseVersion("14")
	assert.Error(t, err)

	_, err = parseVersion("a.4")
	assert.Error(t, err)

	_, err = parseVersion("1.z")
	assert.Error(t, err)

	v, err := parseVersion("1.4")
	assert.NoError(t, err)
	assert.Equal(t, version{1, 4}, v)

	v, err = parseVersion("v1.4")
	assert.NoError(t, err)
	assert.Equal(t, version{1, 4}, v)

	assert.Equal(t, 1, v.Major())
	assert.Equal(t, 4, v.Minor())
	assert.Equal(t, "1.4", v.String())
}

func TestCompareVersion(t *testing.T) {
	v := version{2, 4}
	assert.Equal(t, 0, v.compare(v))
	assert.Equal(t, 1, v.compare(version{1, 4}))
	assert.Equal(t, 1, v.compare(version{2, 2}))
	assert.Equal(t, -1, v.compare(version{2, 5}))
	assert.Equal(t, -1, v.compare(version{3, 4}))
}

func TestParseVersionRange(t *testing.T) {
	vrange, err := parseVersionRange("1.4")
	assert.NoError(t, err)
	assert.Equal(t, versionRange{&version{1, 4}, &version{1, 4}}, vrange)
	assert.True(t, version{1, 4}.isIn(vrange))
	assert.False(t, version{1, 3}.isIn(vrange))
	assert.False(t, version{1, 5}.isIn(vrange))
	assert.Equal(t, "1.4..1.4", vrange.String())

	vrange, err = parseVersionRange("1.4..2.4")
	assert.NoError(t, err)
	assert.Equal(t, versionRange{&version{1, 4}, &version{2, 4}}, vrange)
	assert.True(t, version{1, 4}.isIn(vrange))
	assert.False(t, version{1, 3}.isIn(vrange))
	assert.True(t, version{1, 5}.isIn(vrange))
	assert.True(t, version{2, 3}.isIn(vrange))
	assert.False(t, version{2, 5}.isIn(vrange))
	assert.Equal(t, "1.4..2.4", vrange.String())

	vrange, err = parseVersionRange("1.4..")
	assert.NoError(t, err)
	assert.Equal(t, versionRange{&version{1, 4}, nil}, vrange)
	assert.True(t, version{1, 4}.isIn(vrange))
	assert.False(t, version{1, 3}.isIn(vrange))
	assert.True(t, version{1, 5}.isIn(vrange))
	assert.True(t, version{2, 3}.isIn(vrange))
	assert.True(t, version{2, 5}.isIn(vrange))
	assert.Equal(t, "1.4..", vrange.String())

	vrange, err = parseVersionRange("..2.4")
	assert.NoError(t, err)
	assert.Equal(t, versionRange{nil, &version{2, 4}}, vrange)
	assert.True(t, version{1, 4}.isIn(vrange))
	assert.True(t, version{1, 3}.isIn(vrange))
	assert.True(t, version{1, 5}.isIn(vrange))
	assert.True(t, version{2, 3}.isIn(vrange))
	assert.False(t, version{2, 5}.isIn(vrange))
	assert.Equal(t, "..2.4", vrange.String())

	vrange, err = parseVersionRange("..")
	assert.NoError(t, err)
	assert.Equal(t, versionRange{nil, nil}, vrange)
	assert.True(t, version{1, 4}.isIn(vrange))
	assert.True(t, version{1, 3}.isIn(vrange))
	assert.True(t, version{1, 5}.isIn(vrange))
	assert.True(t, version{2, 3}.isIn(vrange))
	assert.True(t, version{2, 5}.isIn(vrange))
	assert.Equal(t, "..", vrange.String())

	_, err = parseVersionRange("foo")
	assert.Error(t, err)
	_, err = parseVersionRange("2.4..1.4")
	assert.Error(t, err)
	_, err = parseVersionRange("..foo")
	assert.Error(t, err)
	_, err = parseVersionRange("foo..")
	assert.Error(t, err)
	_, err = parseVersionRange("foo..bar")
	assert.Error(t, err)
}

func TestExtension(t *testing.T) {
	ext := extension{}
	vrange, err := parseVersionRange("1.4..2.4")
	assert.NoError(t, err)
	assert.True(t, ext.versionIn(vrange))

	ext.setVersion(version{1, 2})
	assert.False(t, ext.versionIn(vrange))
	ext.setVersion(version{1, 6})
	assert.True(t, ext.versionIn(vrange))
}
