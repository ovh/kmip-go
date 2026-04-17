package ttlv

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nopCloser wraps an io.ReadWriter to satisfy io.ReadWriteCloser.
type nopCloser struct {
	io.ReadWriter
}

func (nopCloser) Close() error { return nil }

func TestStream_Recv_MaxMessageSize(t *testing.T) {
	// Build a valid TTLV message: tag(3 bytes) + type(1 byte) + length(4 bytes) + value
	enc := NewTTLVEncoder()
	enc.TextString(0x42007c, "hello world")
	data := enc.Bytes()

	t.Run("rejected when message exceeds max size", func(t *testing.T) {
		stream := NewStream(nopCloser{bytes.NewBuffer(data)}, 8) // limit smaller than message
		var out any
		err := stream.Recv(&out)
		require.Error(t, err)
		assert.True(t, IsErrEncoding(err))
		assert.Contains(t, err.Error(), "too big")
	})

	t.Run("accepted when message fits max size", func(t *testing.T) {
		stream := NewStream(nopCloser{bytes.NewBuffer(data)}, len(data)+100)
		var out Value
		err := stream.Recv(&out)
		require.NoError(t, err)
	})

	t.Run("no limit when max size is zero", func(t *testing.T) {
		stream := NewStream(nopCloser{bytes.NewBuffer(data)}, 0)
		var out Value
		err := stream.Recv(&out)
		require.NoError(t, err)
	})

	t.Run("no limit when max size is negative", func(t *testing.T) {
		stream := NewStream(nopCloser{bytes.NewBuffer(data)}, -1)
		var out Value
		err := stream.Recv(&out)
		require.NoError(t, err)
	})
}
