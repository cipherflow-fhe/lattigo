package buffer

import (
	"encoding/binary"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// Run on amd64 and js/wasm: the wire is always u64, even when int is 32 bits.
func TestNativeIntUint64Wire(t *testing.T) {
	b := NewBufferSize(8)
	n, err := WriteAsUint64(b, int(123456789))
	require.NoError(t, err)
	require.Equal(t, int64(8), n)
	require.Equal(t, uint64(123456789), binary.LittleEndian.Uint64(b.Bytes()))
	guard := struct{ Value, Neighbor int }{Neighbor: 42}
	n, err = ReadAsUint64(b, &guard.Value)
	require.NoError(t, err)
	require.Equal(t, int64(8), n)
	require.Equal(t, 123456789, guard.Value)
	require.Equal(t, 42, guard.Neighbor)

	for _, value := range []uint64{1 << 63, ^uint64(0)} {
		data := make([]byte, 8)
		binary.LittleEndian.PutUint64(data, value)
		_, err = ReadAsUint64(NewBuffer(data), &guard.Value)
		require.Error(t, err)
	}
	if strconv.IntSize == 32 {
		data := make([]byte, 8)
		binary.LittleEndian.PutUint64(data, 1<<32)
		_, err = ReadAsUint64(NewBuffer(data), &guard.Value)
		require.Error(t, err)
	}
}
