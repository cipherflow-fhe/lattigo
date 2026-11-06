package clientcontext

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/stretchr/testify/require"
)

func TestRestoreFromTrustedProfile(t *testing.T) {
	for _, typ := range []ring.Type{ring.Standard, ring.ConjugateInvariant} {
		params := testParams(t, typ)
		plan := KeyPlan{DefaultRotations: true}
		original, err := New(params, plan)
		require.NoError(t, err)
		full := exportFile(t, original.WriteFull)
		restored, err := RestoreFrom(bytes.NewReader(full), uint64(len(full)), params, plan)
		require.NoError(t, err)
		require.True(t, restored.SecretKey.Equal(original.SecretKey))
		require.True(t, restored.PublicKey.Equal(original.PublicKey))
		// Every container length is checked against the trusted profile before make.
		publicSize := binary.LittleEndian.Uint64(full)
		parameterSize := binary.LittleEndian.Uint64(full[16:])
		pkLength := 24 + int(parameterSize) + 3
		skLength := 8 + int(publicSize)
		for _, at := range []int{0, 16, pkLength, skLength} {
			malformed := bytes.Clone(full)
			binary.LittleEndian.PutUint64(malformed[at:], ^uint64(0))
			_, err = RestoreFrom(bytes.NewReader(malformed), uint64(len(malformed)), params, plan)
			require.Error(t, err)
		}
		for _, data := range [][]byte{full[:len(full)-1], append(bytes.Clone(full), 0)} {
			_, err = RestoreFrom(bytes.NewReader(data), uint64(len(data)), params, plan)
			require.Error(t, err)
		}
	}
}
