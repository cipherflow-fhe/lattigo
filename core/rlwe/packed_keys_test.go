package rlwe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/stretchr/testify/require"
)

func TestPackedEvaluationKeyRoundTrip(t *testing.T) {
	for _, typ := range []ring.Type{ring.Standard, ring.ConjugateInvariant} {
		for _, base := range []int{0, 17} {
			for _, levelQ := range []int{0, 2} {
				for _, levelP := range []int{-1, 0} {
					t.Run(fmt.Sprintf("%v/base=%d/Q=%d/P=%d", typ, base, levelQ, levelP), func(t *testing.T) {
						p, err := NewParametersFromLiteral(ParametersLiteral{LogN: 10, LogQ: []int{60, 40, 40}, LogP: []int{61}, RingType: typ})
						require.NoError(t, err)
						kgen := NewKeyGenerator(p)
						sk := kgen.GenSecretKeyNew()
						key := kgen.GenRelinearizationKeyNew(sk, EvaluationKeyParameters{LevelQ: &levelQ, LevelP: &levelP, BaseTwoDecomposition: &base, Compressed: true})
						var packed bytes.Buffer
						require.NoError(t, WritePackedEvaluationKey(&packed, p, &key.EvaluationKey))
						require.True(t, key.IsCompressed()) // Writing never mutates the live key.
						r := bytes.NewReader(packed.Bytes())
						restored, err := ReadPackedEvaluationKey(r, p)
						require.NoError(t, err)
						require.Zero(t, r.Len())
						require.False(t, restored.IsCompressed())
						require.NoError(t, key.Expand(p, nil))
						require.True(t, key.GadgetCiphertext.Equal(&restored.GadgetCiphertext))
						native, err := key.MarshalBinary()
						require.NoError(t, err)
						require.Less(t, packed.Len(), len(native)/2)
						var again bytes.Buffer
						require.NoError(t, WritePackedEvaluationKey(&again, p, &key.EvaluationKey))
						require.Equal(t, packed.Bytes(), again.Bytes())
						for _, length := range []int{0, 4, 5, 36, packed.Len() - 1} {
							_, err = ReadPackedEvaluationKey(bytes.NewReader(packed.Bytes()[:length]), p)
							require.Error(t, err)
						}
						bad := bytes.Clone(packed.Bytes())
						binary.LittleEndian.PutUint16(bad, 65535)
						_, err = ReadPackedEvaluationKey(bytes.NewReader(bad), p)
						require.Error(t, err)
					})
				}
			}
		}
	}
}

func TestPackedCoefficients(t *testing.T) {
	for _, width := range []int{2, 17, 39, 40, 41, 51, 56, 57, 60, 61, 62, 63} {
		modulus := uint64(1)<<width - 1
		coefficients := make([]uint64, 64)
		for i := range coefficients {
			coefficients[i] = (modulus - 1 - uint64(i)) % modulus
		}
		scratch := make([]byte, len(coefficients)*8+8)
		packed, err := packCoefficients(scratch, coefficients, modulus)
		require.NoError(t, err)
		require.Len(t, packed, len(coefficients)*width/8)
		clear(scratch[len(packed):])
		actual := make([]uint64, len(coefficients))
		require.NoError(t, unpackCoefficients(scratch, actual, modulus))
		require.Equal(t, coefficients, actual)
		coefficients[0] = modulus
		_, err = packCoefficients(scratch, coefficients, modulus)
		require.Error(t, err)
	}
}

func TestPackedParametersRejectInvalidLengths(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("RLWEPK00"), append([]byte(PackedKeySetMagic), 255, 255, 255, 255)} {
		_, err := ReadPackedParameters(bytes.NewReader(data), PackedKeySetMagic)
		require.Error(t, err)
	}
}

func TestPackedKeySetRejectsMalformedContainer(t *testing.T) {
	p, err := NewParametersFromLiteral(ParametersLiteral{LogN: 10, LogQ: []int{60, 40}, LogP: []int{61}})
	require.NoError(t, err)
	kgen := NewKeyGenerator(p)
	sk := kgen.GenSecretKeyNew()
	var output bytes.Buffer
	require.NoError(t, WritePackedParameters(&output, PackedKeySetMagic, p))
	require.NoError(t, WritePackedEvaluationKey(&output, p, &kgen.GenRelinearizationKeyNew(sk, EvaluationKeyParameters{Compressed: true}).EvaluationKey))
	require.NoError(t, binary.Write(&output, binary.LittleEndian, uint32(0)))
	data := output.Bytes()
	_, err = UnmarshalPackedEvaluationKeySet(data)
	require.NoError(t, err)
	_, err = UnmarshalPackedEvaluationKeySet(append(bytes.Clone(data), 0))
	require.Error(t, err)
	bad := bytes.Clone(data)
	binary.LittleEndian.PutUint32(bad[len(bad)-4:], ^uint32(0))
	_, err = UnmarshalPackedEvaluationKeySet(bad)
	require.Error(t, err)
	bad = bytes.Clone(data)
	bad[7] = '2'
	_, err = UnmarshalPackedEvaluationKeySet(bad)
	require.Error(t, err)
}
