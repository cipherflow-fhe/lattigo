package clientcontext

import (
	"bufio"
	"encoding/binary"
	"io"
	"os"
	"strconv"
	"testing"

	"github.com/cipherflow-fhe/lattigo/circuits/ckks/bootstrapping"
	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
	"github.com/stretchr/testify/require"
)

// Validate production descriptors against an actual streamed native bundle,
// decoding only one evaluation key at a time (including boot switching keys).
func TestGeneratedKeyCapabilities(t *testing.T) {
	path := os.Getenv("TAA_GENERATED_EVAL")
	if path == "" {
		t.Skip("set TAA_GENERATED_EVAL to a default-plan streamed eval file")
	}
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	r := bufio.NewReaderSize(f, 64*1024)
	u64 := func() uint64 {
		var value uint64
		require.NoError(t, binary.Read(r, binary.LittleEndian, &value))
		return value
	}
	flag := func() byte {
		value, err := r.ReadByte()
		require.NoError(t, err)
		return value
	}
	skipBlob := func() {
		length := u64()
		_, err := io.CopyN(io.Discard, r, int64(length))
		require.NoError(t, err)
	}
	magic := make([]byte, 8)
	_, err = io.ReadFull(r, magic)
	require.NoError(t, err)
	require.Equal(t, contextMagic, string(magic))
	parameter := make([]byte, u64())
	_, err = io.ReadFull(r, parameter)
	require.NoError(t, err)
	var params ckks.Parameters
	require.NoError(t, params.UnmarshalBinary(parameter))
	plan := KeyPlan{DefaultRotations: flag() == 1, Bootstrapping: flag() == 1}
	require.Equal(t, byte(1), flag())
	skipBlob() // PK
	require.Equal(t, byte(1), flag())
	skipBlob() // residual keys are covered by TestStreamingContextRoundTrip
	require.Equal(t, byte(1), flag())
	bootLength := u64()
	prefix, err := r.Peek(8)
	require.NoError(t, err)
	if string(prefix) == bootstrapping.PackedKeysMagic {
		packed := &boundedPackedReader{LimitedReader: io.LimitedReader{R: r, N: int64(bootLength)}}
		bootParams, err := rlwe.ReadPackedParameters(packed, bootstrapping.PackedKeysMagic)
		require.NoError(t, err)
		capabilities, err := DescribeKeyPlan(params, plan)
		require.NoError(t, err)
		available := map[string]KeyCapability{}
		for _, key := range capabilities {
			if key.Role == "bootstrap" {
				available[key.Kind+"/"+strconv.FormatUint(key.GaloisElement, 10)] = key
			}
		}
		check := func(kind string, element uint64, key *rlwe.EvaluationKey) {
			id := kind + "/" + strconv.FormatUint(element, 10)
			info, exists := available[id]
			require.True(t, exists, id)
			delete(available, id)
			require.Equal(t, info.LevelQ, key.LevelQ(), id)
			require.Equal(t, info.LevelP, key.LevelP(), id)
			require.Equal(t, info.DecompositionRNS, key.BaseRNSDecompositionVectorSize(), id)
			require.Equal(t, info.BaseTwoDecomposition, key.BaseTwoDecomposition, id)
			require.Equal(t, 1, key.Degree(), id)
		}
		for _, kind := range []string{"evk_n1_to_n2", "evk_n2_to_n1", "evk_ci_to_std", "evk_std_to_ci", "evk_dense_to_sparse", "evk_sparse_to_dense"} {
			flag, err := packed.ReadByte()
			require.NoError(t, err)
			require.LessOrEqual(t, flag, byte(1))
			if flag == 1 {
				key, err := rlwe.ReadPackedEvaluationKey(packed, bootParams)
				require.NoError(t, err)
				check(kind, 0, key)
			}
		}
		key, err := rlwe.ReadPackedEvaluationKey(packed, bootParams)
		require.NoError(t, err)
		check("rlk", 0, key)
		var count uint32
		require.NoError(t, binary.Read(packed, binary.LittleEndian, &count))
		for range count {
			key, err := rlwe.ReadPackedGaloisKey(packed, bootParams)
			require.NoError(t, err)
			check("glk", key.GaloisElement, &key.EvaluationKey)
		}
		require.Empty(t, available)
		require.Zero(t, packed.Len())
		_, err = r.ReadByte()
		require.ErrorIs(t, err, io.EOF)
		return
	}
	before, _ := f.Seek(0, io.SeekCurrent)
	before -= int64(r.Buffered())
	capabilities, err := DescribeKeyPlan(params, plan)
	require.NoError(t, err)
	available := map[string]KeyCapability{}
	for _, key := range capabilities {
		if key.Role == "bootstrap" {
			available[key.Kind+"/"+strconv.FormatUint(key.GaloisElement, 10)] = key
		}
	}
	bootCount := len(available)
	var largest int64
	check := func(kind string, element uint64, object io.ReaderFrom, key *rlwe.EvaluationKey) {
		n, err := object.ReadFrom(r)
		require.NoError(t, err)
		if n > largest {
			largest = n
		}
		id := kind + "/" + strconv.FormatUint(element, 10)
		info, ok := available[id]
		require.True(t, ok, id)
		delete(available, id)
		require.Equal(t, key.LevelQ(), info.LevelQ, id)
		require.Equal(t, key.LevelP(), info.LevelP, id)
		require.Equal(t, key.BaseTwoDecomposition, info.BaseTwoDecomposition, id)
		require.Equal(t, key.BaseRNSDecompositionVectorSize(), info.DecompositionRNS, id)
		require.Equal(t, key.Value[0][0][0].Q.N(), 1<<info.LogN, id)
		require.Equal(t, 1, key.Degree(), id)
	}
	for _, kind := range []string{"evk_n1_to_n2", "evk_n2_to_n1", "evk_ci_to_std", "evk_std_to_ci", "evk_dense_to_sparse", "evk_sparse_to_dense"} {
		if flag() == 1 {
			key := new(rlwe.EvaluationKey)
			check(kind, 0, key, key)
		}
	}
	require.Equal(t, byte(1), flag()) // MemEvaluationKeySet
	require.Equal(t, byte(1), flag()) // RLK
	rlk := new(rlwe.RelinearizationKey)
	check("rlk", 0, rlk, &rlk.EvaluationKey)
	require.Equal(t, byte(1), flag()) // GLK map
	var count uint32
	require.NoError(t, binary.Read(r, binary.LittleEndian, &count))
	for range count {
		element := u64()
		key := new(rlwe.GaloisKey)
		check("glk", element, key, &key.EvaluationKey)
		require.Equal(t, element, key.GaloisElement)
	}
	require.Empty(t, available)
	after, _ := f.Seek(0, io.SeekCurrent)
	after -= int64(r.Buffered())
	require.Equal(t, bootLength, uint64(after-before))
	_, err = r.ReadByte()
	require.ErrorIs(t, err, io.EOF)
	t.Logf("bootKeys=%d largestSerializedKeyBytes=%d", bootCount, largest)
}

// Preserve streaming acceptance: never retain an entire multi-GiB key blob.
type boundedPackedReader struct{ io.LimitedReader }

func (r *boundedPackedReader) Len() int { return int(r.N) }
func (r *boundedPackedReader) ReadByte() (byte, error) {
	var value [1]byte
	_, err := io.ReadFull(r, value[:])
	return value[0], err
}
