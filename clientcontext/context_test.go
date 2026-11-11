package clientcontext

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/cmplx"
	"os"
	"testing"

	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
	"github.com/stretchr/testify/require"
)

func testParams(t *testing.T, typ ring.Type) ckks.Parameters {
	t.Helper()
	p, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 10, LogQ: []int{60, 40}, LogP: []int{61},
		LogDefaultScale: 40, RingType: typ,
	})
	require.NoError(t, err)
	return p
}

func exportFile(t *testing.T, write func(Sink) (uint64, error)) []byte {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "context-")
	require.NoError(t, err)
	n, err := write(FileSink{Writer: f, WriterAt: f})
	require.NoError(t, err)
	require.NoError(t, f.Close())
	data, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	require.Equal(t, uint64(len(data)), n)
	return data
}

// The envelope is consumed field-by-field just like CkksContext::deserialize;
// key payloads are unpacked and expanded by the native bridge before use.
func readEval(t *testing.T, data []byte, params ckks.Parameters, pk *rlwe.PublicKey) *rlwe.MemEvaluationKeySet {
	t.Helper()
	r := bytes.NewReader(data)
	magic := make([]byte, 8)
	_, err := io.ReadFull(r, magic)
	require.NoError(t, err)
	require.Equal(t, "CKKSCTX1", string(magic))
	pData, err := readBlob(r)
	require.NoError(t, err)
	var decoded ckks.Parameters
	require.NoError(t, decoded.UnmarshalBinary(pData))
	require.True(t, params.Equal(&decoded))
	for _, want := range []byte{1, 0, 1} {
		got, err := r.ReadByte()
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	pkData, err := readBlob(r)
	require.NoError(t, err)
	wantPK, err := pk.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, wantPK, pkData)
	flag, err := r.ReadByte()
	require.NoError(t, err)
	require.Equal(t, byte(1), flag)
	keysData, err := readBlob(r)
	require.NoError(t, err)
	keys, err := rlwe.UnmarshalPackedEvaluationKeySet(keysData)
	require.NoError(t, err)
	flag, err = r.ReadByte()
	require.NoError(t, err)
	require.Zero(t, flag)
	require.Zero(t, r.Len())
	return keys
}

func TestStreamingContextRoundTrip(t *testing.T) {
	for _, typ := range []ring.Type{ring.Standard, ring.ConjugateInvariant} {
		t.Run(typ.String(), func(t *testing.T) {
			params := testParams(t, typ)
			plan := KeyPlan{DefaultRotations: true}
			c, err := New(params, plan)
			require.NoError(t, err)
			encoder := ckks.NewEncoder(params)
			values := make([]complex128, params.MaxSlots())
			for i := range values {
				values[i] = complex(float64(i%13)/32, 0)
				if typ == ring.Standard {
					values[i] += complex(0, float64(i%7)/64)
				}
			}
			pt := ckks.NewPlaintext(params, params.MaxLevel())
			require.NoError(t, encoder.Encode(values, pt))
			ct, err := rlwe.NewEncryptor(params, c.PublicKey).EncryptNew(pt)
			require.NoError(t, err)
			full := exportFile(t, c.WriteFull)
			restored, err := Restore(full, plan)
			require.NoError(t, err)
			require.True(t, c.SecretKey.Equal(restored.SecretKey))
			require.True(t, c.PublicKey.Equal(restored.PublicKey))
			require.Equal(t, full, exportFile(t, restored.WriteFull))
			check := func(ct *rlwe.Ciphertext, expected func(int) complex128) {
				t.Helper()
				got := make([]complex128, len(values))
				require.NoError(t, encoder.Decode(rlwe.NewDecryptor(params, restored.SecretKey).DecryptNew(ct), got))
				for i := range got {
					require.Less(t, cmplx.Abs(got[i]-expected(i)), 1e-6)
				}
			}
			check(ct, func(i int) complex128 { return values[i] })
			for round := 0; round < 2; round++ {
				keys := readEval(t, exportFile(t, restored.WriteEval), params, c.PublicKey)
				capabilities, err := DescribeKeyPlan(params, plan)
				require.NoError(t, err)
				require.Len(t, capabilities, 1+len(keys.GaloisKeys))
				for _, info := range capabilities {
					key := &keys.RelinearizationKey.EvaluationKey
					if info.Kind == "glk" {
						key = &keys.GaloisKeys[info.GaloisElement].EvaluationKey
					}
					require.Equal(t, key.LevelQ(), info.LevelQ)
					require.Equal(t, key.LevelP(), info.LevelP)
					require.Equal(t, key.BaseTwoDecomposition, info.BaseTwoDecomposition)
					require.Equal(t, key.BaseRNSDecompositionVectorSize(), info.DecompositionRNS)
					require.Equal(t, 1, key.Degree())
					require.False(t, info.Compressed)
				}
				require.Equal(t, len(c.galEls), len(keys.GaloisKeys))
				for _, key := range keys.GaloisKeys {
					require.Equal(t, params.RingQ().NthRoot(), key.NthRoot)
				}
				eval := ckks.NewEvaluator(params, keys)
				for _, k := range []int{1, -1, 4, -4} {
					out, err := eval.RotateNew(ct, k)
					require.NoError(t, err)
					check(out, func(i int) complex128 { return values[(i+k+len(values))%len(values)] })
				}
				squared, err := eval.MulRelinNew(ct, ct)
				require.NoError(t, err)
				require.NoError(t, eval.Rescale(squared, squared))
				check(squared, func(i int) complex128 { return values[i] * values[i] })
				if typ == ring.Standard {
					out, err := eval.ConjugateNew(ct)
					require.NoError(t, err)
					check(out, func(i int) complex128 { return cmplx.Conj(values[i]) })
				}
			}
			// A newly randomized public key still targets the same secret.
			pk := rlwe.NewKeyGenerator(params).GenPublicKeyNew(restored.SecretKey)
			ct2, err := rlwe.NewEncryptor(params, pk).EncryptNew(pt)
			require.NoError(t, err)
			check(ct2, func(i int) complex128 { return values[i] })
		})
	}
}

func TestRestoreRejectsInvalidContainers(t *testing.T) {
	c, err := New(testParams(t, ring.ConjugateInvariant), KeyPlan{DefaultRotations: true})
	require.NoError(t, err)
	full := exportFile(t, c.WriteFull)
	for _, length := range []int{0, 7, 8, 16, len(full) - 1} {
		_, err = Restore(full[:length], c.plan)
		require.Error(t, err)
	}
	_, err = Restore(append(bytes.Clone(full), 0), c.plan)
	require.Error(t, err)
	_, err = Restore(full, KeyPlan{})
	require.Error(t, err)
	bad := bytes.Clone(full)
	binary.LittleEndian.PutUint64(bad, ^uint64(0))
	_, err = Restore(bad, c.plan)
	require.Error(t, err)
	// Preserve outer sizes but inject a huge polynomial dimension: reject before
	// native ReadFrom could allocate according to that untrusted count.
	bad = bytes.Clone(full)
	secretStart := 16 + int(binary.LittleEndian.Uint64(bad))
	binary.LittleEndian.PutUint64(bad[secretStart:], ^uint64(0))
	_, err = Restore(bad, c.plan)
	require.Error(t, err)
}

var errSink = errors.New("injected sink failure")

type failingSink struct {
	bytes.Buffer
	patch bool
	short bool
}

func (s *failingSink) Write(p []byte) (int, error) {
	if s.short {
		return len(p) - 1, nil
	}
	return s.Buffer.Write(p)
}

func (s *failingSink) Patch(_ uint64, _ []byte) error {
	if s.patch {
		return errSink
	}
	return nil
}

func TestSinkFailures(t *testing.T) {
	c, err := New(testParams(t, ring.Standard), KeyPlan{DefaultRotations: true})
	require.NoError(t, err)
	_, err = c.WriteEval(&failingSink{patch: true})
	require.ErrorIs(t, err, errSink)
	_, err = c.WriteEval(&failingSink{short: true})
	require.ErrorIs(t, err, io.ErrShortWrite)
	_, err = c.WriteFull(&failingSink{patch: true})
	require.ErrorIs(t, err, errSink)
}
