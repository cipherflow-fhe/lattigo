package bootstrapping

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
	"github.com/cipherflow-fhe/lattigo/utils"
	"github.com/stretchr/testify/require"
)

func TestStreamingEvaluationKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		logN int
		typ  ring.Type
	}{
		{"standard-same-N", 10, ring.Standard},
		{"standard-cross-N", 9, ring.Standard},
		{"CI-ring-swap", 9, ring.ConjugateInvariant},
	} {
		for _, weight := range []int{0, 8} {
			t.Run(fmt.Sprintf("%s/weight=%d", tc.name, weight), func(t *testing.T) {
				params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
					LogN: tc.logN, LogNthRoot: 11, RingType: tc.typ,
					LogQ: []int{60, 40}, LogP: []int{61}, LogDefaultScale: 40,
					Xs: ring.Ternary{H: 8},
				})
				require.NoError(t, err)
				p, err := NewParametersFromLiteral(params, ParametersLiteral{
					LogN: utils.Pointy(10), EphemeralSecretWeight: utils.Pointy(weight),
					Xs: ring.Ternary{H: 8},
				})
				require.NoError(t, err)
				// Insecure, reduced-degree fixtures use a sparse residual/circuit
				// secret so the default Mod1 approximation also applies without
				// encapsulation. Production parameters and thresholds are unchanged.
				p.SlotsToCoeffsParameters.LogSlots = 9
				p.CoeffsToSlotsParameters.LogSlots = 9
				p.Mod1ParametersLiteral.LogMessageRatio += 16 - params.LogN()
				sk := rlwe.NewKeyGenerator(params).GenSecretKeyNew()
				encoder := ckks.NewEncoder(params)
				values := make([]float64, params.MaxSlots())
				for i := range values {
					values[i] = float64(i%17)/32 - 0.25
				}
				pt := ckks.NewPlaintext(params, 0)
				require.NoError(t, encoder.Encode(values, pt))
				ct, err := rlwe.NewEncryptor(params, sk).EncryptNew(pt)
				require.NoError(t, err)
				// Regenerate a complete bundle twice under the same residual SK,
				// and consume both with the unchanged v6 reader and evaluator.
				for round := 0; round < 3; round++ {
					var output bytes.Buffer
					var keys EvaluationKeys
					if round == 2 {
						require.NoError(t, p.GenPackedEvaluationKeysTo(sk, &output))
						decoded, err := UnmarshalPackedEvaluationKeys(output.Bytes())
						require.NoError(t, err)
						keys = *decoded
					} else {
						n, err := p.GenEvaluationKeysTo(sk, &output)
						require.NoError(t, err)
						require.Equal(t, int64(output.Len()), n)
						read, err := keys.ReadFrom(bytes.NewReader(output.Bytes()))
						require.NoError(t, err)
						require.Equal(t, n, read)
					}
					require.Equal(t, weight != 0, keys.EvkDenseToSparse != nil)
					require.Equal(t, weight != 0, keys.EvkSparseToDense != nil)
					require.Equal(t, tc.typ == ring.ConjugateInvariant, keys.EvkRealToCmplx != nil)
					require.Equal(t, tc.typ == ring.ConjugateInvariant, keys.EvkCmplxToReal != nil)
					require.Equal(t, tc.typ == ring.Standard && tc.logN != 10, keys.EvkN1ToN2 != nil)
					require.Equal(t, tc.typ == ring.Standard && tc.logN != 10, keys.EvkN2ToN1 != nil)
					require.ElementsMatch(t, p.evaluationGaloisElements(), keys.GetGaloisKeysList())
					if round != 2 {
						canonical, err := keys.MarshalBinary()
						require.NoError(t, err)
						require.Equal(t, canonical, output.Bytes())
					}
					for _, key := range keys.GaloisKeys {
						require.Equal(t, p.BootstrappingParameters.RingQ().NthRoot(), key.NthRoot)
					}
					eval, err := NewEvaluator(p, &keys)
					require.NoError(t, err)
					var result *rlwe.Ciphertext
					if tc.typ == ring.ConjugateInvariant {
						result, _, err = eval.EvaluateConjugateInvariant(ct, nil)
					} else {
						result, err = eval.Bootstrap(ct)
					}
					require.NoError(t, err)
					verifyTestVectorsBootstrapping(params, encoder, rlwe.NewDecryptor(params, sk), values, result, t)
				}
			})
		}
	}
}

func TestSequentialGenerationStopsOnConsumerError(t *testing.T) {
	params, err := ckks.NewParametersFromLiteral(testPrec45)
	require.NoError(t, err)
	p, err := NewParametersFromLiteral(params, ParametersLiteral{LogN: utils.Pointy(params.LogN())})
	require.NoError(t, err)
	sk := rlwe.NewKeyGenerator(params).GenSecretKeyNew()
	failure := errors.New("consumer cancelled")
	calls := 0
	_, err = p.genEvaluationKeysSequential(sk, func(slot int, key io.WriterTo) error {
		calls++
		require.Equal(t, 0, slot)
		return failure
	})
	require.ErrorIs(t, err, failure)
	require.Equal(t, 1, calls)
	_, err = p.GenEvaluationKeysTo(sk, rejectWriter{failure})
	require.ErrorIs(t, err, failure)
	require.ErrorIs(t, p.GenPackedEvaluationKeysTo(sk, rejectWriter{failure}), failure)
}

type rejectWriter struct{ err error }

func (w rejectWriter) Write([]byte) (int, error) { return 0, w.err }
