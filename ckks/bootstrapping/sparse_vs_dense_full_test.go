package bootstrapping

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/rlwe"
	"github.com/stretchr/testify/require"
)

func TestSparseVsDenseFullParams(t *testing.T) {
	// WARNING: LogN=16 is SLOW. Only run ratio=2.0 (default) for direct comparison.
	sparseSet := DefaultParametersSparse[0]
	denseSet := DefaultParametersDense[0]

	for _, tc := range []struct {
		label string
		ckksP ckks.ParametersLiteral
		btpP  Parameters
	}{
		{"Sparse", sparseSet.SchemeParams, sparseSet.BootstrappingParams},
		{"Dense", denseSet.SchemeParams, denseSet.BootstrappingParams},
	} {
		t.Run(tc.label, func(t *testing.T) {
			params, err := ckks.NewParametersFromLiteral(tc.ckksP)
			require.NoError(t, err)

			kgen := ckks.NewKeyGenerator(params)
			sk := kgen.GenSecretKey()

			btpParams := tc.btpP
			ratio := 2.0
			btpParams.CoeffsToSlotsParameters.BSGSRatio = ratio
			btpParams.SlotsToCoeffsParameters.BSGSRatio = ratio

			rotations := btpParams.RotationsForBootstrapping(params)
			rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
			rlk := kgen.GenRelinearizationKey(sk, 1)
			swkDtS, swkStD := btpParams.GenEncapsulationSwitchingKeys(params, sk)

			evk := EvaluationKeys{
				EvaluationKey: rlwe.EvaluationKey{Rlk: rlk, Rtks: rotkeys},
				SwkDtS:        swkDtS,
				SwkStD:        swkStD,
			}

			btp, err := NewBootstrapper(params, btpParams, evk)
			require.NoError(t, err)

			bootstrappingScale := math.Exp2(math.Round(math.Log2(btp.params.QiFloat64(0) / btp.evalModPoly.MessageRatio())))

			// CtS
			ct := ckks.NewCiphertext(params, 1, 0, bootstrappingScale)
			ct = btp.modUpFromQ0(ct)
			btp.Trace(ct, btp.params.LogSlots(), ct)
			start := time.Now()
			ct0, ct1 := btp.CoeffsToSlotsNew(ct, btp.ctsMatrices)
			ctsTime := time.Since(start)

			// StC
			ct0 = btp.EvalModNew(ct0, btp.evalModPoly)
			ct0.Scale = btp.params.DefaultScale()
			if ct1 != nil {
				ct1 = btp.EvalModNew(ct1, btp.evalModPoly)
				ct1.Scale = btp.params.DefaultScale()
			}
			start = time.Now()
			_ = btp.SlotsToCoeffsNew(ct0, ct1, btp.stcMatrices)
			stcTime := time.Since(start)

			fmt.Printf("\n[%s Full LogN=16, Ratio=%.1f] CtS=%s, StC=%s, Total=%s, Rots=%d\n",
				tc.label, ratio, ctsTime, stcTime, ctsTime+stcTime, len(rotations))
		})
	}
}
