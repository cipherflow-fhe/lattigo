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

func TestSparseVsDenseBSGS(t *testing.T) {
	// Toy params for safe & fast comparison
	sparseSet := DefaultParametersSparse[0]
	denseSet := DefaultParametersDense[0]

	for _, tc := range []struct {
		label   string
		ckksP   ckks.ParametersLiteral
		btpP    Parameters
	}{
		{"Sparse", sparseSet.SchemeParams, sparseSet.BootstrappingParams},
		{"Dense", denseSet.SchemeParams, denseSet.BootstrappingParams},
	} {
		t.Run(tc.label, func(t *testing.T) {
			ckksParams := tc.ckksP
			ckksParams.LogN = 13
			ckksParams.LogSlots = 12

			params, err := ckks.NewParametersFromLiteral(ckksParams)
			require.NoError(t, err)

			kgen := ckks.NewKeyGenerator(params)
			sk := kgen.GenSecretKey()

			fmt.Printf("\n=== %s (LogN=%d) ===\n", tc.label, params.LogN())
			fmt.Printf("%-8s %-12s %-12s %-12s %-8s\n", "Ratio", "CtS", "StC", "Total", "Rots")

			for _, ratio := range []float64{1.0, 2.0, 4.0} {
				btpParams := tc.btpP
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

				fmt.Printf("%-8.1f %-12s %-12s %-12s %-8d\n",
					ratio, ctsTime, stcTime, ctsTime+stcTime, len(rotations))
			}
		})
	}
}
