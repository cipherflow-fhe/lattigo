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

func TestBSGSOptShort(t *testing.T) {
	// Use small insecure params for fast comparison
	paramSet := DefaultParametersSparse[0]
	ckksParams := paramSet.SchemeParams
	baseBtpParams := paramSet.BootstrappingParams

	// Reduce to toy size for speed
	ckksParams.LogN = 13
	ckksParams.LogSlots = 12

	params, err := ckks.NewParametersFromLiteral(ckksParams)
	require.NoError(t, err)

	kgen := ckks.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()

	results := []struct {
		 Ratio float64
		 CtS   time.Duration
		 StC   time.Duration
		 Rots  int
	}{}

	for _, ratio := range []float64{1.0, 2.0, 4.0} {
		btpParams := baseBtpParams
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

		// CtS test
		ct := ckks.NewCiphertext(params, 1, 0, bootstrappingScale)
		ct = btp.modUpFromQ0(ct)
		btp.Trace(ct, btp.params.LogSlots(), ct)
		start := time.Now()
		ct0, ct1 := btp.CoeffsToSlotsNew(ct, btp.ctsMatrices)
		ctsTime := time.Since(start)

		// StC test
		ct0 = btp.EvalModNew(ct0, btp.evalModPoly)
		ct0.Scale = btp.params.DefaultScale()
		if ct1 != nil {
			ct1 = btp.EvalModNew(ct1, btp.evalModPoly)
			ct1.Scale = btp.params.DefaultScale()
		}
		start = time.Now()
		_ = btp.SlotsToCoeffsNew(ct0, ct1, btp.stcMatrices)
		stcTime := time.Since(start)

		results = append(results, struct {
			 Ratio float64
			 CtS   time.Duration
			 StC   time.Duration
			 Rots  int
		}{ratio, ctsTime, stcTime, len(rotations)})
	}

	fmt.Println("\n=== BSGS Ratio Comparison (LogN=13, insecure) ===")
	fmt.Printf("%-8s %-12s %-12s %-8s\n", "Ratio", "CtS", "StC", "Rots")
	for _, r := range results {
		fmt.Printf("%-8.1f %-12s %-12s %-8d\n", r.Ratio, r.CtS, r.StC, r.Rots)
	}

	// Find best (fastest total)
	best := results[0]
	for _, r := range results[1:] {
		if r.CtS+r.StC < best.CtS+best.StC {
			best = r
		}
	}
	fmt.Printf("\nBest ratio: %.1f (CtS+StC = %s)\n", best.Ratio, best.CtS+best.StC)
}
