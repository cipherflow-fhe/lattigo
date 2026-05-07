package bootstrapping

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/rlwe"
)

func BenchmarkCtSStCWithBSGS(b *testing.B) {
	paramSet := DefaultParametersSparse[0]
	ckksParams := paramSet.SchemeParams
	baseBtpParams := paramSet.BootstrappingParams

	params, err := ckks.NewParametersFromLiteral(ckksParams)
	if err != nil {
		panic(err)
	}

	kgen := ckks.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()

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
		if err != nil {
			panic(err)
		}

		b.Run(ParamsToString(params, "BSGS="+fmt.Sprintf("%.1f", ratio)+"/CtS/"), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				bootstrappingScale := math.Exp2(math.Round(math.Log2(btp.params.QiFloat64(0) / btp.evalModPoly.MessageRatio())))
				b.StopTimer()
				ct := ckks.NewCiphertext(params, 1, 0, bootstrappingScale)
				ct = btp.modUpFromQ0(ct)
				btp.Trace(ct, btp.params.LogSlots(), ct)
				b.StartTimer()

				t := time.Now()
				ct0, ct1 := btp.CoeffsToSlotsNew(ct, btp.ctsMatrices)
				b.Log("CtS time:", time.Since(t), "levels", ct0.Level(), "ratio", ratio)

				_ = ct1
				_ = ct0
			}
		})

		b.Run(ParamsToString(params, "BSGS="+fmt.Sprintf("%.1f", ratio)+"/StC/"), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				bootstrappingScale := math.Exp2(math.Round(math.Log2(btp.params.QiFloat64(0) / btp.evalModPoly.MessageRatio())))
				b.StopTimer()
				ct := ckks.NewCiphertext(params, 1, 0, bootstrappingScale)
				ct = btp.modUpFromQ0(ct)
				btp.Trace(ct, btp.params.LogSlots(), ct)
				ctReal, ctImag := btp.CoeffsToSlotsNew(ct, btp.ctsMatrices)
				ctReal = btp.EvalModNew(ctReal, btp.evalModPoly)
				ctReal.Scale = btp.params.DefaultScale()
				if ctImag != nil {
					ctImag = btp.EvalModNew(ctImag, btp.evalModPoly)
					ctImag.Scale = btp.params.DefaultScale()
				}
				b.StartTimer()

				t := time.Now()
				ct0 := btp.SlotsToCoeffsNew(ctReal, ctImag, btp.stcMatrices)
				b.Log("StC time:", time.Since(t), "levels", ct0.Level(), "ratio", ratio)

				_ = ct0
			}
		})
	}
}
