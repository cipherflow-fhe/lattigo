// @company CipherFlow
// Package main implements an example showcasing the native conjugate-invariant
// (CI) CKKS bootstrapping.
//
// In the CI ring Z[X]/(X^N+1) a plaintext packs N real slots. The native CI
// bootstrapping evaluates the whole circuit directly in the CI ring using the
// factorized real DFT (circuits/ckks/realdft), so it does not need the usual
// domain switch to the standard ring. The residual and bootstrapping parameters
// therefore share the same conjugate-invariant ring degree.
//
// Use the flag -short to run the example fast but with insecure parameters.
package main

import (
	"flag"
	"fmt"
	"math"

	"github.com/cipherflow-fhe/lattigo/circuits/ckks/bootstrapping"
	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
	"github.com/cipherflow-fhe/lattigo/utils"
	"github.com/cipherflow-fhe/lattigo/utils/sampling"
)

var flagShort = flag.Bool("short", false, "run the example with a smaller and insecure ring degree.")

func main() {

	flag.Parse()

	// Default LogN, which with the following defined parameters provides a
	// reasonable security level. The native CI path packs 2^LogN real slots.
	LogN := 16

	if *flagShort {
		LogN -= 3
	}

	//==============================
	//=== 1) RESIDUAL PARAMETERS ===
	//==============================

	// The residual parameters are used outside of the bootstrapping circuit.
	// They must use the conjugate-invariant ring type for the native CI path.
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            LogN,                  // Log2 of the ring degree
		LogQ:            []int{60, 40, 40, 40}, // Log2 of the ciphertext prime moduli
		LogP:            []int{61, 61, 61},     // Log2 of the key-switch auxiliary prime moduli
		LogDefaultScale: 40,                    // Log2 of the scale
		Xs:              ring.Ternary{H: 192},
		RingType:        ring.ConjugateInvariant,
	})
	if err != nil {
		panic(err)
	}

	//==========================================
	//=== 2) BOOTSTRAPPING PARAMETERSLITERAL ===
	//==========================================

	// NativeCI enables the native conjugate-invariant bootstrapping. It requires
	// the bootstrapping LogN to equal the residual LogN (both use the same CI
	// ring, so there is no domain switch).
	btpParametersLit := bootstrapping.ParametersLiteral{
		LogN:     utils.Pointy(LogN),
		Xs:       params.Xs(),
		NativeCI: true,
	}

	btpParams, err := bootstrapping.NewParametersFromLiteral(params, btpParametersLit)
	if err != nil {
		panic(err)
	}

	if *flagShort {
		// Corrects the message ratio Q0/|m(X)| to account for the smaller number
		// of slots and keep the same precision.
		btpParams.Mod1ParametersLiteral.LogMessageRatio += 16 - params.LogN()
	}

	fmt.Printf("Residual parameters      : logN=%d, logSlots=%d, logQP=%f, levels=%d, scale=2^%d\n",
		btpParams.ResidualParameters.LogN(),
		btpParams.ResidualParameters.LogMaxSlots(),
		btpParams.ResidualParameters.LogQP(),
		btpParams.ResidualParameters.MaxLevel(),
		btpParams.ResidualParameters.LogDefaultScale())

	fmt.Printf("Bootstrapping parameters : logN=%d, logSlots=%d, logQP=%f, levels=%d, scale=2^%d, nativeCI=%v\n",
		btpParams.BootstrappingParameters.LogN(),
		btpParams.BootstrappingParameters.LogMaxSlots(),
		btpParams.BootstrappingParameters.LogQP(),
		btpParams.BootstrappingParameters.MaxLevel(),
		btpParams.BootstrappingParameters.LogDefaultScale(),
		btpParams.NativeCI)

	//===========================
	//=== 3) KEYGEN & ENCRYPT ===
	//===========================

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	encoder := ckks.NewEncoder(params)
	decryptor := rlwe.NewDecryptor(params, sk)
	encryptor := rlwe.NewEncryptor(params, sk)

	fmt.Println()
	fmt.Println("Generating bootstrapping evaluation keys...")
	evk, _, err := btpParams.GenEvaluationKeys(sk)
	if err != nil {
		panic(err)
	}
	fmt.Println("Done")

	//========================
	//=== 4) BOOTSTRAPPING ===
	//========================

	eval, err := bootstrapping.NewEvaluator(btpParams, evk)
	if err != nil {
		panic(err)
	}

	// The CI ring packs real slots, so we encode a real vector of length 2^LogN.
	values := make([]float64, params.MaxSlots())
	for i := range values {
		values[i] = sampling.RandFloat64(-1, 1)
	}

	plaintext := ckks.NewPlaintext(params, 0)
	if err := encoder.Encode(values, plaintext); err != nil {
		panic(err)
	}

	ciphertext, err := encryptor.EncryptNew(plaintext)
	if err != nil {
		panic(err)
	}

	// Bootstrap the ciphertext at level 0 to a higher level.
	fmt.Println("Bootstrapping...")
	ctOut, err := eval.Bootstrap(ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Println("Done")

	//==================
	//=== 5) DECRYPT ===
	//==================

	valuesTest := make([]float64, params.MaxSlots())
	if err := encoder.Decode(decryptor.DecryptNew(ctOut), valuesTest); err != nil {
		panic(err)
	}

	fmt.Println()
	fmt.Printf("Level: %d (logQ = %d)\n", ctOut.Level(), params.LogQLvl(ctOut.Level()))
	fmt.Printf("Scale: 2^%f\n", math.Log2(ctOut.Scale.Float64()))
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", values[0], values[1], values[2], values[3])

	fmt.Println()
	fmt.Println("Precision of Bootstrap(ciphertext) vs. ciphertext")
	fmt.Println(ckks.GetPrecisionStats(params, encoder, decryptor, values, ctOut, 0, false).String())
}
