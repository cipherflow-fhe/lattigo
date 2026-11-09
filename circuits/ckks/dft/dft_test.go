package dft

import (
	"math/big"
	"math/rand"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
	"github.com/cipherflow-fhe/lattigo/utils"
	"github.com/cipherflow-fhe/lattigo/utils/bignum"
	"github.com/cipherflow-fhe/lattigo/utils/sampling"
)

func TestHomomorphicDFT(t *testing.T) {
	var err error

	if runtime.GOARCH == "wasm" {
		t.Skip("skipping homomorphic DFT tests for GOARCH=wasm")
	}

	testDFTMatrixLiteralMarshalling(t)

	for _, paramsLiteral := range testParametersLiteral {

		var params ckks.Parameters
		if params, err = ckks.NewParametersFromLiteral(paramsLiteral); err != nil {
			t.Fatal(err)
		}

		for _, logSlots := range []int{params.LogMaxDimensions().Cols - 1, params.LogMaxDimensions().Cols} {
			for _, testSet := range []func(params ckks.Parameters, logSlots int, t *testing.T){
				testHomomorphicEncoding,
				testHomomorphicDecoding,
			} {
				testSet(params, logSlots, t)
				runtime.GC()
			}
		}
	}
}

func testDFTMatrixLiteralMarshalling(t *testing.T) {
	t.Run("Marshalling", func(t *testing.T) {
		m := MatrixLiteral{
			LogSlots:     15,
			Type:         HomomorphicDecode,
			Format:       RepackImagAsReal,
			LevelQ:       12,
			LevelP:       1,
			LogBSGSRatio: 2,
			Levels:       []int{1, 1, 1},
			BitReversed:  true,
		}

		data, err := m.MarshalBinary()
		require.Nil(t, err)

		mNew := new(MatrixLiteral)
		if err := mNew.UnmarshalBinary(data); err != nil {
			require.Nil(t, err)
		}
		require.Equal(t, m, *mNew)
	})
}

func testHomomorphicEncoding(params ckks.Parameters, LogSlots int, t *testing.T) {

	slots := 1 << LogSlots

	var sparse bool = LogSlots < params.LogMaxDimensions().Cols

	packing := "FullPacking"
	if sparse {
		packing = "SparsePacking"
	}

	var params2N ckks.Parameters
	var err error
	if params2N, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            params.LogN() + 1,
		LogQ:            []int{60},
		LogP:            []int{61},
		LogDefaultScale: params.LogDefaultScale(),
	}); err != nil {
		t.Fatal(err)
	}

	ecd2N := ckks.NewEncoder(params2N)

	t.Run("Encode/"+packing, func(t *testing.T) {

		// This test tests the homomorphic encoding
		// It first generates a vector of complex values of size slots
		//
		// vReal + i*vImag
		//
		// Then encode coefficient-wise and encrypts the vectors :
		//
		// Enc(bitReverse(vReal)||bitReverse(vImg))
		//
		// And applies the homomorphic Encoding (will merge both vectors if there was two)
		//
		// Enc(iFFT(vReal+ i*vImag))
		//
		// And returns the result in one ciphextext if the ciphertext can store it else in two ciphertexts
		//
		// Enc(Ecd(vReal) || Ecd(vImag)) or Enc(Ecd(vReal)) and Enc(Ecd(vImag))
		//
		// Then checks that Dcd(Dec(Enc(Ecd(vReal)))) = vReal and Dcd(Dec(Enc(Ecd(vImag)))) = vImag

		Levels := make([]int, params.MaxDepth())
		for i := range Levels {
			Levels[i] = 1
		}

		CoeffsToSlotsParametersLiteral := MatrixLiteral{
			LogSlots: LogSlots,
			Type:     HomomorphicEncode,
			Format:   RepackImagAsReal,
			LevelQ:   params.MaxLevelQ(),
			LevelP:   params.MaxLevelP(),
			Levels:   Levels,
		}

		kgen := rlwe.NewKeyGenerator(params)
		sk := kgen.GenSecretKeyNew()
		encoder := ckks.NewEncoder(params, 90) // Required to force roots.(type) to be []*bignum.Complex instead of []complex128
		encryptor := rlwe.NewEncryptor(params, sk)
		decryptor := rlwe.NewDecryptor(params, sk)

		// Generates the encoding matrices
		CoeffsToSlotMatrices, err := NewMatrixFromLiteral(params, CoeffsToSlotsParametersLiteral, encoder)
		require.NoError(t, err)

		// Gets Galois elements
		galEls := append(CoeffsToSlotsParametersLiteral.GaloisElements(params), params.GaloisElementOrderTwoOrthogonalSubgroup())

		// Generates and adds the keys
		// Instantiates the EvaluationKeySet
		evk := rlwe.NewMemEvaluationKeySet(nil, kgen.GenGaloisKeysNew(galEls, sk)...)

		// Creates an evaluator with the rotation keys
		eval := ckks.NewEvaluator(params, evk)
		hdftEval := NewEvaluator(params, eval)

		prec := params.EncodingPrecision()

		// Generates the vector of random complex values
		values := make([]*bignum.Complex, slots)
		r := rand.New(rand.NewSource(0))
		for i := range values {
			values[i] = bignum.NewComplex().SetPrec(prec)
			values[i][0].SetFloat64(2*r.Float64() - 1)
			values[i][1].SetFloat64(2*r.Float64() - 1)
		}

		// Splits between real and imaginary
		valuesReal := make([]*big.Float, slots)
		for i := range valuesReal {
			valuesReal[i] = new(big.Float).Set(values[i][0])
		}

		valuesImag := make([]*big.Float, slots)
		for i := range valuesImag {
			valuesImag[i] = new(big.Float).Set(values[i][1])
		}

		// Applies bit-reverse on the original complex vector
		utils.BitReverseInPlaceSlice(values, slots)

		// Maps to a float vector
		// Add gaps if sparse packing
		valuesFloat := make([]*big.Float, params.N())
		gap := params.N() / (2 * slots)
		for i, jdx, idx := 0, params.N()>>1, 0; i < slots; i, jdx, idx = i+1, jdx+gap, idx+gap {
			valuesFloat[idx] = values[i][0]
			valuesFloat[jdx] = values[i][1]
		}

		// Encodes coefficient-wise and encrypts the test vector
		pt := ckks.NewPlaintext(params, params.MaxLevel())
		pt.LogDimensions = ring.Dimensions{Rows: 0, Cols: LogSlots}
		pt.IsBatched = false

		if err = encoder.Encode(valuesFloat, pt); err != nil {
			t.Fatal(err)
		}
		pt.IsBatched = true

		ct, err := encryptor.EncryptNew(pt)
		require.NoError(t, err)

		// Applies the homomorphic DFT
		ct0, ct1, err := hdftEval.CoeffsToSlotsNew(ct, CoeffsToSlotMatrices)
		require.NoError(t, err)

		// Checks against the original coefficients
		if sparse {

			ct0.IsBatched = false

			have := make([]*big.Float, params.N())

			if err = encoder.Decode(decryptor.DecryptNew(ct0), have); err != nil {
				t.Fatal(err)
			}

			// Plaintext circuit
			vec := make([]*bignum.Complex, 2*slots)

			// Embed real vector into the complex vector (trivial)
			for i, j := 0, slots; i < slots; i, j = i+1, j+1 {
				vec[i] = bignum.NewComplex().SetPrec(prec)
				vec[i][0].Set(valuesReal[i])
				vec[j] = bignum.NewComplex().SetPrec(prec)
				vec[j][0].Set(valuesImag[i])
			}

			// IFFT
			if err = encoder.IFFT(vec, LogSlots+1); err != nil {
				t.Fatal(err)
			}

			// Extract complex vector into real vector
			want := make([]*big.Float, params.N())
			for i, idx, jdx := 0, 0, params.N()>>1; i < 2*slots; i, idx, jdx = i+1, idx+gap/2, jdx+gap/2 {
				want[idx] = vec[i][0]
				want[jdx] = vec[i][1]
			}

			// Compares
			ckks.VerifyTestVectors(params, ecd2N, nil, want, have, params.LogDefaultScale(), 0, true, t)

		} else {

			ct0.IsBatched = false
			ct1.IsBatched = false

			haveReal := make([]*big.Float, params.N())
			if err = encoder.Decode(decryptor.DecryptNew(ct0), haveReal); err != nil {
				t.Fatal(err)
			}

			haveImag := make([]*big.Float, params.N())
			if err = encoder.Decode(decryptor.DecryptNew(ct1), haveImag); err != nil {
				t.Fatal(err)
			}

			vec0 := make([]*bignum.Complex, slots)
			vec1 := make([]*bignum.Complex, slots)

			// Embed real vector into the complex vector (trivial)
			for i := 0; i < slots; i++ {
				vec0[i] = bignum.NewComplex().SetPrec(prec)
				vec0[i][0].Set(valuesReal[i])
				vec1[i] = bignum.NewComplex().SetPrec(prec)
				vec1[i][0].Set(valuesImag[i])
			}

			// IFFT
			if err = encoder.IFFT(vec0, LogSlots); err != nil {
				t.Fatal(err)
			}
			if err = encoder.IFFT(vec1, LogSlots); err != nil {
				t.Fatal(err)
			}

			// Extract complex vectors into real vectors
			wantReal := make([]*big.Float, params.N())
			wantImag := make([]*big.Float, params.N())
			for i, j := 0, slots; i < slots; i, j = i+1, j+1 {
				wantReal[i], wantReal[j] = vec0[i][0], vec0[i][1]
				wantImag[i], wantImag[j] = vec1[i][0], vec1[i][1]
			}

			ckks.VerifyTestVectors(params, ecd2N, nil, wantReal, haveReal, params.LogDefaultScale(), 0, true, t)
			ckks.VerifyTestVectors(params, ecd2N, nil, wantImag, haveImag, params.LogDefaultScale(), 0, true, t)
		}
	})
}

func testHomomorphicDecoding(params ckks.Parameters, LogSlots int, t *testing.T) {

	slots := 1 << LogSlots

	var sparse bool = LogSlots < params.LogMaxDimensions().Cols

	packing := "FullPacking"
	if sparse {
		packing = "SparsePacking"
	}

	t.Run("Decode/"+packing, func(t *testing.T) {

		// This test tests the homomorphic decoding
		// It first generates a complex vector of size 2*slots
		// if 2*slots == N, then two vectors are generated, one for the real part, one for the imaginary part :
		//
		// vReal and vReal (both floating point vectors because the encoding always result in a real vector)
		//
		// Then encode and encrypts the vectors :
		//
		// Enc(Ecd(vReal)) and Enc(Ecd(vImag))
		//
		// And applies the homomorphic decoding (will merge both vectors if there was two)
		//
		// Enc(FFT(Ecd(vReal) + i*Ecd(vImag)))
		//
		// The result should be the decoding of the initial vectors bit-reversed
		//
		// Enc(FFT(Ecd(vReal) + i*Ecd(vImag))) = Enc(BitReverse(Dcd(Ecd(vReal + i*vImag))))
		//
		// The first N/2 slots of the plaintext will be the real part while the last N/2 the imaginary part
		// In case of 2*slots < N, then there is a gap of N/(2*slots) between each values

		Levels := make([]int, params.MaxDepth())
		for i := range Levels {
			Levels[i] = 1
		}

		SlotsToCoeffsParametersLiteral := MatrixLiteral{
			LogSlots: LogSlots,
			Type:     HomomorphicDecode,
			Format:   RepackImagAsReal,
			LevelQ:   params.MaxLevelQ(),
			LevelP:   params.MaxLevelP(),
			Levels:   Levels,
		}

		kgen := rlwe.NewKeyGenerator(params)
		sk := kgen.GenSecretKeyNew()
		encoder := ckks.NewEncoder(params)
		encryptor := rlwe.NewEncryptor(params, sk)
		decryptor := rlwe.NewDecryptor(params, sk)

		// Generates the encoding matrices
		SlotsToCoeffsMatrix, err := NewMatrixFromLiteral(params, SlotsToCoeffsParametersLiteral, encoder)
		require.NoError(t, err)

		// Gets the Galois elements
		galEls := append(SlotsToCoeffsParametersLiteral.GaloisElements(params), params.GaloisElementOrderTwoOrthogonalSubgroup())

		// Generates and adds the keys
		// Instantiates the EvaluationKeySet
		evk := rlwe.NewMemEvaluationKeySet(nil, kgen.GenGaloisKeysNew(galEls, sk)...)

		// Creates an evaluator with the rotation keys
		eval := ckks.NewEvaluator(params, evk)
		hdftEval := NewEvaluator(params, eval)

		prec := params.EncodingPrecision()

		// Generates the n first slots of the test vector (real part to encode)
		valuesReal := make([]*bignum.Complex, slots)
		for i := range valuesReal {
			valuesReal[i] = bignum.NewComplex().SetPrec(prec)
			valuesReal[i][0].SetFloat64(sampling.RandFloat64(-1, 1))
		}

		// Generates the n first slots of the test vector (imaginary part to encode)
		valuesImag := make([]*bignum.Complex, slots)
		for i := range valuesImag {
			valuesImag[i] = bignum.NewComplex().SetPrec(prec)
			valuesImag[i][0].SetFloat64(sampling.RandFloat64(-1, 1))
		}

		// If sparse, there there is the space to store both vectors in one
		if sparse {
			for i := range valuesReal {
				valuesReal[i][1].Add(valuesReal[i][1], valuesImag[i][0])
			}
			LogSlots++
		}

		// Encodes and encrypts the test vectors
		plaintext := ckks.NewPlaintext(params, params.MaxLevel())
		plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: LogSlots}
		if err = encoder.Encode(valuesReal, plaintext); err != nil {
			t.Fatal(err)
		}
		ct0, err := encryptor.EncryptNew(plaintext)
		require.NoError(t, err)

		var ct1 *rlwe.Ciphertext
		if !sparse {
			if err = encoder.Encode(valuesImag, plaintext); err != nil {
				t.Fatal(err)
			}
			var err error
			ct1, err = encryptor.EncryptNew(plaintext)
			require.NoError(t, err)
		}

		// Applies the homomorphic DFT
		res, err := hdftEval.SlotsToCoeffsNew(ct0, ct1, SlotsToCoeffsMatrix)
		require.NoError(t, err)

		// Decrypt and decode in the coefficient domain
		coeffsFloat := make([]*big.Float, params.N())
		res.IsBatched = false

		if err = encoder.Decode(decryptor.DecryptNew(res), coeffsFloat); err != nil {
			t.Fatal(err)
		}

		// Extracts the coefficients and construct the complex vector
		// This is simply coefficient ordering
		valuesTest := make([]*bignum.Complex, slots)
		gap := params.N() / (2 * slots)
		for i, idx := 0, 0; i < slots; i, idx = i+1, idx+gap {
			valuesTest[i] = &bignum.Complex{coeffsFloat[idx], coeffsFloat[idx+(params.N()>>1)]}
		}

		// The result is always returned as a single complex vector, so if full-packing (2 initial vectors)
		// then repacks both vectors together
		if !sparse {
			for i := range valuesReal {
				valuesReal[i][1].Add(valuesReal[i][1], valuesImag[i][0])
			}
		}

		// Result is bit-reversed, so applies the bit-reverse permutation on the reference vector
		utils.BitReverseInPlaceSlice(valuesReal, slots)

		ckks.VerifyTestVectors(params, encoder, decryptor, valuesReal, valuesTest, params.LogDefaultScale(), 0, true, t)
	})
}

var (
	// testInsecurePrec45 are insecure parameters used for the sole purpose of fast testing.
	testInsecurePrec45 = ckks.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{55, 45, 45, 45, 45, 45, 45},
		LogP:            []int{60},
		LogDefaultScale: 45,
	}

	// testInsecurePrec90 are insecure parameters used for the sole purpose of fast testing.
	testInsecurePrec90 = ckks.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{55, 55, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45},
		LogP:            []int{60, 60},
		LogDefaultScale: 90,
	}

	testParametersLiteral = []ckks.ParametersLiteral{testInsecurePrec45, testInsecurePrec90}
)

// TestHomomorphicRealDFT tests the homomorphic encoding and decoding of the real
// DFT in the conjugate-invariant ring, following the CI-CKKS bootstrapping
// circuit.
//
// Per the CI-CKKS bootstrapping paper (ePrint 2026/2618, Section 3.1), the real
// DFT factorization computes P·V^{-1} (CoeffsToSlots) and V·P^T (SlotsToCoeffs),
// where P is the permutation induced by the ordering of the final real
// coordinates — it is explicitly *not* a bit-reversal. The permutation is not
// evaluated separately: it is left in place and cancels between the two
// transformations. Each direction is checked against the exact permuted
// reference produced by realDFTCoordinatePermutation.
// @company CipherFlow
func TestHomomorphicRealDFT(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("skipping homomorphic real DFT tests for GOARCH=wasm")
	}

	paramsLiteral := testInsecurePrec45
	paramsLiteral.RingType = ring.ConjugateInvariant

	params, err := ckks.NewParametersFromLiteral(paramsLiteral)
	require.NoError(t, err)

	testHomomorphicRealEncoding(params, t)
	testHomomorphicRealDecoding(params, t)
}

// testHomomorphicRealEncoding checks CoeffsToSlots: a coefficient-encoded
// ciphertext is transformed into the slot domain. Slot-decoding the result
// yields the input vector permuted by the real-DFT slot permutation P.
// @company CipherFlow
func testHomomorphicRealEncoding(params ckks.Parameters, t *testing.T) {
	logSlots := params.LogMaxDimensions().Cols // = logN for the CI ring
	slots := 1 << logSlots

	levels := make([]int, params.MaxDepth())
	for i := range levels {
		levels[i] = 1
	}

	ctsLit := MatrixLiteral{Type: HomomorphicEncode, LogSlots: logSlots, Real: true, LevelQ: params.MaxLevelQ(), LevelP: params.MaxLevelP(), Levels: levels}

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	encoder := ckks.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, sk)
	decryptor := rlwe.NewDecryptor(params, sk)

	ctsMat, err := NewMatrixFromLiteral(params, ctsLit, encoder)
	require.NoError(t, err)

	galEls := ctsLit.GaloisElements(params)
	evk := rlwe.NewMemEvaluationKeySet(nil, kgen.GenGaloisKeysNew(galEls, sk)...)
	hdftEval := NewEvaluator(params, ckks.NewEvaluator(params, evk))

	// Random real slot vector.
	values := make([]float64, slots)
	r := rand.New(rand.NewSource(0))
	for i := range values {
		values[i] = 2*r.Float64() - 1
	}

	// Encode coefficient-wise: the plaintext holds the slot values as raw
	// polynomial coefficients (the output of the bootstrapping ModRaise).
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	pt.LogDimensions = ring.Dimensions{Rows: 0, Cols: logSlots}
	pt.IsBatched = false
	require.NoError(t, encoder.Encode(values, pt))
	pt.IsBatched = true
	ct, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	// CoeffsToSlots (coeffs -> slots).
	ctSlots, _, err := hdftEval.CoeffsToSlotsNew(ct, ctsMat)
	require.NoError(t, err)

	// Slot-decode the result; it is the input permuted by the real-DFT slot
	// permutation P.
	ctSlots.IsBatched = true
	ctSlots.LogDimensions = ring.Dimensions{Rows: 0, Cols: logSlots}
	have := make([]float64, slots)
	require.NoError(t, encoder.Decode(decryptor.DecryptNew(ctSlots), have))

	want := permute(values, realDFTCoordinatePermutation(logSlots))
	ckks.VerifyTestVectors(params, encoder, nil, want, have, params.LogDefaultScale(), 0, true, t)
}

// testHomomorphicRealDecoding checks SlotsToCoeffs: a slot-encoded ciphertext is
// transformed into the coefficient domain. Coefficient-decoding the result
// yields the input vector permuted by the inverse of the real-DFT slot
// permutation P.
// @company CipherFlow
func testHomomorphicRealDecoding(params ckks.Parameters, t *testing.T) {
	logSlots := params.LogMaxDimensions().Cols // = logN for the CI ring
	slots := 1 << logSlots

	levels := make([]int, params.MaxDepth())
	for i := range levels {
		levels[i] = 1
	}

	stcLit := MatrixLiteral{Type: HomomorphicDecode, LogSlots: logSlots, Real: true, LevelQ: params.MaxLevelQ(), LevelP: params.MaxLevelP(), Levels: levels}

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	encoder := ckks.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, sk)
	decryptor := rlwe.NewDecryptor(params, sk)

	stcMat, err := NewMatrixFromLiteral(params, stcLit, encoder)
	require.NoError(t, err)

	galEls := stcLit.GaloisElements(params)
	evk := rlwe.NewMemEvaluationKeySet(nil, kgen.GenGaloisKeysNew(galEls, sk)...)
	hdftEval := NewEvaluator(params, ckks.NewEvaluator(params, evk))

	// Random real slot vector.
	values := make([]float64, slots)
	r := rand.New(rand.NewSource(0))
	for i := range values {
		values[i] = 2*r.Float64() - 1
	}

	// Encode (slots -> coeffs) and encrypt.
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	pt.LogDimensions = ring.Dimensions{Rows: 0, Cols: logSlots}
	require.NoError(t, encoder.Encode(values, pt))
	ct0, err := encryptor.EncryptNew(pt)
	require.NoError(t, err)

	// SlotsToCoeffs (slots -> coeffs).
	res, err := hdftEval.SlotsToCoeffsNew(ct0, nil, stcMat)
	require.NoError(t, err)

	// Coefficient-decode the result; it is the input permuted by P^{-1}.
	res.IsBatched = false
	have := make([]float64, params.N())
	require.NoError(t, encoder.Decode(decryptor.DecryptNew(res), have))

	want := permute(values, invertPermutation(realDFTCoordinatePermutation(logSlots)))
	ckks.VerifyTestVectors(params, encoder, nil, want, have, params.LogDefaultScale(), 0, true, t)
}

// realDFTCoordinatePermutation returns the permutation P determined by the ordering
// of the final real coordinates of the real DFT (CI-CKKS bootstrapping paper,
// ePrint 2026/2618, Theorem 1). P[i] is the slot index that lands at output
// position i after CoeffsToSlots, so slot-decoding the CoeffsToSlots output
// yields P(x) for an input slot vector x. It is the "real FFT" ordering, not a
// bit-reversal.
// @company CipherFlow
func realDFTCoordinatePermutation(logN int) []int {
	N := 1 << logN

	// Replicates the realdft unitsStage ordering: the real sub-vectors at the
	// final stage, each carrying a frequency r and whether it is a conjugate
	// pair (r, N-r).
	type unit struct {
		r    int
		pair bool
	}
	us := []unit{{0, false}}
	for s := 1; s < N; s <<= 1 {
		next := make([]unit, 0, 2*len(us))
		for _, u := range us {
			if !u.pair {
				if u.r == 0 {
					next = append(next, unit{0, false}, unit{s, false})
				} else {
					next = append(next, unit{s >> 1, true})
				}
			} else {
				next = append(next, unit{u.r, true}, unit{s - u.r, true})
			}
		}
		us = next
	}

	// The final coordinates store a real sub-vector at slot r, and a conjugate
	// pair (r, N-r) as (Re, Im) at slots r and N-r respectively.
	perm := make([]int, 0, N)
	for _, u := range us {
		if !u.pair {
			perm = append(perm, u.r)
		} else {
			perm = append(perm, u.r, N-u.r)
		}
	}
	return perm
}

// permute returns x reordered by perm: out[i] = x[perm[i]].
// @company CipherFlow
func permute(x []float64, perm []int) []float64 {
	out := make([]float64, len(perm))
	for i, p := range perm {
		out[i] = x[p]
	}
	return out
}

// invertPermutation returns the inverse of perm: inv[perm[i]] = i.
// @company CipherFlow
func invertPermutation(perm []int) []int {
	inv := make([]int, len(perm))
	for i, p := range perm {
		inv[p] = i
	}
	return inv
}
