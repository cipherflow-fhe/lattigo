package bootstrapping

import (
	"flag"
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var minPrec float64 = 12.0

var flagLongTest = flag.Bool("long", true, "run the long test suite (all parameters + secure bootstrapping). Overrides -short and requires -timeout=0.")
var printPrecisionStats = flag.Bool("print-precision", false, "print precision stats")

func ParamsToString(params ckks.Parameters, opname string) string {
	return fmt.Sprintf("%slogN=%d/LogSlots=%d/logQP=%d/levels=%d/a=%d/b=%d",
		opname,
		params.LogN(),
		params.LogSlots(),
		params.LogQP(),
		params.MaxLevel()+1,
		params.PCount(),
		params.DecompRNS(params.QCount()-1, params.PCount()-1))
}

func TestBootstrapParametersMarshalling(t *testing.T) {
	bootstrapParams := DefaultParametersDense[0].BootstrappingParams
	data, err := bootstrapParams.MarshalBinary()
	assert.Nil(t, err)

	bootstrapParamsNew := new(Parameters)
	if err := bootstrapParamsNew.UnmarshalBinary(data); err != nil {
		assert.Nil(t, err)
	}
	assert.Equal(t, bootstrapParams, *bootstrapParamsNew)
}

func TestBootstrap(t *testing.T) {

	if runtime.GOARCH == "wasm" {
		t.Skip("skipping bootstrapping tests for GOARCH=wasm")
	}

	paramSet := DefaultParametersSparse[0]
	ckksParams := paramSet.SchemeParams
	btpParams := paramSet.BootstrappingParams

	// Insecure params for fast testing only
	if !*flagLongTest {
		ckksParams.LogN = 13
		ckksParams.LogSlots = 12
		fmt.Println("WARNING: Running bootstrapping tests with reduced parameters, results are not representative of the precision of bootstrapping with secure parameters.")
	}

	LogSlots := ckksParams.LogSlots
	H := ckksParams.H
	EphemeralSecretWeight := btpParams.EphemeralSecretWeight

	for _, testSet := range [][]bool{{false, false}, {true, false}, {false, true}, {true, true}} {

		if testSet[0] {
			ckksParams.H = EphemeralSecretWeight
			btpParams.EphemeralSecretWeight = 0
		} else {
			ckksParams.H = H
			btpParams.EphemeralSecretWeight = EphemeralSecretWeight
		}

		if testSet[1] {
			ckksParams.LogSlots = LogSlots - 1
		} else {
			ckksParams.LogSlots = LogSlots
		}

		params, err := ckks.NewParametersFromLiteral(ckksParams)
		if err != nil {
			panic(err)
		}

		testbootstrap(params, testSet[0], btpParams, t)
		runtime.GC()
	}
}

func TestSparsePackedBootstrap(t *testing.T) {

	if runtime.GOARCH == "wasm" {
		t.Skip("skipping bootstrapping tests for GOARCH=wasm")
	}

	paramSet := DefaultParametersSparse[0]
	ckksParams := paramSet.SchemeParams
	btpParams := paramSet.BootstrappingParams

	// Insecure params for fast testing only
	if !*flagLongTest {
		ckksParams.LogN = 13
		ckksParams.LogSlots = 12
	}

	H := ckksParams.H
	EphemeralSecretWeight := btpParams.EphemeralSecretWeight

	// test all sparseSlots from 2 to LogSlots
	sparseSlotsToTest := make([]int, 0)
	for i := 2; i <= ckksParams.LogSlots; i++ {
		sparseSlotsToTest = append(sparseSlotsToTest, i)
	}

	for _, testSet := range []bool{false, true} {
		if testSet {
			ckksParams.H = EphemeralSecretWeight
			btpParams.EphemeralSecretWeight = 0
		} else {
			ckksParams.H = H
			btpParams.EphemeralSecretWeight = EphemeralSecretWeight
		}
		params, err := ckks.NewParametersFromLiteral(ckksParams)
		if err != nil {
			panic(err)
		}

		for _, logSlots := range sparseSlotsToTest {
			curBtpParams := btpParams
			curLogSlots := logSlots
			curBtpParams.LogSlots = &curLogSlots

			testSparsePackedBootstrap(params, testSet, curBtpParams, t)
			runtime.GC()
		}
	}
}

func testbootstrap(params ckks.Parameters, original bool, btpParams Parameters, t *testing.T) {

	btpType := "Encapsulation/"

	if original {
		btpType = "Original/"
	}

	t.Run(ParamsToString(params, "Bootstrapping/FullCircuit/"+btpType), func(t *testing.T) {

		kgen := ckks.NewKeyGenerator(params)
		sk := kgen.GenSecretKey()
		encoder := ckks.NewEncoder(params)
		encryptor := ckks.NewEncryptor(params, sk)
		decryptor := ckks.NewDecryptor(params, sk)

		evk := GenEvaluationKeys(btpParams, params, sk)

		btp, err := NewBootstrapper(params, btpParams, evk)
		if err != nil {
			panic(err)
		}

		values := make([]complex128, 1<<params.LogSlots())
		for i := range values {
			values[i] = utils.RandComplex128(-1, 1)
		}

		values[0] = complex(0.9238795325112867, 0.3826834323650898)
		values[1] = complex(0.9238795325112867, 0.3826834323650898)
		if 1<<params.LogSlots() > 2 {
			values[2] = complex(0.9238795325112867, 0.3826834323650898)
			values[3] = complex(0.9238795325112867, 0.3826834323650898)
		}

		plaintext := ckks.NewPlaintext(params, 0, params.DefaultScale())
		encoder.Encode(values, plaintext, params.LogSlots())

		ciphertexts := make([]*ckks.Ciphertext, 2)
		bootstrappers := make([]*Bootstrapper, 2)
		bootstrappers[0] = btp
		ciphertexts[0] = encryptor.EncryptNew(plaintext)
		for i := 1; i < len(ciphertexts); i++ {
			ciphertexts[i] = encryptor.EncryptNew(plaintext)
			bootstrappers[i] = bootstrappers[0].ShallowCopy()
		}

		var wg sync.WaitGroup
		wg.Add(2)
		for i := range ciphertexts {
			go func(index int) {
				ciphertexts[index] = bootstrappers[index].Bootstrapp(ciphertexts[index])
				//btp.SetScale(ciphertexts[index], params.Scale())
				wg.Done()
			}(i)
		}
		wg.Wait()

		for i := range ciphertexts {
			verifyTestVectors(params, encoder, decryptor, values, ciphertexts[i], params.LogSlots(), 0, t)
		}
	})
}

func testSparsePackedBootstrap(params ckks.Parameters, original bool, btpParams Parameters, t *testing.T) {

	btpType := "Encapsulation/"
	if original {
		btpType = "Original/"
	}

	logSlots := params.LogSlots()
	if btpParams.LogSlots != nil {
		logSlots = *btpParams.LogSlots
	}
	slots := 1 << logSlots

	testName := fmt.Sprintf("Bootstrapping/SparsePacked/%sGlobalLogSlots_%d/BtpLogSlots_%d", btpType, params.LogSlots(), logSlots)

	t.Run(testName, func(t *testing.T) {
		kgen := ckks.NewKeyGenerator(params)
		sk := kgen.GenSecretKey()
		encoder := ckks.NewEncoder(params)
		encryptor := ckks.NewEncryptor(params, sk)
		decryptor := ckks.NewDecryptor(params, sk)

		evk := GenEvaluationKeys(btpParams, params, sk)

		btp, err := NewBootstrapper(params, btpParams, evk)
		if err != nil {
			panic(err)
		}

		values := make([]complex128, slots)
		for i := range values {
			values[i] = utils.RandComplex128(-1, 1)
		}

		values[0] = complex(0.9238795325112867, 0.3826834323650898)
		values[1] = complex(0.9238795325112867, 0.3826834323650898)
		if slots > 2 {
			values[2] = complex(0.9238795325112867, 0.3826834323650898)
			values[3] = complex(0.9238795325112867, 0.3826834323650898)
		}

		plaintext := ckks.NewPlaintext(params, 0, params.DefaultScale())
		encoder.Encode(values, plaintext, logSlots)

		ciphertext := encryptor.EncryptNew(plaintext)
		ciphertext = btp.Bootstrapp(ciphertext)
		verifyTestVectors(params, encoder, decryptor, values, ciphertext, logSlots, 0, t)
	})
}

func verifyTestVectors(params ckks.Parameters, encoder ckks.Encoder, decryptor ckks.Decryptor, valuesWant []complex128, element interface{}, logSlots int, bound float64, t *testing.T) {
	precStats := ckks.GetPrecisionStats(params, encoder, decryptor, valuesWant, element, logSlots, bound)
	if *printPrecisionStats {
		t.Log(precStats.String())
	}

	require.GreaterOrEqual(t, precStats.MeanPrecision.Real, minPrec)
	require.GreaterOrEqual(t, precStats.MeanPrecision.Imag, minPrec)
}
