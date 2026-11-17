package main

/*
#include <stdint.h>
#include <stdlib.h>

#ifndef GO_SDK_ERROR_STATUS_DEFINED
#define GO_SDK_ERROR_STATUS_DEFINED
typedef struct ErrorStatus {
    int code;
    char* message;
} ErrorStatus;
#endif
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/cipherflow-fhe/lattigo/circuits/ckks/bootstrapping"
	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
	"github.com/cipherflow-fhe/lattigo/utils"
)

//export GetCkksResidualParameterFromBtpParameter
func GetCkksResidualParameterFromBtpParameter(parameterHandle uint64, residualParameterHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	btpParams := getObject[bootstrapping.Parameters](parameterHandle)
	params := btpParams.ResidualParameters
	*residualParameterHandle = C.uint64_t(insertObject(&params))
	return status
}

//export GetCkksBootstrappingParameterFromBtpParameter
func GetCkksBootstrappingParameterFromBtpParameter(parameterHandle uint64, bootstrappingParameterHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	btpParams := getObject[bootstrapping.Parameters](parameterHandle)
	// Store a copy of the value (not a pointer to a local) so the handle does
	// not dangle after this function returns.
	params := btpParams.BootstrappingParameters
	*bootstrappingParameterHandle = C.uint64_t(insertObject(params))
	return status
}

// btpParamsByResidualLogN is the bootstrapping circuit shape, indexed by the
// residual ring degree. The circuit runs at degree 16 for both ring types; a
// conjugate invariant residual bootstraps natively in the CI ring (full packing,
// no domain switch). Only a residual degree listed here can be bootstrapped.
var btpParamsByResidualLogN = map[int]bootstrapping.ParametersLiteral{
	14: {
		LogN: utils.Pointy(16),
		SlotsToCoeffsFactorizationDepthAndLogScales: [][]int{{39}, {39}, {39}},
		CoeffsToSlotsFactorizationDepthAndLogScales: [][]int{{56}, {56}, {56}, {56}},
		EvalModLogScale: utils.Pointy(60),
	},
	15: {
		LogN: utils.Pointy(16),
		SlotsToCoeffsFactorizationDepthAndLogScales: [][]int{{39}, {39}, {39}},
		CoeffsToSlotsFactorizationDepthAndLogScales: [][]int{{56}, {56}, {56}, {56}},
		EvalModLogScale: utils.Pointy(60),
	},
	16: {
		LogN: utils.Pointy(16),
		SlotsToCoeffsFactorizationDepthAndLogScales: [][]int{{39}, {39}, {39}},
		CoeffsToSlotsFactorizationDepthAndLogScales: [][]int{{56}, {56}, {56}, {56}},
		EvalModLogScale: utils.Pointy(60),
	},
}

//export CreateCkksBtpParameterFromResidualParameter
func CreateCkksBtpParameterFromResidualParameter(residualParameterHandle uint64, parameterHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[ckks.Parameters](residualParameterHandle)

	btpParametersLit, ok := btpParamsByResidualLogN[params.LogN()]
	if !ok {
		return errorStatus(fmt.Errorf("cannot CreateCkksBtpParameterFromResidualParameter: no bootstrapping parameter set for a residual of LogN=%d", params.LogN()))
	}
	bootLogN := btpParametersLit.GetLogN()

	// A conjugate invariant residual bootstraps natively in the CI ring via the
	// real DFT (full packing), so no domain switch keys are involved.
	ci := params.RingType() == ring.ConjugateInvariant
	btpParametersLit.NativeCI = ci

	btpParams, err := bootstrapping.NewParametersFromLiteral(*params, btpParametersLit)
	if err != nil {
		return errorStatus(err)
	}
	logSlots := bootLogN - 1
	if ci {
		logSlots = bootLogN
	}
	btpParams.SlotsToCoeffsParameters.LogSlots = logSlots
	btpParams.CoeffsToSlotsParameters.LogSlots = logSlots
	// The circuit ring is larger than the residual ring, which shifts the message
	// ratio of the modular reduction by the degree difference.
	btpParams.Mod1ParametersLiteral.LogMessageRatio += bootLogN - params.LogN()

	*parameterHandle = C.uint64_t(insertObject(&btpParams))
	return status
}

//export GenCkksBootstrappingEvaluationKeys
func GenCkksBootstrappingEvaluationKeys(parameterHandle uint64, secretKeyHandle uint64, compressed int, bootstrappingEvaluationKeysHandle *C.uint64_t, evkN1ToN2Handle *C.uint64_t, evkN2ToN1Handle *C.uint64_t, evkDenseToSparseHandle *C.uint64_t, evkSparseToDenseHandle *C.uint64_t, evaluationKeySetHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[bootstrapping.Parameters](parameterHandle)
	secretKey := getObject[rlwe.SecretKey](secretKeyHandle)
	keys, _, err := params.GenEvaluationKeysWithCompressedOption(secretKey, compressed != 0)
	if err != nil {
		return errorStatus(err)
	}

	if keys.EvkN1ToN2 != nil {
		*evkN1ToN2Handle = C.uint64_t(insertObject(keys.EvkN1ToN2))
	}
	if keys.EvkN2ToN1 != nil {
		*evkN2ToN1Handle = C.uint64_t(insertObject(keys.EvkN2ToN1))
	}
	if keys.EvkDenseToSparse != nil {
		*evkDenseToSparseHandle = C.uint64_t(insertObject(keys.EvkDenseToSparse))
	}
	if keys.EvkSparseToDense != nil {
		*evkSparseToDenseHandle = C.uint64_t(insertObject(keys.EvkSparseToDense))
	}
	if keys.MemEvaluationKeySet != nil {
		*evaluationKeySetHandle = C.uint64_t(insertObject(keys.MemEvaluationKeySet))
	}
	*bootstrappingEvaluationKeysHandle = C.uint64_t(insertObject(keys))
	return status
}

//export CreateCkksBootstrappingEvaluationKeys
func CreateCkksBootstrappingEvaluationKeys(evkN1ToN2Handle uint64, evkN2ToN1Handle uint64, evkDenseToSparseHandle uint64, evkSparseToDenseHandle uint64, evaluationKeySetHandle uint64, bootstrappingEvaluationKeysHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	keys := &bootstrapping.EvaluationKeys{}
	if evkN1ToN2Handle != 0 {
		keys.EvkN1ToN2 = getObject[rlwe.EvaluationKey](evkN1ToN2Handle)
	}
	if evkN2ToN1Handle != 0 {
		keys.EvkN2ToN1 = getObject[rlwe.EvaluationKey](evkN2ToN1Handle)
	}
	if evkDenseToSparseHandle != 0 {
		keys.EvkDenseToSparse = getObject[rlwe.EvaluationKey](evkDenseToSparseHandle)
	}
	if evkSparseToDenseHandle != 0 {
		keys.EvkSparseToDense = getObject[rlwe.EvaluationKey](evkSparseToDenseHandle)
	}
	if evaluationKeySetHandle != 0 {
		keys.MemEvaluationKeySet = getObject[rlwe.MemEvaluationKeySet](evaluationKeySetHandle)
	}
	*bootstrappingEvaluationKeysHandle = C.uint64_t(insertObject(keys))
	return status
}

//export GetCkksBootstrappingEvaluationKeys
func GetCkksBootstrappingEvaluationKeys(bootstrappingEvaluationKeysHandle uint64, evkN1ToN2Handle *C.uint64_t, evkN2ToN1Handle *C.uint64_t, evkDenseToSparseHandle *C.uint64_t, evkSparseToDenseHandle *C.uint64_t, evaluationKeySetHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	keys := getObject[bootstrapping.EvaluationKeys](bootstrappingEvaluationKeysHandle)
	*evkN1ToN2Handle = 0
	*evkN2ToN1Handle = 0
	*evkDenseToSparseHandle = 0
	*evkSparseToDenseHandle = 0
	*evaluationKeySetHandle = 0
	if keys.EvkN1ToN2 != nil {
		*evkN1ToN2Handle = C.uint64_t(insertObject(keys.EvkN1ToN2))
	}
	if keys.EvkN2ToN1 != nil {
		*evkN2ToN1Handle = C.uint64_t(insertObject(keys.EvkN2ToN1))
	}
	if keys.EvkDenseToSparse != nil {
		*evkDenseToSparseHandle = C.uint64_t(insertObject(keys.EvkDenseToSparse))
	}
	if keys.EvkSparseToDense != nil {
		*evkSparseToDenseHandle = C.uint64_t(insertObject(keys.EvkSparseToDense))
	}
	if keys.MemEvaluationKeySet != nil {
		*evaluationKeySetHandle = C.uint64_t(insertObject(keys.MemEvaluationKeySet))
	}
	return status
}

//export SerializeCkksBootstrappingEvaluationKeys
func SerializeCkksBootstrappingEvaluationKeys(bootstrappingEvaluationKeysHandle uint64, rawData **byte, length *C.uint64_t, dataHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	keys := getObject[bootstrapping.EvaluationKeys](bootstrappingEvaluationKeysHandle)
	data, err := keys.MarshalBinary()
	if err != nil {
		return errorStatus(err)
	}

	*length = C.uint64_t(len(data))
	if len(data) == 0 {
		*rawData = nil
	} else {
		*rawData = &data[0]
	}
	*dataHandle = C.uint64_t(insertObject(data))
	return status
}

//export DeserializeCkksBootstrappingEvaluationKeys
func DeserializeCkksBootstrappingEvaluationKeys(rawData *byte, length C.uint64_t, bootstrappingEvaluationKeysHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if rawData == nil && length != 0 {
		return errorStatus(fmt.Errorf("CKKS bootstrapping evaluation keys data is nil"))
	}

	var data []byte
	if length != 0 {
		data = unsafe.Slice(rawData, int(length))
	}

	keys := new(bootstrapping.EvaluationKeys)
	if err := keys.UnmarshalBinary(data); err != nil {
		return errorStatus(err)
	}

	*bootstrappingEvaluationKeysHandle = C.uint64_t(insertObject(keys))
	return status
}

//export SetCkksBootstrappingEvaluationKeySet
func SetCkksBootstrappingEvaluationKeySet(bootstrappingEvaluationKeysHandle uint64, evaluationKeySetHandle uint64) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	keys := getObject[bootstrapping.EvaluationKeys](bootstrappingEvaluationKeysHandle)
	evaluationKeySet := getObject[rlwe.MemEvaluationKeySet](evaluationKeySetHandle)
	keys.MemEvaluationKeySet = evaluationKeySet
	return status
}

//export SetCkksBootstrappingEvaluationKeyN1ToN2
func SetCkksBootstrappingEvaluationKeyN1ToN2(bootstrappingEvaluationKeysHandle uint64, evaluationKeyHandle uint64) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	keys := getObject[bootstrapping.EvaluationKeys](bootstrappingEvaluationKeysHandle)
	evaluationKey := getObject[rlwe.EvaluationKey](evaluationKeyHandle)
	keys.EvkN1ToN2 = evaluationKey
	return status
}

//export SetCkksBootstrappingEvaluationKeyN2ToN1
func SetCkksBootstrappingEvaluationKeyN2ToN1(bootstrappingEvaluationKeysHandle uint64, evaluationKeyHandle uint64) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	keys := getObject[bootstrapping.EvaluationKeys](bootstrappingEvaluationKeysHandle)
	evaluationKey := getObject[rlwe.EvaluationKey](evaluationKeyHandle)
	keys.EvkN2ToN1 = evaluationKey
	return status
}

//export SetCkksBootstrappingEvaluationKeyDenseToSparse
func SetCkksBootstrappingEvaluationKeyDenseToSparse(bootstrappingEvaluationKeysHandle uint64, evaluationKeyHandle uint64) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	keys := getObject[bootstrapping.EvaluationKeys](bootstrappingEvaluationKeysHandle)
	evaluationKey := getObject[rlwe.EvaluationKey](evaluationKeyHandle)
	keys.EvkDenseToSparse = evaluationKey
	return status
}

//export SetCkksBootstrappingEvaluationKeySparseToDense
func SetCkksBootstrappingEvaluationKeySparseToDense(bootstrappingEvaluationKeysHandle uint64, evaluationKeyHandle uint64) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	keys := getObject[bootstrapping.EvaluationKeys](bootstrappingEvaluationKeysHandle)
	evaluationKey := getObject[rlwe.EvaluationKey](evaluationKeyHandle)
	keys.EvkSparseToDense = evaluationKey
	return status
}

// expandBootstrappingEvaluationKeysIfNeeded returns the input keys when none is
// compressed, otherwise an expanded deep copy.
func expandBootstrappingEvaluationKeysIfNeeded(params bootstrapping.Parameters,
	keys *bootstrapping.EvaluationKeys) (*bootstrapping.EvaluationKeys, error) {

	if keys == nil {
		return nil, nil
	}

	paramsN2 := params.BootstrappingParameters
	needsExpand := false
	for _, key := range []*rlwe.EvaluationKey{
		keys.EvkN1ToN2, keys.EvkN2ToN1, keys.EvkRealToCmplx, keys.EvkCmplxToReal, keys.EvkDenseToSparse,
		keys.EvkSparseToDense,
	} {
		if key != nil && key.IsCompressed() {
			needsExpand = true
			break
		}
	}
	if !needsExpand && keys.MemEvaluationKeySet != nil {
		needsExpand = keys.MemEvaluationKeySet.RelinearizationKey != nil &&
			keys.MemEvaluationKeySet.RelinearizationKey.IsCompressed()
		if !needsExpand {
			for _, galoisKey := range keys.MemEvaluationKeySet.GaloisKeys {
				if galoisKey.IsCompressed() {
					needsExpand = true
					break
				}
			}
		}
	}
	if !needsExpand {
		return keys, nil
	}

	expand := func(key *rlwe.EvaluationKey, keyParams rlwe.ParameterProvider) (*rlwe.EvaluationKey, error) {
		if key == nil {
			return nil, nil
		}
		keyCopy := key.CopyNew()
		if keyCopy.IsCompressed() {
			if err := keyCopy.Expand(keyParams, nil); err != nil {
				return nil, err
			}
		}
		return keyCopy, nil
	}

	out := *keys
	var err error
	if out.EvkN1ToN2, err = expand(keys.EvkN1ToN2, paramsN2); err != nil {
		return nil, err
	}
	if out.EvkN2ToN1, err = expand(keys.EvkN2ToN1, paramsN2); err != nil {
		return nil, err
	}
	if out.EvkRealToCmplx, err = expand(keys.EvkRealToCmplx, paramsN2); err != nil {
		return nil, err
	}
	if out.EvkCmplxToReal, err = expand(keys.EvkCmplxToReal, paramsN2); err != nil {
		return nil, err
	}

	// The dense-to-sparse key lives in a parameter set whose Q is the first
	// prime of the bootstrapping modulus chain.
	var sparseParams rlwe.ParameterProvider = paramsN2
	if paramsN2.QCount() > 1 {
		paramsSparse, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN:     paramsN2.LogN(),
			Q:        paramsN2.Q()[:1],
			P:        paramsN2.P(),
			RingType: paramsN2.RingType(),
		})
		if err != nil {
			return nil, err
		}
		sparseParams = paramsSparse
	}
	if out.EvkDenseToSparse, err = expand(keys.EvkDenseToSparse, sparseParams); err != nil {
		return nil, err
	}
	if out.EvkSparseToDense, err = expand(keys.EvkSparseToDense, paramsN2); err != nil {
		return nil, err
	}

	if keys.MemEvaluationKeySet != nil {
		evaluationKeySet, err := expandEvaluationKeySetIfNeeded(paramsN2, keys.MemEvaluationKeySet)
		if err != nil {
			return nil, err
		}
		out.MemEvaluationKeySet = evaluationKeySet
	}

	return &out, nil
}

//export CreateCkksBtpEvaluator
func CreateCkksBtpEvaluator(parameterHandle uint64, bootstrappingEvaluationKeysHandle uint64, evaluatorHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[bootstrapping.Parameters](parameterHandle)
	keys := getObject[bootstrapping.EvaluationKeys](bootstrappingEvaluationKeysHandle)
	keys, err := expandBootstrappingEvaluationKeysIfNeeded(*params, keys)
	if err != nil {
		return errorStatus(err)
	}
	bootstrapper, err := bootstrapping.NewEvaluator(*params, keys)
	if err != nil {
		return errorStatus(err)
	}
	*evaluatorHandle = C.uint64_t(insertObject(bootstrapper))
	return status
}

//export CkksBootstrap
func CkksBootstrap(evaluatorHandle uint64, op0CiphertextHandle uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bootstrapping.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext, err := evaluator.Bootstrap(op0Ciphertext)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export CkksBootstrapMany
func CkksBootstrapMany(evaluatorHandle uint64, op0CiphertextHandles *C.uint64_t, op0Count int, opOutCiphertextHandles *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bootstrapping.Evaluator](evaluatorHandle)
	op0Handles := unsafe.Slice((*uint64)(op0CiphertextHandles), op0Count)
	op0Ciphertexts := make([]rlwe.Ciphertext, op0Count)
	for i, handle := range op0Handles {
		op0Ciphertexts[i] = *getObject[rlwe.Ciphertext](handle)
	}

	opOutCiphertexts, err := evaluator.BootstrapMany(op0Ciphertexts)
	if err != nil {
		return errorStatus(err)
	}

	opOutHandles := unsafe.Slice((*uint64)(opOutCiphertextHandles), op0Count)
	for i := range opOutCiphertexts {
		opOutHandles[i] = uint64(insertObject(&opOutCiphertexts[i]))
	}
	return status
}
