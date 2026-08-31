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
	"runtime/cgo"
	"strconv"
	"unsafe"

	"github.com/cipherflow-fhe/lattigo/circuits/ckks/bootstrapping"
	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/examples"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
)

// ─── CkksParameter ───────────────────────────────────────────────────────────

//export CreateCkksDefaultParameter
func CreateCkksDefaultParameter(logN int, parameterHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	var literal ckks.ParametersLiteral
	switch logN {
	case 12:
		literal = examples.CKKSComplexParamsN12QP109
	case 13:
		literal = examples.CKKSComplexParamsN13QP218
	case 14:
		literal = examples.CKKSComplexParamsN14QP438
	case 15:
		literal = examples.CKKSComplexParamsN15QP881
	case 16:
		literal = examples.CKKSComplexParamsPN16QP1761
	default:
		return errorStatus(fmt.Errorf("LogN not supported"))
	}
	literal.LogNthRoot = bootstrapping.DefaultLogN + 1

	params, err := ckks.NewParametersFromLiteral(literal)
	if err != nil {
		return errorStatus(err)
	}
	*parameterHandle = C.uint64_t(insertObject(&params))
	return status
}

//export CreateCkksCustomParameter
func CreateCkksCustomParameter(logN int, logDefaultScale int, q *C.uint64_t, qLen int, p *C.uint64_t, pLen int, parameterHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	qSlice := unsafe.Slice((*uint64)(q), qLen)
	pSlice := unsafe.Slice((*uint64)(p), pLen)

	literal := ckks.ParametersLiteral{
		LogN:            logN,
		Q:               append([]uint64(nil), qSlice...),
		P:               append([]uint64(nil), pSlice...),
		LogDefaultScale: logDefaultScale,
	}

	params, err := ckks.NewParametersFromLiteral(literal)
	if err != nil {
		return errorStatus(err)
	}
	*parameterHandle = C.uint64_t(insertObject(&params))
	return status
}

//export CopyCkksParameter
func CopyCkksParameter(parameterHandle uint64, targetHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := *getObject[ckks.Parameters](parameterHandle)
	*targetHandle = C.uint64_t(insertObject(&params))
	return status
}

//export SerializeCkksParameter
func SerializeCkksParameter(parameterHandle uint64, rawData **byte, length *C.uint64_t, dataHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[ckks.Parameters](parameterHandle)
	data, err := params.MarshalBinary()
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

//export DeserializeCkksParameter
func DeserializeCkksParameter(rawData *byte, length C.uint64_t, parameterHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if rawData == nil && length != 0 {
		return errorStatus(fmt.Errorf("CKKS parameter data is nil"))
	}

	var data []byte
	if length != 0 {
		data = unsafe.Slice(rawData, int(length))
	}

	params := new(ckks.Parameters)
	if err := params.UnmarshalBinary(data); err != nil {
		return errorStatus(err)
	}
	*parameterHandle = C.uint64_t(insertObject(params))
	return status
}

//export PrintCkksParameter
func PrintCkksParameter(parameterHandle uint64) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[ckks.Parameters](parameterHandle)
	fmt.Println(*params)
	return status
}

//export GetCkksN
func GetCkksN(parameterHandle uint64, n *C.int) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[ckks.Parameters](parameterHandle)
	*n = C.int(params.N())
	return status
}

//export GetCkksLogN
func GetCkksLogN(parameterHandle uint64, logN *C.int) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[ckks.Parameters](parameterHandle)
	*logN = C.int(params.LogN())
	return status
}

//export GetCkksMaxLevel
func GetCkksMaxLevel(parameterHandle uint64, maxLevel *C.int) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[ckks.Parameters](parameterHandle)
	*maxLevel = C.int(params.MaxLevel())
	return status
}

//export GetCkksQ
func GetCkksQ(parameterHandle uint64, rawData *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[ckks.Parameters](parameterHandle)
	q := params.Q()
	if len(q) != 0 {
		copy(unsafe.Slice((*uint64)(rawData), len(q)), q)
	}
	return status
}

//export GetCkksP
func GetCkksP(parameterHandle uint64, rawData *C.uint64_t, length *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[ckks.Parameters](parameterHandle)
	p := params.P()
	requiredLength := C.uint64_t(len(p))
	if rawData == nil {
		*length = requiredLength
		return status
	}
	if *length < requiredLength {
		*length = requiredLength
		return errorStatus(fmt.Errorf("GetCkksP buffer too small"))
	}
	if len(p) != 0 {
		copy(unsafe.Slice((*uint64)(rawData), len(p)), p)
	}
	*length = requiredLength
	return status
}

//export GetCkksLogMaxSlots
func GetCkksLogMaxSlots(parameterHandle uint64, logMaxSlots *C.int) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[ckks.Parameters](parameterHandle)
	*logMaxSlots = C.int(params.LogMaxSlots())
	return status
}

//export GetCkksMaxSlots
func GetCkksMaxSlots(parameterHandle uint64, maxSlots *C.int) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[ckks.Parameters](parameterHandle)
	*maxSlots = C.int(params.MaxSlots())
	return status
}

//export GetCkksDefaultScale
func GetCkksDefaultScale(parameterHandle uint64, defaultScale *C.double) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[ckks.Parameters](parameterHandle)
	*defaultScale = C.double(params.DefaultScale().Float64())
	return status
}

//export GetCkksLogDefaultScale
func GetCkksLogDefaultScale(parameterHandle uint64, logDefaultScale *C.int) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[ckks.Parameters](parameterHandle)
	*logDefaultScale = C.int(params.LogDefaultScale())
	return status
}

// ─── CkksEncoder ─────────────────────────────────────────────────────────────

//export CreateCkksEncoder
func CreateCkksEncoder(parameterHandle uint64, encoderHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[ckks.Parameters](parameterHandle)
	encoder := ckks.NewEncoder(*params)
	*encoderHandle = C.uint64_t(insertObject(encoder))
	return status
}

// ─── CkksEvaluator ───────────────────────────────────────────────────────────

//export CreateCkksEvaluator
func CreateCkksEvaluator(parameterHandle uint64, evaluationKeySetHandle uint64, evaluatorHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[ckks.Parameters](parameterHandle)
	evaluationKeySet := getObject[rlwe.MemEvaluationKeySet](evaluationKeySetHandle)
	evaluator := ckks.NewEvaluator(*params, evaluationKeySet)
	*evaluatorHandle = C.uint64_t(insertObject(evaluator))
	return status
}

//export SetCkksEvaluatorEvaluationKeySet
func SetCkksEvaluatorEvaluationKeySet(evaluatorHandle uint64, evaluationKeySetHandle uint64) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[ckks.Evaluator](evaluatorHandle)
	evaluationKeySet := getObject[rlwe.MemEvaluationKeySet](evaluationKeySetHandle)
	*evaluator = *evaluator.WithKey(evaluationKeySet)
	return status
}

// ─── CkksCiphertext ──────────────────────────────────────────────────────────

//export CopyCkksCiphertext
func CopyCkksCiphertext(ciphertextHandle uint64) uint64 {
	ciphertext := getObject[rlwe.Ciphertext](ciphertextHandle)
	return insertObject(ciphertext.CopyNew())
}

//export CopyCkksCiphertextTo
func CopyCkksCiphertextTo(xCiphertextHandle uint64, yCiphertextHandle uint64) uint64 {
	src := getObject[rlwe.Ciphertext](xCiphertextHandle)
	dst := getObject[rlwe.Ciphertext](yCiphertextHandle)
	dst.Copy(src)
	return yCiphertextHandle
}

// ─── CkksContext ─────────────────────────────────────────────────────────────

//export CkksEncodeReal
func CkksEncodeReal(encoderHandle uint64, messageArray *C.double, messageLen int, plaintextHandle uint64) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	encoder := getObject[ckks.Encoder](encoderHandle)
	plaintext := getObject[rlwe.Plaintext](plaintextHandle)
	message := unsafe.Slice((*float64)(messageArray), messageLen)
	if err := encoder.Encode(message, plaintext); err != nil {
		return errorStatus(err)
	}
	return status
}

//export CkksEncodeComplex
func CkksEncodeComplex(encoderHandle uint64, messageArray *C.double, messageLen int, plaintextHandle uint64) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	encoder := getObject[ckks.Encoder](encoderHandle)
	plaintext := getObject[rlwe.Plaintext](plaintextHandle)
	slice := unsafe.Slice((*float64)(messageArray), messageLen*2)
	message := make([]complex128, messageLen)
	for i := range message {
		message[i] = complex(slice[i*2], slice[i*2+1])
	}
	if err := encoder.Encode(message, plaintext); err != nil {
		return errorStatus(err)
	}
	return status
}

//export CkksDecode
func CkksDecode(encoderHandle uint64, plaintextHandle uint64, rawData **C.double, length *C.uint64_t, dataHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	encoder := getObject[ckks.Encoder](encoderHandle)
	plaintext := getObject[rlwe.Plaintext](plaintextHandle)

	valueCount := encoder.GetParameters().N()
	if plaintext.IsBatched {
		valueCount = 1 << plaintext.LogSlots()
	}
	message := make([]complex128, valueCount)
	if err := encoder.Decode(plaintext, message); err != nil {
		return errorStatus(err)
	}

	data := make([]float64, valueCount*2)
	for i, value := range message {
		data[i*2] = real(value)
		data[i*2+1] = imag(value)
	}
	*length = C.uint64_t(valueCount)
	if len(data) == 0 {
		*rawData = nil
	} else {
		*rawData = (*C.double)(unsafe.Pointer(&data[0]))
	}
	*dataHandle = C.uint64_t(insertObject(data))
	return status
}

//export CkksEncrypt
func CkksEncrypt(encryptorHandle uint64, plaintextHandle uint64, ciphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	encryptor := getObject[rlwe.Encryptor](encryptorHandle)
	plaintext := getObject[rlwe.Plaintext](plaintextHandle)
	ciphertext, err := encryptor.EncryptNew(plaintext)
	if err != nil {
		return errorStatus(err)
	}
	*ciphertextHandle = C.uint64_t(insertObject(ciphertext))
	return status
}

//export CkksDecrypt
func CkksDecrypt(decryptorHandle uint64, ciphertextHandle uint64, plaintextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	decryptor := getObject[rlwe.Decryptor](decryptorHandle)
	ciphertext := getObject[rlwe.Ciphertext](ciphertextHandle)
	plaintext := decryptor.DecryptNew(ciphertext)
	*plaintextHandle = C.uint64_t(insertObject(plaintext))
	return status
}

//export CkksAdd
func CkksAdd(evaluatorHandle uint64, op0CiphertextHandle uint64, op1OperandHandle uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[ckks.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	var op1Operand rlwe.Operand
	switch operand := cgo.Handle(op1OperandHandle).Value().(type) {
	case *rlwe.Ciphertext:
		op1Operand = operand
	case *rlwe.Plaintext:
		if operand.IsRingT {
			plaintext := rlwe.NewPlaintext(evaluator.GetParameters(), op0Ciphertext.Level())
			plaintext.Scale = operand.Scale
			plaintext.IsBatched = operand.IsBatched
			plaintext.LogDimensions = operand.LogDimensions
			if err := evaluator.RingTToPt(operand, plaintext); err != nil {
				return errorStatus(err)
			}
			op1Operand = plaintext
		} else {
			op1Operand = operand
		}
	default:
		return errorStatus(fmt.Errorf("unsupported CKKS add operand type %T", operand))
	}
	opOutCiphertext, err := evaluator.AddNew(op0Ciphertext, op1Operand)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export CkksAddScalar
func CkksAddScalar(evaluatorHandle uint64, op0CiphertextHandle uint64, op1Real float64, op1Imag float64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[ckks.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	var scalar rlwe.Operand
	if op1Imag == 0 {
		scalar = op1Real
	} else {
		scalar = complex(op1Real, op1Imag)
	}
	opOutCiphertext, err := evaluator.AddNew(op0Ciphertext, scalar)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export CkksSub
func CkksSub(evaluatorHandle uint64, op0CiphertextHandle uint64, op1OperandHandle uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[ckks.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	var op1Operand rlwe.Operand
	switch operand := cgo.Handle(op1OperandHandle).Value().(type) {
	case *rlwe.Ciphertext:
		op1Operand = operand
	case *rlwe.Plaintext:
		if operand.IsRingT {
			plaintext := rlwe.NewPlaintext(evaluator.GetParameters(), op0Ciphertext.Level())
			plaintext.Scale = operand.Scale
			plaintext.IsBatched = operand.IsBatched
			plaintext.LogDimensions = operand.LogDimensions
			if err := evaluator.RingTToPt(operand, plaintext); err != nil {
				return errorStatus(err)
			}
			op1Operand = plaintext
		} else {
			op1Operand = operand
		}
	default:
		return errorStatus(fmt.Errorf("unsupported CKKS sub operand type %T", operand))
	}
	opOutCiphertext, err := evaluator.SubNew(op0Ciphertext, op1Operand)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export CkksSubScalar
func CkksSubScalar(evaluatorHandle uint64, op0CiphertextHandle uint64, op1Real float64, op1Imag float64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[ckks.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	var scalar rlwe.Operand
	if op1Imag == 0 {
		scalar = op1Real
	} else {
		scalar = complex(op1Real, op1Imag)
	}
	opOutCiphertext, err := evaluator.SubNew(op0Ciphertext, scalar)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export CkksMul
func CkksMul(evaluatorHandle uint64, op0CiphertextHandle uint64, op1OperandHandle uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[ckks.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	var op1Operand rlwe.Operand
	switch operand := cgo.Handle(op1OperandHandle).Value().(type) {
	case *rlwe.Ciphertext:
		op1Operand = operand
	case *rlwe.Plaintext:
		if operand.IsRingT {
			plaintext := rlwe.NewPlaintext(evaluator.GetParameters(), op0Ciphertext.Level())
			plaintext.Scale = operand.Scale
			plaintext.IsBatched = operand.IsBatched
			plaintext.LogDimensions = operand.LogDimensions
			if err := evaluator.RingTToPt(operand, plaintext); err != nil {
				return errorStatus(err)
			}
			op1Operand = plaintext
		} else {
			op1Operand = operand
		}
	default:
		return errorStatus(fmt.Errorf("unsupported CKKS mul operand type %T", operand))
	}
	opOutCiphertext, err := evaluator.MulNew(op0Ciphertext, op1Operand)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export CkksMulScalar
func CkksMulScalar(evaluatorHandle uint64, op0CiphertextHandle uint64, op1Real float64, op1Imag float64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[ckks.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	var scalar rlwe.Operand
	if op1Imag == 0 {
		scalar = op1Real
	} else {
		scalar = complex(op1Real, op1Imag)
	}
	opOutCiphertext, err := evaluator.MulNew(op0Ciphertext, scalar)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export CkksRelinearize
func CkksRelinearize(evaluatorHandle uint64, op0CiphertextHandle uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[ckks.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext, err := evaluator.RelinearizeNew(op0Ciphertext)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export CkksDropLevel
func CkksDropLevel(evaluatorHandle uint64, op0CiphertextHandle uint64, levels int32, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[ckks.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext := evaluator.DropLevelNew(op0Ciphertext, int(levels))
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export CkksRescale
func CkksRescale(evaluatorHandle uint64, op0CiphertextHandle uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[ckks.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext := ckks.NewCiphertext(*evaluator.GetParameters(), op0Ciphertext.Degree(), op0Ciphertext.Level())
	if err := evaluator.Rescale(op0Ciphertext, opOutCiphertext); err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

func getGLKCol(step int32) (glkColPosIdx []int, glkColNegIdx []int) {
	convertToNAF := func(x int32) (string, string) {
		xh := x >> 1
		x3 := x + xh
		c := xh ^ x3
		nPos := x3 & c
		nNeg := xh & c
		return strconv.FormatInt(int64(nPos), 2), strconv.FormatInt(int64(nNeg), 2)
	}

	rPos, rNeg := convertToNAF(step)
	for idx, digit := range rPos {
		if digit == '0' {
			continue
		}
		glkColPosIdx = append(glkColPosIdx, len(rPos)-idx-1)
	}
	for idx, digit := range rNeg {
		if digit == '0' {
			continue
		}
		glkColNegIdx = append(glkColNegIdx, len(rNeg)-idx-1)
	}
	return
}

//export CkksRotate
func CkksRotate(evaluatorHandle uint64, op0CiphertextHandle uint64, steps *C.int32_t, length int, useDefaultRotationKeys C.uint8_t, opOutCiphertextHandles *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if length < 0 {
		return errorStatus(fmt.Errorf("rotation count cannot be negative"))
	}
	if length != 0 && steps == nil {
		return errorStatus(fmt.Errorf("rotation input is not set"))
	}
	if length != 0 && opOutCiphertextHandles == nil {
		return errorStatus(fmt.Errorf("rotation output is not set"))
	}

	evaluator := getObject[ckks.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	rotationSteps := unsafe.Slice((*int32)(steps), length)
	opOutHandles := unsafe.Slice((*uint64)(opOutCiphertextHandles), length)

	if useDefaultRotationKeys == 0 {
		rotations := make([]int, length)
		for i, step := range rotationSteps {
			rotations[i] = int(step)
		}
		opOutCiphertexts, err := evaluator.RotateHoistedNew(op0Ciphertext, rotations)
		if err != nil {
			return errorStatus(err)
		}
		for i, step := range rotations {
			opOutHandles[i] = insertObject(opOutCiphertexts[step])
		}
		return status
	}

	rotatedInput := map[int]*rlwe.Ciphertext{0: op0Ciphertext}
	for i, step := range rotationSteps {
		glkColPosIdx, glkColNegIdx := getGLKCol(step)
		subSteps := make([]int, 0, len(glkColPosIdx)+len(glkColNegIdx))
		for _, idx := range glkColPosIdx {
			subSteps = append(subSteps, 1<<idx)
		}
		for _, idx := range glkColNegIdx {
			subSteps = append(subSteps, -1*(1<<idx))
		}

		subStepsSum := 0
		for _, subStep := range subSteps {
			nextStep := subStepsSum + subStep
			if _, ok := rotatedInput[nextStep]; !ok {
				rotatedCiphertext, err := evaluator.RotateNew(rotatedInput[subStepsSum], subStep)
				if err != nil {
					return errorStatus(err)
				}
				rotatedInput[nextStep] = rotatedCiphertext
			}
			subStepsSum = nextStep
		}
		opOutHandles[i] = insertObject(rotatedInput[subStepsSum])
	}
	return status
}

//export CkksConjugate
func CkksConjugate(evaluatorHandle uint64, op0CiphertextHandle uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[ckks.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext, err := evaluator.ConjugateNew(op0Ciphertext)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export CkksPolyEvalStepFunction
func CkksPolyEvalStepFunction(evaluatorHandle uint64, ciphertextHandle uint64, a float64, b float64, degree int, threshold float64) uint64 {
	return 0
}
