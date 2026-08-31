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
	"unsafe"

	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/examples"
	"github.com/cipherflow-fhe/lattigo/schemes/bgv"
)

// ─── BfvParameter ────────────────────────────────────────────────────────────

//export CreateBfvDefaultParameter
func CreateBfvDefaultParameter(logN int, T uint64, parameterHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	var literal bgv.ParametersLiteral
	switch logN {
	case 12:
		literal = examples.BGVScaleInvariantParamsN12QP109
	case 13:
		literal = examples.BGVScaleInvariantParamsN13QP218
	case 14:
		literal = examples.BGVScaleInvariantParamsN14QP438
	case 15:
		literal = examples.BGVScaleInvariantParamsN15QP880
	default:
		return errorStatus(fmt.Errorf("LogN not supported"))
	}
	literal.PlaintextModulus = T

	params, err := bgv.NewParametersFromLiteral(literal)
	if err != nil {
		return errorStatus(err)
	}
	*parameterHandle = C.uint64_t(insertObject(&params))
	return status
}

//export CreateBfvCustomParameter
func CreateBfvCustomParameter(logN int, T uint64, q *C.uint64_t, qLen int, p *C.uint64_t, pLen int, parameterHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	qSlice := unsafe.Slice((*uint64)(q), qLen)
	pSlice := unsafe.Slice((*uint64)(p), pLen)

	literal := bgv.ParametersLiteral{
		LogN:             logN,
		Q:                append([]uint64(nil), qSlice...),
		P:                append([]uint64(nil), pSlice...),
		PlaintextModulus: T,
	}

	params, err := bgv.NewParametersFromLiteral(literal)
	if err != nil {
		return errorStatus(err)
	}
	*parameterHandle = C.uint64_t(insertObject(&params))
	return status
}

//export CopyBfvParameter
func CopyBfvParameter(parameterHandle uint64, targetHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := *getObject[bgv.Parameters](parameterHandle)
	*targetHandle = C.uint64_t(insertObject(&params))
	return status
}

//export SerializeBfvParameter
func SerializeBfvParameter(parameterHandle uint64, rawData **byte, length *C.uint64_t, dataHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[bgv.Parameters](parameterHandle)
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

//export DeserializeBfvParameter
func DeserializeBfvParameter(rawData *byte, length C.uint64_t, parameterHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if rawData == nil && length != 0 {
		return errorStatus(fmt.Errorf("BFV parameter data is nil"))
	}

	var data []byte
	if length != 0 {
		data = unsafe.Slice(rawData, int(length))
	}

	params := new(bgv.Parameters)
	if err := params.UnmarshalBinary(data); err != nil {
		return errorStatus(err)
	}
	*parameterHandle = C.uint64_t(insertObject(params))
	return status
}

//export PrintBfvParameter
func PrintBfvParameter(parameterHandle uint64) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[bgv.Parameters](parameterHandle)
	fmt.Println(*params)
	return status
}

//export GetBfvN
func GetBfvN(parameterHandle uint64, n *C.int) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[bgv.Parameters](parameterHandle)
	*n = C.int(params.N())
	return status
}

//export GetBfvLogN
func GetBfvLogN(parameterHandle uint64, logN *C.int) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[bgv.Parameters](parameterHandle)
	*logN = C.int(params.LogN())
	return status
}

//export GetBfvMaxLevel
func GetBfvMaxLevel(parameterHandle uint64, maxLevel *C.int) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[bgv.Parameters](parameterHandle)
	*maxLevel = C.int(params.MaxLevel())
	return status
}

//export GetBfvQ
func GetBfvQ(parameterHandle uint64, rawData *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[bgv.Parameters](parameterHandle)
	q := params.Q()
	if len(q) != 0 {
		copy(unsafe.Slice((*uint64)(rawData), len(q)), q)
	}
	return status
}

//export GetBfvP
func GetBfvP(parameterHandle uint64, rawData *C.uint64_t, length *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[bgv.Parameters](parameterHandle)
	p := params.P()
	requiredLength := C.uint64_t(len(p))
	if rawData == nil {
		*length = requiredLength
		return status
	}
	if *length < requiredLength {
		*length = requiredLength
		return errorStatus(fmt.Errorf("GetBfvP buffer too small"))
	}
	if len(p) != 0 {
		copy(unsafe.Slice((*uint64)(rawData), len(p)), p)
	}
	*length = requiredLength
	return status
}

//export GetBfvT
func GetBfvT(parameterHandle uint64, t *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[bgv.Parameters](parameterHandle)
	*t = C.uint64_t(params.PlaintextModulus())
	return status
}

// ─── BfvEncoder ──────────────────────────────────────────────────────────────

//export CreateBfvEncoder
func CreateBfvEncoder(parameterHandle uint64, encoderHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[bgv.Parameters](parameterHandle)
	encoder := bgv.NewEncoder(*params)
	*encoderHandle = C.uint64_t(insertObject(encoder))
	return status
}

// ─── BfvEvaluator ────────────────────────────────────────────────────────────

//export CreateBfvEvaluator
func CreateBfvEvaluator(parameterHandle uint64, evaluationKeySetHandle uint64, evaluatorHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObject[bgv.Parameters](parameterHandle)

	evaluationKeySet := getObject[rlwe.MemEvaluationKeySet](evaluationKeySetHandle)
	evaluator := bgv.NewEvaluator(*params, evaluationKeySet, true)
	*evaluatorHandle = C.uint64_t(insertObject(evaluator))
	return status
}

//export SetBfvEvaluatorEvaluationKeySet
func SetBfvEvaluatorEvaluationKeySet(evaluatorHandle uint64, evaluationKeySetHandle uint64) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	evaluationKeySet := getObject[rlwe.MemEvaluationKeySet](evaluationKeySetHandle)
	*evaluator = *evaluator.WithKey(evaluationKeySet)
	return status
}

// ─── BfvCiphertext ───────────────────────────────────────────────────────────

//export CopyBfvCiphertext
func CopyBfvCiphertext(ciphertextHandle uint64) uint64 {
	ciphertext := getObject[rlwe.Ciphertext](ciphertextHandle)
	return insertObject(ciphertext.CopyNew())
}

//export CopyBfvCiphertextTo
func CopyBfvCiphertextTo(xCiphertextHandle uint64, yCiphertextHandle uint64) uint64 {
	src := getObject[rlwe.Ciphertext](xCiphertextHandle)
	dst := getObject[rlwe.Ciphertext](yCiphertextHandle)
	dst.Copy(src)
	return yCiphertextHandle
}

// ─── BfvContext ──────────────────────────────────────────────────────────────

//export BfvEncode
func BfvEncode(encoderHandle uint64, messageArray *C.uint64_t, messageLen int, plaintextHandle uint64) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	encoder := getObject[bgv.Encoder](encoderHandle)
	plaintext := getObject[rlwe.Plaintext](plaintextHandle)
	message := unsafe.Slice((*uint64)(messageArray), messageLen)
	if err := encoder.Encode(message, plaintext); err != nil {
		return errorStatus(err)
	}
	return status
}

//export BfvDecode
func BfvDecode(encoderHandle uint64, plaintextHandle uint64, rawData **C.uint64_t, length *C.uint64_t, dataHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	encoder := getObject[bgv.Encoder](encoderHandle)
	plaintext := getObject[rlwe.Plaintext](plaintextHandle)

	valueCount := encoder.GetRLWEParameters().N()
	message := make([]uint64, valueCount)
	if err := encoder.Decode(plaintext, message); err != nil {
		return errorStatus(err)
	}

	*length = C.uint64_t(valueCount)
	if len(message) == 0 {
		*rawData = nil
	} else {
		*rawData = (*C.uint64_t)(unsafe.Pointer(&message[0]))
	}
	*dataHandle = C.uint64_t(insertObject(message))
	return status
}

//export BfvEncrypt
func BfvEncrypt(encryptorHandle uint64, plaintextHandle uint64, ciphertextHandle *C.uint64_t) (status C.ErrorStatus) {
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

//export BfvDecrypt
func BfvDecrypt(decryptorHandle uint64, ciphertextHandle uint64, plaintextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	decryptor := getObject[rlwe.Decryptor](decryptorHandle)
	ciphertext := getObject[rlwe.Ciphertext](ciphertextHandle)
	plaintext := decryptor.DecryptNew(ciphertext)
	*plaintextHandle = C.uint64_t(insertObject(plaintext))
	return status
}

//export BfvAdd
func BfvAdd(evaluatorHandle uint64, op0CiphertextHandle uint64, op1OperandHandle uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
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
			evaluator.RingT2Q(op0Ciphertext.Level(), true, operand.Value, plaintext.Value)
			if plaintext.IsNTT {
				evaluator.GetParameters().RingQ().AtLevel(op0Ciphertext.Level()).NTT(plaintext.Value, plaintext.Value)
			}
			op1Operand = plaintext
		} else {
			op1Operand = operand
		}
	default:
		return errorStatus(fmt.Errorf("unsupported BFV add operand type %T", operand))
	}
	opOutCiphertext, err := evaluator.AddNew(op0Ciphertext, op1Operand)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvAddScalarInt
func BfvAddScalarInt(evaluatorHandle uint64, op0CiphertextHandle uint64, op1Value int, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext, err := evaluator.AddNew(op0Ciphertext, op1Value)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvAddScalar
func BfvAddScalar(evaluatorHandle uint64, op0CiphertextHandle uint64, op1Value int64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext, err := evaluator.AddNew(op0Ciphertext, op1Value)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvAddScalarUint
func BfvAddScalarUint(evaluatorHandle uint64, op0CiphertextHandle uint64, op1Value uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext, err := evaluator.AddNew(op0Ciphertext, op1Value)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvSub
func BfvSub(evaluatorHandle uint64, op0CiphertextHandle uint64, op1OperandHandle uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
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
			evaluator.RingT2Q(op0Ciphertext.Level(), true, operand.Value, plaintext.Value)
			if plaintext.IsNTT {
				evaluator.GetParameters().RingQ().AtLevel(op0Ciphertext.Level()).NTT(plaintext.Value, plaintext.Value)
			}
			op1Operand = plaintext
		} else {
			op1Operand = operand
		}
	default:
		return errorStatus(fmt.Errorf("unsupported BFV sub operand type %T", operand))
	}
	opOutCiphertext, err := evaluator.SubNew(op0Ciphertext, op1Operand)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvSubScalarInt
func BfvSubScalarInt(evaluatorHandle uint64, op0CiphertextHandle uint64, op1Value int, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext, err := evaluator.SubNew(op0Ciphertext, op1Value)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvSubScalar
func BfvSubScalar(evaluatorHandle uint64, op0CiphertextHandle uint64, op1Value int64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext, err := evaluator.SubNew(op0Ciphertext, op1Value)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvSubScalarUint
func BfvSubScalarUint(evaluatorHandle uint64, op0CiphertextHandle uint64, op1Value uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext, err := evaluator.SubNew(op0Ciphertext, op1Value)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvMult
func BfvMult(evaluatorHandle uint64, op0CiphertextHandle uint64, op1OperandHandle uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	var op1Operand rlwe.Operand
	switch operand := cgo.Handle(op1OperandHandle).Value().(type) {
	case *rlwe.Ciphertext:
		op1Operand = operand
	case *rlwe.Plaintext:
		if operand.IsRingT {
			opOutCiphertext := rlwe.NewCiphertext(evaluator.GetParameters(), op0Ciphertext.Degree(), op0Ciphertext.Level())
			opOutCiphertext.MetaData = op0Ciphertext.MetaData.CopyNew()
			opOutCiphertext.Scale = op0Ciphertext.Scale.Mul(operand.Scale)

			ringQ := evaluator.GetParameters().RingQ().AtLevel(op0Ciphertext.Level())
			plaintextNTT := ringQ.NewPoly()
			for i := range plaintextNTT.Coeffs {
				copy(plaintextNTT.Coeffs[i], operand.Value.Coeffs[0])
			}
			ringQ.NTT(plaintextNTT, plaintextNTT)
			ringQ.MForm(plaintextNTT, plaintextNTT)
			for i := range opOutCiphertext.Value {
				ringQ.MulCoeffsMontgomery(op0Ciphertext.Value[i], plaintextNTT, opOutCiphertext.Value[i])
			}

			*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
			return status
		}
		op1Operand = operand
	default:
		return errorStatus(fmt.Errorf("unsupported BFV mult operand type %T", operand))
	}
	opOutCiphertext, err := evaluator.MulNew(op0Ciphertext, op1Operand)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvMultScalarInt
func BfvMultScalarInt(evaluatorHandle uint64, op0CiphertextHandle uint64, op1Value int, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext, err := evaluator.MulNew(op0Ciphertext, op1Value)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvMultScalar
func BfvMultScalar(evaluatorHandle uint64, op0CiphertextHandle uint64, op1Value int64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext, err := evaluator.MulNew(op0Ciphertext, op1Value)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvMultScalarUint
func BfvMultScalarUint(evaluatorHandle uint64, op0CiphertextHandle uint64, op1Value uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext, err := evaluator.MulNew(op0Ciphertext, op1Value)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvRelinearize
func BfvRelinearize(evaluatorHandle uint64, op0CiphertextHandle uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext, err := evaluator.RelinearizeNew(op0Ciphertext)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvDropLevel
func BfvDropLevel(evaluatorHandle uint64, op0CiphertextHandle uint64, levels int32, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	opOutCiphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle).CopyNew()
	evaluator.DropLevel(opOutCiphertext, int(levels))
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvRescale
func BfvRescale(evaluatorHandle uint64, op0CiphertextHandle uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext := op0Ciphertext.CopyNew()
	if err := evaluator.RescaleScaleInvariant(op0Ciphertext, opOutCiphertext); err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}

//export BfvRotateColumns
func BfvRotateColumns(evaluatorHandle uint64, op0CiphertextHandle uint64, steps *C.int32_t, length int, useDefaultRotationKeys C.uint8_t, opOutCiphertextHandles *C.uint64_t) (status C.ErrorStatus) {
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

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
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
		for i, step := range rotationSteps {
			opOutHandles[i] = insertObject(opOutCiphertexts[int(step)])
		}
		return status
	}

	rotatedInput := map[int]*rlwe.Ciphertext{0: op0Ciphertext}
	targetSubSteps := make([][]int, length)
	for i, step := range rotationSteps {
		glkColPosIdx, glkColNegIdx := getGLKCol(step)
		subSteps := make([]int, 0, len(glkColPosIdx)+len(glkColNegIdx))
		for _, idx := range glkColPosIdx {
			subSteps = append(subSteps, 1<<idx)
		}
		for _, idx := range glkColNegIdx {
			subSteps = append(subSteps, -1*(1<<idx))
		}
		targetSubSteps[i] = subSteps
	}

	for {
		rotationsBySource := make(map[int]map[int]struct{})
		for _, subSteps := range targetSubSteps {
			currentStep := 0
			for _, subStep := range subSteps {
				nextStep := currentStep + subStep
				if _, ok := rotatedInput[nextStep]; ok {
					currentStep = nextStep
					continue
				}
				if _, ok := rotatedInput[currentStep]; ok {
					if rotationsBySource[currentStep] == nil {
						rotationsBySource[currentStep] = make(map[int]struct{})
					}
					rotationsBySource[currentStep][subStep] = struct{}{}
				}
				break
			}
		}
		if len(rotationsBySource) == 0 {
			break
		}

		for sourceStep, rotationSet := range rotationsBySource {
			rotations := make([]int, 0, len(rotationSet))
			for rotation := range rotationSet {
				rotations = append(rotations, rotation)
			}
			opOutCiphertexts, err := evaluator.RotateHoistedNew(rotatedInput[sourceStep], rotations)
			if err != nil {
				return errorStatus(err)
			}
			for _, rotation := range rotations {
				rotatedInput[sourceStep+rotation] = opOutCiphertexts[rotation]
			}
		}
	}

	for i, subSteps := range targetSubSteps {
		subStepsSum := 0
		for _, subStep := range subSteps {
			subStepsSum += subStep
		}
		opOutHandles[i] = insertObject(rotatedInput[subStepsSum])
	}
	return status
}

//export BfvRotateRows
func BfvRotateRows(evaluatorHandle uint64, op0CiphertextHandle uint64, opOutCiphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluator := getObject[bgv.Evaluator](evaluatorHandle)
	op0Ciphertext := getObject[rlwe.Ciphertext](op0CiphertextHandle)
	opOutCiphertext, err := evaluator.RotateRowsNew(op0Ciphertext)
	if err != nil {
		return errorStatus(err)
	}
	*opOutCiphertextHandle = C.uint64_t(insertObject(opOutCiphertext))
	return status
}
