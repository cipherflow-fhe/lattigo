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

typedef struct Metadata {
    uint8_t is_ringt;
    uint8_t is_batched;
    int degree;
    int level;
    int log_slots;
    double scale;
} Metadata;
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/cipherflow-fhe/lattigo/core/rlwe"
)

func okStatus() C.ErrorStatus {
	return C.ErrorStatus{code: 0, message: nil}
}

func errorStatus(err error) C.ErrorStatus {
	return C.ErrorStatus{code: 1, message: C.CString(err.Error())}
}

func recoverStatus(status *C.ErrorStatus) {
	if r := recover(); r != nil {
		*status = errorStatus(fmt.Errorf("%v", r))
	}
}

//export FreeGoString
func FreeGoString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

type logMaxSlotsProvider interface {
	LogMaxSlots() int
}

//export NewPlaintext
func NewPlaintext(parameterHandle uint64, metadata *C.Metadata, plaintextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObjectAs[rlwe.ParameterProvider](parameterHandle)
	level := int(metadata.level)
	if metadata.is_ringt != 0 {
		level = 0
	}
	plaintext := rlwe.NewPlaintext(params, level)
	plaintext.IsRingT = metadata.is_ringt != 0
	if plaintext.IsRingT {
		plaintext.IsNTT = false
		plaintext.IsMontgomery = false
	}
	plaintext.IsBatched = metadata.is_batched != 0
	scale := float64(metadata.scale)
	if scale == 0 {
		scale = 1.0
	}
	plaintext.Scale = params.GetRLWEParameters().NewScale(scale)

	logSlots := int(metadata.log_slots)
	maxLogSlots := params.GetRLWEParameters().LogN()
	if p, ok := params.(logMaxSlotsProvider); ok {
		maxLogSlots = p.LogMaxSlots()
	}
	if logSlots > maxLogSlots {
		return errorStatus(fmt.Errorf("log_slots %d exceeds max %d", logSlots, maxLogSlots))
	}
	plaintext.LogDimensions.Rows = 0
	plaintext.LogDimensions.Cols = logSlots

	*plaintextHandle = C.uint64_t(insertObject(plaintext))
	return status
}

//export GetPlaintextMetadata
func GetPlaintextMetadata(plaintextHandle uint64, metadata *C.Metadata) {
	plaintext := getObject[rlwe.Plaintext](plaintextHandle)
	if plaintext.IsRingT {
		metadata.is_ringt = 1
	} else {
		metadata.is_ringt = 0
	}
	if plaintext.IsBatched {
		metadata.is_batched = 1
	} else {
		metadata.is_batched = 0
	}
	metadata.degree = 0
	metadata.level = C.int(plaintext.Level())
	metadata.log_slots = C.int(plaintext.LogSlots())
	metadata.scale = C.double(plaintext.Scale.Float64())
}

//export GetPlaintextScale
func GetPlaintextScale(plaintextHandle uint64) float64 {
	plaintext := getObject[rlwe.Plaintext](plaintextHandle)
	return plaintext.Scale.Float64()
}

//export SerializePlaintext
func SerializePlaintext(plaintextHandle uint64, rawData **byte, length *C.uint64_t, dataHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	plaintext := getObject[rlwe.Plaintext](plaintextHandle)
	data, err := plaintext.MarshalBinary()
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

//export DeserializePlaintext
func DeserializePlaintext(rawData *byte, length C.uint64_t, plaintextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if rawData == nil && length != 0 {
		return errorStatus(fmt.Errorf("plaintext data is nil"))
	}

	var data []byte
	if length != 0 {
		data = unsafe.Slice(rawData, int(length))
	}

	plaintext := new(rlwe.Plaintext)
	if err := plaintext.UnmarshalBinary(data); err != nil {
		return errorStatus(err)
	}
	*plaintextHandle = C.uint64_t(insertObject(plaintext))
	return status
}

//export NewCiphertext
func NewCiphertext(parameterHandle uint64, degree int, level int, ciphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObjectAs[rlwe.ParameterProvider](parameterHandle)
	ciphertext := rlwe.NewCiphertext(params, degree, level)
	*ciphertextHandle = C.uint64_t(insertObject(ciphertext))
	return status
}

//export GetCiphertextDegree
func GetCiphertextDegree(ciphertextHandle uint64) int {
	ciphertext := getObject[rlwe.Ciphertext](ciphertextHandle)
	return ciphertext.Degree()
}

//export GetCiphertextMetadata
func GetCiphertextMetadata(ciphertextHandle uint64, metadata *C.Metadata) {
	ciphertext := getObject[rlwe.Ciphertext](ciphertextHandle)
	metadata.is_ringt = 0
	if ciphertext.IsBatched {
		metadata.is_batched = 1
	} else {
		metadata.is_batched = 0
	}
	metadata.degree = C.int(ciphertext.Degree())
	metadata.level = C.int(ciphertext.Level())
	metadata.log_slots = C.int(ciphertext.LogSlots())
	metadata.scale = C.double(ciphertext.Scale.Float64())
}

//export GetCiphertextScale
func GetCiphertextScale(ciphertextHandle uint64) float64 {
	ciphertext := getObject[rlwe.Ciphertext](ciphertextHandle)
	return ciphertext.Scale.Float64()
}

//export SetCiphertextScale
func SetCiphertextScale(ciphertextHandle uint64, scaleIn float64) float64 {
	ciphertext := getObject[rlwe.Ciphertext](ciphertextHandle)
	ciphertext.Scale = rlwe.NewScale(scaleIn)
	return ciphertext.Scale.Float64()
}

//export SerializeCiphertext
func SerializeCiphertext(ciphertextHandle uint64, rawData **byte, length *C.uint64_t, dataHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	ciphertext := getObject[rlwe.Ciphertext](ciphertextHandle)
	data, err := ciphertext.MarshalBinary()
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

//export DeserializeCiphertext
func DeserializeCiphertext(rawData *byte, length C.uint64_t, ciphertextHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if rawData == nil && length != 0 {
		return errorStatus(fmt.Errorf("ciphertext data is nil"))
	}

	var data []byte
	if length != 0 {
		data = unsafe.Slice(rawData, int(length))
	}

	ciphertext := new(rlwe.Ciphertext)
	if err := ciphertext.UnmarshalBinary(data); err != nil {
		return errorStatus(err)
	}
	*ciphertextHandle = C.uint64_t(insertObject(ciphertext))
	return status
}

//export CreateKeyGenerator
func CreateKeyGenerator(parameterHandle uint64, keyGeneratorHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObjectAs[rlwe.ParameterProvider](parameterHandle)
	keyGenerator := rlwe.NewKeyGenerator(params)
	*keyGeneratorHandle = C.uint64_t(insertObject(keyGenerator))
	return status
}

//export GenSecretKey
func GenSecretKey(keyGeneratorHandle uint64, secretKeyHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	keyGenerator := getObject[rlwe.KeyGenerator](keyGeneratorHandle)
	secretKey := keyGenerator.GenSecretKeyNew()
	*secretKeyHandle = C.uint64_t(insertObject(secretKey))
	return status
}

//export GenPublicKey
func GenPublicKey(keyGeneratorHandle uint64, secretKeyHandle uint64, publicKeyHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	keyGenerator := getObject[rlwe.KeyGenerator](keyGeneratorHandle)
	secretKey := getObject[rlwe.SecretKey](secretKeyHandle)
	publicKey := keyGenerator.GenPublicKeyNew(secretKey)
	*publicKeyHandle = C.uint64_t(insertObject(publicKey))
	return status
}

//export SerializeSecretKey
func SerializeSecretKey(secretKeyHandle uint64, rawData **byte, length *C.uint64_t, dataHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	secretKey := getObject[rlwe.SecretKey](secretKeyHandle)
	data, err := secretKey.MarshalBinary()
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

//export DeserializeSecretKey
func DeserializeSecretKey(rawData *byte, length C.uint64_t, secretKeyHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if rawData == nil && length != 0 {
		return errorStatus(fmt.Errorf("secret key data is nil"))
	}

	var data []byte
	if length != 0 {
		data = unsafe.Slice(rawData, int(length))
	}

	secretKey := new(rlwe.SecretKey)
	if err := secretKey.UnmarshalBinary(data); err != nil {
		return errorStatus(err)
	}
	*secretKeyHandle = C.uint64_t(insertObject(secretKey))
	return status
}

//export SerializePublicKey
func SerializePublicKey(publicKeyHandle uint64, rawData **byte, length *C.uint64_t, dataHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	publicKey := getObject[rlwe.PublicKey](publicKeyHandle)
	data, err := publicKey.MarshalBinary()
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

//export DeserializePublicKey
func DeserializePublicKey(rawData *byte, length C.uint64_t, publicKeyHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if rawData == nil && length != 0 {
		return errorStatus(fmt.Errorf("public key data is nil"))
	}

	var data []byte
	if length != 0 {
		data = unsafe.Slice(rawData, int(length))
	}

	publicKey := new(rlwe.PublicKey)
	if err := publicKey.UnmarshalBinary(data); err != nil {
		return errorStatus(err)
	}
	*publicKeyHandle = C.uint64_t(insertObject(publicKey))
	return status
}

//export CreateEncryptorFromSecretKey
func CreateEncryptorFromSecretKey(parameterHandle uint64, secretKeyHandle uint64, encryptorHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObjectAs[rlwe.ParameterProvider](parameterHandle)
	secretKey := getObject[rlwe.SecretKey](secretKeyHandle)
	encryptor := rlwe.NewEncryptor(params, secretKey)
	*encryptorHandle = C.uint64_t(insertObject(encryptor))
	return status
}

//export CreateEncryptorFromPublicKey
func CreateEncryptorFromPublicKey(parameterHandle uint64, publicKeyHandle uint64, encryptorHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObjectAs[rlwe.ParameterProvider](parameterHandle)
	publicKey := getObject[rlwe.PublicKey](publicKeyHandle)
	encryptor := rlwe.NewEncryptor(params, publicKey)
	*encryptorHandle = C.uint64_t(insertObject(encryptor))
	return status
}

//export CreateDecryptor
func CreateDecryptor(parameterHandle uint64, secretKeyHandle uint64, decryptorHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	params := getObjectAs[rlwe.ParameterProvider](parameterHandle)
	secretKey := getObject[rlwe.SecretKey](secretKeyHandle)
	decryptor := rlwe.NewDecryptor(params, secretKey)
	*decryptorHandle = C.uint64_t(insertObject(decryptor))
	return status
}

//export GenRelinearizationKey
func GenRelinearizationKey(keyGeneratorHandle uint64, secretKeyHandle uint64, level int, relinearizationKeyHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	keyGenerator := getObject[rlwe.KeyGenerator](keyGeneratorHandle)
	secretKey := getObject[rlwe.SecretKey](secretKeyHandle)
	var evaluationKeyParameters []rlwe.EvaluationKeyParameters
	if level >= 0 {
		levelQ := level
		evaluationKeyParameters = []rlwe.EvaluationKeyParameters{{LevelQ: &levelQ}}
	}
	relinearizationKey := keyGenerator.GenRelinearizationKeyNew(secretKey, evaluationKeyParameters...)
	*relinearizationKeyHandle = C.uint64_t(insertObject(relinearizationKey))
	return status
}

func genGaloisKeys(keyGeneratorHandle uint64, secretKeyHandle uint64, galoisElementList []uint64, level int, galoisKeyHandles *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if len(galoisElementList) != 0 && galoisKeyHandles == nil {
		return errorStatus(fmt.Errorf("galois key handle output is not set"))
	}

	keyGenerator := getObject[rlwe.KeyGenerator](keyGeneratorHandle)
	secretKey := getObject[rlwe.SecretKey](secretKeyHandle)
	var evaluationKeyParameters []rlwe.EvaluationKeyParameters
	if level >= 0 {
		levelQ := level
		evaluationKeyParameters = []rlwe.EvaluationKeyParameters{{LevelQ: &levelQ}}
	}
	handles := unsafe.Slice((*uint64)(galoisKeyHandles), len(galoisElementList))
	for i, galoisElement := range galoisElementList {
		galoisKey := keyGenerator.GenGaloisKeyNew(galoisElement, secretKey, evaluationKeyParameters...)
		handles[i] = insertObject(galoisKey)
	}
	return status
}

//export GenGaloisKeysForRotations
func GenGaloisKeysForRotations(keyGeneratorHandle uint64, secretKeyHandle uint64, rotations *C.int32_t, rotationCount int, includeConjugation bool, level int, galoisElements *C.uint64_t, galoisKeyHandles *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if rotationCount < 0 {
		return errorStatus(fmt.Errorf("rotation count cannot be negative"))
	}
	if rotationCount != 0 && rotations == nil {
		return errorStatus(fmt.Errorf("rotation input is not set"))
	}

	keyGenerator := getObject[rlwe.KeyGenerator](keyGeneratorHandle)
	params := keyGenerator.GetRLWEParameters()
	galoisElementList := make([]uint64, 0, rotationCount+1)
	for _, rotation := range unsafe.Slice((*int32)(rotations), rotationCount) {
		galoisElementList = append(galoisElementList, params.GaloisElement(int(rotation)))
	}
	if includeConjugation {
		galoisElementList = append(galoisElementList, params.GaloisElementOrderTwoOrthogonalSubgroup())
	}
	if len(galoisElementList) != 0 && galoisElements == nil {
		return errorStatus(fmt.Errorf("galois element output is not set"))
	}
	if len(galoisElementList) != 0 {
		copy(unsafe.Slice((*uint64)(galoisElements), len(galoisElementList)), galoisElementList)
	}
	return genGaloisKeys(keyGeneratorHandle, secretKeyHandle, galoisElementList, level, galoisKeyHandles)
}

//export CopyEvaluationKey
func CopyEvaluationKey(evaluationKeyHandle uint64, targetHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluationKey := *getObject[rlwe.EvaluationKey](evaluationKeyHandle)
	*targetHandle = C.uint64_t(insertObject(&evaluationKey))
	return status
}

//export SerializeEvaluationKey
func SerializeEvaluationKey(evaluationKeyHandle uint64, rawData **byte, length *C.uint64_t, dataHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluationKey := getObject[rlwe.EvaluationKey](evaluationKeyHandle)
	data, err := evaluationKey.MarshalBinary()
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

//export DeserializeEvaluationKey
func DeserializeEvaluationKey(rawData *byte, length C.uint64_t, evaluationKeyHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if rawData == nil && length != 0 {
		return errorStatus(fmt.Errorf("evaluation key data is nil"))
	}

	var data []byte
	if length != 0 {
		data = unsafe.Slice(rawData, int(length))
	}

	evaluationKey := new(rlwe.EvaluationKey)
	if err := evaluationKey.UnmarshalBinary(data); err != nil {
		return errorStatus(err)
	}
	*evaluationKeyHandle = C.uint64_t(insertObject(evaluationKey))
	return status
}

//export CopyRelinearizationKey
func CopyRelinearizationKey(relinearizationKeyHandle uint64, targetHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	relinearizationKey := *getObject[rlwe.RelinearizationKey](relinearizationKeyHandle)
	*targetHandle = C.uint64_t(insertObject(&relinearizationKey))
	return status
}

//export GetRelinearizationKeyLevel
func GetRelinearizationKeyLevel(relinearizationKeyHandle uint64, level *C.int) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	relinearizationKey := getObject[rlwe.RelinearizationKey](relinearizationKeyHandle)
	*level = C.int(relinearizationKey.LevelQ())
	return status
}

//export SerializeRelinearizationKey
func SerializeRelinearizationKey(relinearizationKeyHandle uint64, rawData **byte, length *C.uint64_t, dataHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	relinearizationKey := getObject[rlwe.RelinearizationKey](relinearizationKeyHandle)
	data, err := relinearizationKey.MarshalBinary()
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

//export DeserializeRelinearizationKey
func DeserializeRelinearizationKey(rawData *byte, length C.uint64_t, relinearizationKeyHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if rawData == nil && length != 0 {
		return errorStatus(fmt.Errorf("relinearization key data is nil"))
	}

	var data []byte
	if length != 0 {
		data = unsafe.Slice(rawData, int(length))
	}

	relinearizationKey := new(rlwe.RelinearizationKey)
	if err := relinearizationKey.UnmarshalBinary(data); err != nil {
		return errorStatus(err)
	}
	*relinearizationKeyHandle = C.uint64_t(insertObject(relinearizationKey))
	return status
}

//export CopyGaloisKey
func CopyGaloisKey(galoisKeyHandle uint64, targetHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	galoisKey := *getObject[rlwe.GaloisKey](galoisKeyHandle)
	*targetHandle = C.uint64_t(insertObject(&galoisKey))
	return status
}

//export GetGaloisKeyElement
func GetGaloisKeyElement(galoisKeyHandle uint64, galoisElement *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	galoisKey := getObject[rlwe.GaloisKey](galoisKeyHandle)
	*galoisElement = C.uint64_t(galoisKey.GaloisElement)
	return status
}

//export GetGaloisKeyLevel
func GetGaloisKeyLevel(galoisKeyHandle uint64, level *C.int) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	galoisKey := getObject[rlwe.GaloisKey](galoisKeyHandle)
	*level = C.int(galoisKey.LevelQ())
	return status
}

//export SerializeGaloisKey
func SerializeGaloisKey(galoisKeyHandle uint64, rawData **byte, length *C.uint64_t, dataHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	galoisKey := getObject[rlwe.GaloisKey](galoisKeyHandle)
	data, err := galoisKey.MarshalBinary()
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

//export DeserializeGaloisKey
func DeserializeGaloisKey(rawData *byte, length C.uint64_t, galoisKeyHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if rawData == nil && length != 0 {
		return errorStatus(fmt.Errorf("galois key data is nil"))
	}

	var data []byte
	if length != 0 {
		data = unsafe.Slice(rawData, int(length))
	}

	galoisKey := new(rlwe.GaloisKey)
	if err := galoisKey.UnmarshalBinary(data); err != nil {
		return errorStatus(err)
	}
	*galoisKeyHandle = C.uint64_t(insertObject(galoisKey))
	return status
}

//export SerializeEvaluationKeySet
func SerializeEvaluationKeySet(evaluationKeySetHandle uint64, rawData **byte, length *C.uint64_t, dataHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluationKeySet := getObject[rlwe.MemEvaluationKeySet](evaluationKeySetHandle)
	data, err := evaluationKeySet.MarshalBinary()
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

//export DeserializeEvaluationKeySet
func DeserializeEvaluationKeySet(rawData *byte, length C.uint64_t, evaluationKeySetHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if rawData == nil && length != 0 {
		return errorStatus(fmt.Errorf("evaluation key set data is nil"))
	}

	var data []byte
	if length != 0 {
		data = unsafe.Slice(rawData, int(length))
	}

	evaluationKeySet := new(rlwe.MemEvaluationKeySet)
	if err := evaluationKeySet.UnmarshalBinary(data); err != nil {
		return errorStatus(err)
	}
	*evaluationKeySetHandle = C.uint64_t(insertObject(evaluationKeySet))
	return status
}

//export GetEvaluationKeyRelinearizationKey
func GetEvaluationKeyRelinearizationKey(evaluationKeySetHandle uint64, relinearizationKeyHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluationKeySet := getObject[rlwe.MemEvaluationKeySet](evaluationKeySetHandle)
	if evaluationKeySet.RelinearizationKey == nil {
		*relinearizationKeyHandle = 0
		return status
	}
	relinearizationKey := *evaluationKeySet.RelinearizationKey
	*relinearizationKeyHandle = C.uint64_t(insertObject(&relinearizationKey))
	return status
}

//export GetEvaluationKeyGaloisKeyCount
func GetEvaluationKeyGaloisKeyCount(evaluationKeySetHandle uint64, galoisKeyCount *C.int) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluationKeySet := getObject[rlwe.MemEvaluationKeySet](evaluationKeySetHandle)
	*galoisKeyCount = C.int(len(evaluationKeySet.GetGaloisKeysList()))
	return status
}

//export GetEvaluationKeyGaloisKeyElements
func GetEvaluationKeyGaloisKeyElements(evaluationKeySetHandle uint64, galoisElements *C.uint64_t, galoisKeyCount int) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluationKeySet := getObject[rlwe.MemEvaluationKeySet](evaluationKeySetHandle)
	galoisElementList := evaluationKeySet.GetGaloisKeysList()
	if galoisKeyCount < len(galoisElementList) {
		return errorStatus(fmt.Errorf("galois key output buffer is too small"))
	}
	if len(galoisElementList) != 0 {
		copy(unsafe.Slice((*uint64)(galoisElements), len(galoisElementList)), galoisElementList)
	}
	return status
}

//export GetEvaluationKeyGaloisKey
func GetEvaluationKeyGaloisKey(evaluationKeySetHandle uint64, galoisElement uint64, galoisKeyHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	evaluationKeySet := getObject[rlwe.MemEvaluationKeySet](evaluationKeySetHandle)
	galoisKey, err := evaluationKeySet.GetGaloisKey(galoisElement)
	if err != nil {
		return errorStatus(err)
	}
	galoisKeyCopy := *galoisKey
	*galoisKeyHandle = C.uint64_t(insertObject(&galoisKeyCopy))
	return status
}

//export SetEvaluationKeyRelinearizationKey
func SetEvaluationKeyRelinearizationKey(evaluationKeySetHandle uint64, relinearizationKeyHandle uint64) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	relinearizationKey := getObject[rlwe.RelinearizationKey](relinearizationKeyHandle)
	evaluationKeySet := getObject[rlwe.MemEvaluationKeySet](evaluationKeySetHandle)
	evaluationKeySet.RelinearizationKey = relinearizationKey
	return status
}

//export SetEvaluationKeyGaloisKey
func SetEvaluationKeyGaloisKey(evaluationKeySetHandle uint64, galoisKeyHandle uint64) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	galoisKey := getObject[rlwe.GaloisKey](galoisKeyHandle)
	evaluationKeySet := getObject[rlwe.MemEvaluationKeySet](evaluationKeySetHandle)
	if evaluationKeySet.GaloisKeys == nil {
		evaluationKeySet.GaloisKeys = map[uint64]*rlwe.GaloisKey{}
	}
	evaluationKeySet.GaloisKeys[galoisKey.GaloisElement] = galoisKey
	return status
}

//export SetEvaluationKeyGaloisKeys
func SetEvaluationKeyGaloisKeys(evaluationKeySetHandle uint64, galoisKeyHandles *C.uint64_t, galoisKeyCount int) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if galoisKeyCount < 0 {
		return errorStatus(fmt.Errorf("galois key count cannot be negative"))
	}
	if galoisKeyCount != 0 && galoisKeyHandles == nil {
		return errorStatus(fmt.Errorf("galois key input is not set"))
	}

	evaluationKeySet := getObject[rlwe.MemEvaluationKeySet](evaluationKeySetHandle)
	evaluationKeySet.GaloisKeys = map[uint64]*rlwe.GaloisKey{}
	for _, handle := range unsafe.Slice((*uint64)(galoisKeyHandles), galoisKeyCount) {
		galoisKey := getObject[rlwe.GaloisKey](handle)
		evaluationKeySet.GaloisKeys[galoisKey.GaloisElement] = galoisKey
	}
	return status
}

//export CreateEvaluationKeySet
func CreateEvaluationKeySet(relinearizationKeyHandle uint64, galoisKeyHandles *C.uint64_t, galoisKeyCount int, evaluationKeySetHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	var relinearizationKey *rlwe.RelinearizationKey
	if relinearizationKeyHandle != 0 {
		relinearizationKey = getObject[rlwe.RelinearizationKey](relinearizationKeyHandle)
	}

	handles := unsafe.Slice((*uint64)(galoisKeyHandles), galoisKeyCount)
	galoisKeys := make([]*rlwe.GaloisKey, 0, galoisKeyCount)
	for _, handle := range handles {
		if handle != 0 {
			galoisKeys = append(galoisKeys, getObject[rlwe.GaloisKey](handle))
		}
	}

	evaluationKeySet := rlwe.NewMemEvaluationKeySet(relinearizationKey, galoisKeys...)
	*evaluationKeySetHandle = C.uint64_t(insertObject(evaluationKeySet))
	return status
}
