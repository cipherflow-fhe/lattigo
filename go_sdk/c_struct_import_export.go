package main

/*
#include <stdint.h>
#include <stdlib.h>
#include "../../../abi/c_types.h"
*/
import "C"

import (
	"fmt"
	"math/big"
	"runtime/cgo"
	"unsafe"

	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/ring/ringqp"
)

func mallocUint64s(n int) *C.uint64_t {
	if n <= 0 {
		return nil
	}
	return (*C.uint64_t)(C.calloc(C.size_t(n), C.size_t(unsafe.Sizeof(C.uint64_t(0)))))
}

func uint64PtrAt(data *C.uint64_t, offset int) *C.uint64_t {
	return (*C.uint64_t)(unsafe.Pointer(uintptr(unsafe.Pointer(data)) + uintptr(offset)*unsafe.Sizeof(C.uint64_t(0))))
}

func uint64Slice(data *C.uint64_t, n int) []uint64 {
	if data == nil || n <= 0 {
		return nil
	}
	return unsafe.Slice((*uint64)(unsafe.Pointer(data)), n)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ringDegree(src ring.Poly) int {
	if len(src.Coeffs) == 0 {
		return 0
	}
	return len(src.Coeffs[0])
}

func polyViewFromFlatRNS(data *C.uint64_t, rnsSize int, ringDegree int) ring.Poly {
	poly := ring.Poly{Coeffs: make([][]uint64, rnsSize)}
	for rnsIdx := 0; rnsIdx < rnsSize; rnsIdx++ {
		poly.Coeffs[rnsIdx] = uint64Slice(uint64PtrAt(data, rnsIdx*ringDegree), ringDegree)
	}
	return poly
}

func exportQPPoly(src ringqp.Poly, data *C.uint64_t, levelQ int, levelP int, ringDegree int) {
	qSize := levelQ + 1
	pSize := 0
	if levelP >= 0 {
		pSize = levelP + 1
	}

	for rnsIdx := 0; rnsIdx < minInt(qSize, len(src.Q.Coeffs)); rnsIdx++ {
		copy(uint64Slice(uint64PtrAt(data, rnsIdx*ringDegree), ringDegree), src.Q.Coeffs[rnsIdx])
	}
	for rnsIdx := 0; rnsIdx < minInt(pSize, len(src.P.Coeffs)); rnsIdx++ {
		copy(uint64Slice(uint64PtrAt(data, (qSize+rnsIdx)*ringDegree), ringDegree), src.P.Coeffs[rnsIdx])
	}
}

func mulByPow2(r *ring.Ring, poly ring.Poly, pow2 int) {
	if r == nil || pow2 <= 0 || poly.Level() < 0 {
		return
	}
	scalar := new(big.Int).Lsh(big.NewInt(1), uint(pow2))
	r.AtLevel(poly.Level()).MulScalarBigint(poly, scalar, poly)
}

func transformNTT(r *ring.Ring, poly ring.Poly, sourceIsNTT bool, targetIsNTT bool) {
	if r == nil || sourceIsNTT == targetIsNTT || poly.Level() < 0 {
		return
	}

	rlvl := r.AtLevel(poly.Level())
	if targetIsNTT {
		rlvl.NTT(poly, poly)
	} else {
		rlvl.INTT(poly, poly)
	}
}

func transformMontgomeryBits(r *ring.Ring, poly ring.Poly, sourceMFNBits int, targetMFNBits int) {
	diff := targetMFNBits - sourceMFNBits
	if r == nil || diff == 0 || poly.Level() < 0 {
		return
	}

	rlvl := r.AtLevel(poly.Level())
	if diff == -64 {
		rlvl.IMForm(poly, poly)
	} else if diff > 0 {
		mulByPow2(rlvl, poly, diff)
	} else {
		rlvl.IMForm(poly, poly)
		mulByPow2(rlvl, poly, 64+diff)
	}
}

func exportEvaluationKey(params *rlwe.Parameters, src *rlwe.EvaluationKey, dest *C.CEvaluationKey, levelP int, metadata *C.Metadata) {
	if src == nil || len(src.Value) == 0 || len(src.Value[0]) == 0 || len(src.Value[0][0]) == 0 {
		dest.level_q = C.int(0)
		dest.level_p = C.int(0)
		dest.ring_degree = C.int(0)
		dest.data = nil
		return
	}

	levelQ := src.LevelQ()
	if metadata != nil {
		levelQ = minInt(int(metadata.level), src.LevelQ())
	}
	levelP = minInt(levelP, src.LevelP())
	if levelP < -1 {
		levelP = src.LevelP()
	}

	ringDegree := src.Value[0][0][0].Q.N()
	decompRNS := params.BaseRNSDecompositionVectorSize(levelQ, levelP)
	decompRNS = minInt(decompRNS, len(src.Value))
	qSize := levelQ + 1
	pSize := 0
	if levelP >= 0 {
		pSize = levelP + 1
	}
	rnsSize := qSize + pSize

	dest.level_q = C.int(levelQ)
	dest.level_p = C.int(levelP)
	dest.ring_degree = C.int(ringDegree)
	dest.data = mallocUint64s(decompRNS * 2 * rnsSize * ringDegree)

	for decompIdx := 0; decompIdx < decompRNS; decompIdx++ {
		if len(src.Value[decompIdx]) == 0 {
			continue
		}
		polys := src.Value[decompIdx][0]
		for polyIdx := 0; polyIdx < minInt(2, len(polys)); polyIdx++ {
			offset := ((decompIdx*2 + polyIdx) * rnsSize) * ringDegree
			exportQPPoly(polys[polyIdx], uint64PtrAt(dest.data, offset), levelQ, levelP, ringDegree)
		}
	}

	if metadata == nil {
		return
	}

	sourceIsNTT := true
	sourceMFormBits := 64
	targetIsNTT := metadata.is_ntt != 0
	targetMFormBits := int(metadata.mform_bits)
	if sourceIsNTT == targetIsNTT && sourceMFormBits == targetMFormBits {
		return
	}

	ringQ := params.RingQ()
	ringP := params.RingP()
	for decompIdx := 0; decompIdx < decompRNS; decompIdx++ {
		for polyIdx := 0; polyIdx < 2; polyIdx++ {
			offset := ((decompIdx*2 + polyIdx) * rnsSize) * ringDegree
			qPoly := polyViewFromFlatRNS(uint64PtrAt(dest.data, offset), qSize, ringDegree)
			transformNTT(ringQ, qPoly, sourceIsNTT, targetIsNTT)
			transformMontgomeryBits(ringQ, qPoly, sourceMFormBits, targetMFormBits)

			if pSize > 0 {
				pPoly := polyViewFromFlatRNS(uint64PtrAt(dest.data, offset+qSize*ringDegree), pSize, ringDegree)
				transformNTT(ringP, pPoly, sourceIsNTT, targetIsNTT)
				transformMontgomeryBits(ringP, pPoly, sourceMFormBits, targetMFormBits)
			}
		}
	}
}

//export ImportCiphertext
func ImportCiphertext(parameterHandle uint64, destHandle uint64, sourceMetadata *C.Metadata, targetMetadata *C.Metadata, cCiphertext *C.CCiphertext) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)

	if targetMetadata == nil {
		return errorStatus(fmt.Errorf("target metadata is required for ciphertext import"))
	}
	if targetMetadata.log_slots < 0 {
		return errorStatus(fmt.Errorf("target metadata log_slots must be non-negative, got %d", int(targetMetadata.log_slots)))
	}
	if targetMetadata.scale <= 0 {
		return errorStatus(fmt.Errorf("target metadata scale must be positive, got %f", float64(targetMetadata.scale)))
	}

	params := getObjectAs[rlwe.ParameterProvider](parameterHandle).GetRLWEParameters()
	dest := getObject[rlwe.Ciphertext](destHandle)
	cipherSize := int(cCiphertext.cipher_size)
	level := int(cCiphertext.level)
	ringDegree := int(cCiphertext.ring_degree)
	rnsSize := level + 1

	dest.Resize(cipherSize-1, level)
	for polyIdx := 0; polyIdx < minInt(cipherSize, len(dest.Value)); polyIdx++ {
		for rnsIdx := 0; rnsIdx < minInt(rnsSize, len(dest.Value[polyIdx].Coeffs)); rnsIdx++ {
			offset := (polyIdx*rnsSize + rnsIdx) * ringDegree
			copy(dest.Value[polyIdx].Coeffs[rnsIdx], uint64Slice(uint64PtrAt(cCiphertext.data, offset), ringDegree))
		}
	}

	if sourceMetadata != nil {
		ringQ := params.RingQ().AtLevel(level)
		for polyIdx := 0; polyIdx < minInt(cipherSize, len(dest.Value)); polyIdx++ {
			transformNTT(ringQ, dest.Value[polyIdx], sourceMetadata.is_ntt != 0, targetMetadata.is_ntt != 0)
			transformMontgomeryBits(ringQ, dest.Value[polyIdx], int(sourceMetadata.mform_bits), int(targetMetadata.mform_bits))
		}
	}

	dest.IsRingT = targetMetadata.is_ringt != 0
	dest.IsBatched = targetMetadata.is_batched != 0
	dest.IsNTT = targetMetadata.is_ntt != 0
	dest.IsMontgomery = targetMetadata.mform_bits == 64
	dest.LogDimensions.Rows = 0
	dest.LogDimensions.Cols = int(targetMetadata.log_slots)
	scale := float64(targetMetadata.scale)
	dest.Scale = params.NewScale(scale)
	return status
}

//export ExportPlaintext
func ExportPlaintext(parameterHandle uint64, plaintextHandle uint64, metadata *C.Metadata, plaintext *C.CPlaintext) {
	params := getObjectAs[rlwe.ParameterProvider](parameterHandle).GetRLWEParameters()
	src := getObject[rlwe.Plaintext](plaintextHandle)
	level := src.Level()
	ringDegree := ringDegree(src.Value)
	rnsSize := level + 1

	plaintext.level = C.int(level)
	plaintext.ring_degree = C.int(ringDegree)
	plaintext.data = mallocUint64s(rnsSize * ringDegree)

	for rnsIdx := 0; rnsIdx < rnsSize; rnsIdx++ {
		copy(uint64Slice(uint64PtrAt(plaintext.data, rnsIdx*ringDegree), ringDegree), src.Value.Coeffs[rnsIdx])
	}

	if metadata == nil || src.IsRingT || metadata.is_ringt != 0 {
		return
	}

	sourceMFormBits := 0
	if src.IsMontgomery {
		sourceMFormBits = 64
	}
	qPoly := polyViewFromFlatRNS(plaintext.data, rnsSize, ringDegree)
	ringQ := params.RingQ().AtLevel(level)
	transformNTT(ringQ, qPoly, src.IsNTT, metadata.is_ntt != 0)
	transformMontgomeryBits(ringQ, qPoly, sourceMFormBits, int(metadata.mform_bits))
}

//export ExportCiphertext
func ExportCiphertext(parameterHandle uint64, ciphertextHandle uint64, metadata *C.Metadata, ciphertext *C.CCiphertext) {
	params := getObjectAs[rlwe.ParameterProvider](parameterHandle).GetRLWEParameters()
	src := getObject[rlwe.Ciphertext](ciphertextHandle)
	level := src.Level()
	cipherSize := src.Degree() + 1

	if cipherSize <= 0 || len(src.Value) == 0 {
		ciphertext.level = C.int(level)
		ciphertext.cipher_size = C.int(0)
		ciphertext.ring_degree = C.int(0)
		ciphertext.data = nil
		return
	}

	ringDegree := ringDegree(src.Value[0])
	rnsSize := level + 1

	ciphertext.level = C.int(level)
	ciphertext.cipher_size = C.int(cipherSize)
	ciphertext.ring_degree = C.int(ringDegree)
	ciphertext.data = mallocUint64s(cipherSize * rnsSize * ringDegree)

	for polyIdx := 0; polyIdx < minInt(cipherSize, len(src.Value)); polyIdx++ {
		for rnsIdx := 0; rnsIdx < minInt(rnsSize, len(src.Value[polyIdx].Coeffs)); rnsIdx++ {
			offset := (polyIdx*rnsSize + rnsIdx) * ringDegree
			copy(uint64Slice(uint64PtrAt(ciphertext.data, offset), ringDegree), src.Value[polyIdx].Coeffs[rnsIdx])
		}
	}

	if metadata == nil {
		return
	}

	sourceMFormBits := 0
	if src.IsMontgomery {
		sourceMFormBits = 64
	}
	ringQ := params.RingQ().AtLevel(level)
	for polyIdx := 0; polyIdx < minInt(cipherSize, len(src.Value)); polyIdx++ {
		qPoly := polyViewFromFlatRNS(uint64PtrAt(ciphertext.data, polyIdx*rnsSize*ringDegree), rnsSize, ringDegree)
		transformNTT(ringQ, qPoly, src.IsNTT, metadata.is_ntt != 0)
		transformMontgomeryBits(ringQ, qPoly, sourceMFormBits, int(metadata.mform_bits))
	}
}

//export ExportEvaluationKey
func ExportEvaluationKey(parameterHandle uint64, evaluationKeyHandle uint64, levelP int, metadata *C.Metadata, evaluationKey *C.CEvaluationKey) {
	params := getObjectAs[rlwe.ParameterProvider](parameterHandle).GetRLWEParameters()
	value := cgo.Handle(evaluationKeyHandle).Value()
	switch key := value.(type) {
	case *rlwe.EvaluationKey:
		resolvedLevelP := levelP
		if resolvedLevelP == -1 {
			resolvedLevelP = key.LevelP()
		}
		exportEvaluationKey(params, key, evaluationKey, resolvedLevelP, metadata)
	case *rlwe.RelinearizationKey:
		resolvedLevelP := levelP
		if resolvedLevelP == -1 {
			resolvedLevelP = key.LevelP()
		}
		exportEvaluationKey(params, &key.EvaluationKey, evaluationKey, resolvedLevelP, metadata)
	case *rlwe.GaloisKey:
		resolvedLevelP := levelP
		if resolvedLevelP == -1 {
			resolvedLevelP = key.LevelP()
		}
		exportEvaluationKey(params, &key.EvaluationKey, evaluationKey, resolvedLevelP, metadata)
	}
}
