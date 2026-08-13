package main

/*
#include <stdint.h>
#include <stdlib.h>
#include "../../../abi/c_types.h"
*/
import "C"

import (
	"math/big"
	"runtime/cgo"
	"unsafe"

	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/ring/ringqp"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
)

func mallocUint64s(n int) *C.uint64_t {
	if n <= 0 {
		return nil
	}
	return (*C.uint64_t)(C.calloc(C.size_t(n), C.size_t(unsafe.Sizeof(C.uint64_t(0)))))
}

func mallocSwitchingKeys(n int) *C.CSwitchingKey {
	if n <= 0 {
		return nil
	}
	return (*C.CSwitchingKey)(C.calloc(C.size_t(n), C.size_t(unsafe.Sizeof(C.CSwitchingKey{}))))
}

func uint64PtrAt(data *C.uint64_t, offset int) *C.uint64_t {
	return (*C.uint64_t)(unsafe.Pointer(uintptr(unsafe.Pointer(data)) + uintptr(offset)*unsafe.Sizeof(C.uint64_t(0))))
}

func switchingKeyPtrAt(data *C.CSwitchingKey, offset int) *C.CSwitchingKey {
	return (*C.CSwitchingKey)(unsafe.Pointer(uintptr(unsafe.Pointer(data)) + uintptr(offset)*unsafe.Sizeof(C.CSwitchingKey{})))
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

func exportPlaintextPoly(src ring.Poly, dest *C.CPlaintext) {
	level := src.Level()
	ringDegree := ringDegree(src)
	rnsSize := level + 1

	dest.level = C.int(level)
	dest.ring_degree = C.int(ringDegree)
	dest.data = mallocUint64s(rnsSize * ringDegree)

	for rnsIdx := 0; rnsIdx < rnsSize; rnsIdx++ {
		copy(uint64Slice(uint64PtrAt(dest.data, rnsIdx*ringDegree), ringDegree), src.Coeffs[rnsIdx])
	}
}

func importCiphertextPolys(src *C.CCiphertext, dest []ring.Poly) {
	cipherSize := int(src.cipher_size)
	level := int(src.level)
	ringDegree := int(src.ring_degree)
	rnsSize := level + 1

	for polyIdx := 0; polyIdx < minInt(cipherSize, len(dest)); polyIdx++ {
		for rnsIdx := 0; rnsIdx < minInt(rnsSize, len(dest[polyIdx].Coeffs)); rnsIdx++ {
			offset := (polyIdx*rnsSize + rnsIdx) * ringDegree
			copy(dest[polyIdx].Coeffs[rnsIdx], uint64Slice(uint64PtrAt(src.data, offset), ringDegree))
		}
	}
}

func exportCiphertextPolys(src []ring.Poly, level int, cipherSize int, dest *C.CCiphertext) {
	if cipherSize <= 0 || len(src) == 0 {
		dest.level = C.int(level)
		dest.cipher_size = C.int(0)
		dest.ring_degree = C.int(0)
		dest.data = nil
		return
	}

	ringDegree := ringDegree(src[0])
	rnsSize := level + 1

	dest.level = C.int(level)
	dest.cipher_size = C.int(cipherSize)
	dest.ring_degree = C.int(ringDegree)
	dest.data = mallocUint64s(cipherSize * rnsSize * ringDegree)

	for polyIdx := 0; polyIdx < minInt(cipherSize, len(src)); polyIdx++ {
		for rnsIdx := 0; rnsIdx < minInt(rnsSize, len(src[polyIdx].Coeffs)); rnsIdx++ {
			offset := (polyIdx*rnsSize + rnsIdx) * ringDegree
			copy(uint64Slice(uint64PtrAt(dest.data, offset), ringDegree), src[polyIdx].Coeffs[rnsIdx])
		}
	}
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

func transformMontgomeryBits(r *ring.Ring, poly ring.Poly, mfNBits int) {
	diff := mfNBits - 64
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

func exportEvaluationKey(params rlwe.Parameters, src *rlwe.EvaluationKey, dest *C.CSwitchingKey, levelQ int, levelP int, mfNBits int) {
	if src == nil || len(src.Value) == 0 || len(src.Value[0]) == 0 || len(src.Value[0][0]) == 0 {
		dest.level_q = C.int(0)
		dest.level_p = C.int(0)
		dest.ring_degree = C.int(0)
		dest.data = nil
		return
	}

	levelQ = minInt(levelQ, src.LevelQ())
	levelP = minInt(levelP, src.LevelP())
	if levelQ < 0 {
		levelQ = src.LevelQ()
	}
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

	if mfNBits == 64 {
		return
	}

	ringQ := params.RingQ()
	ringP := params.RingP()
	for decompIdx := 0; decompIdx < decompRNS; decompIdx++ {
		for polyIdx := 0; polyIdx < 2; polyIdx++ {
			offset := ((decompIdx*2 + polyIdx) * rnsSize) * ringDegree
			qPoly := polyViewFromFlatRNS(uint64PtrAt(dest.data, offset), qSize, ringDegree)
			transformMontgomeryBits(ringQ, qPoly, mfNBits)

			if pSize > 0 {
				pPoly := polyViewFromFlatRNS(uint64PtrAt(dest.data, offset+qSize*ringDegree), pSize, ringDegree)
				transformMontgomeryBits(ringP, pPoly, mfNBits)
			}
		}
	}
}

func exportGaloisKey(params rlwe.Parameters, gk *rlwe.GaloisKey, dest *C.CGaloisKey, levelQ int, mfNBits int) {
	levelP := gk.LevelP()
	dest.n_switching_key = C.int(1)
	dest.galois_elements = mallocUint64s(1)
	*dest.galois_elements = C.uint64_t(gk.GaloisElement)
	dest.switching_keys = mallocSwitchingKeys(1)
	exportEvaluationKey(params, &gk.EvaluationKey, dest.switching_keys, levelQ, levelP, mfNBits)
}

//export ImportBfvCiphertext
func ImportBfvCiphertext(destHandle uint64, cCiphertext *C.CCiphertext) {
}

//export ImportCkksCiphertext
func ImportCkksCiphertext(destHandle uint64, cCiphertext *C.CCiphertext) {
	dest := getObject[rlwe.Ciphertext](destHandle)
	dest.Resize(int(cCiphertext.cipher_size)-1, int(cCiphertext.level))
	importCiphertextPolys(cCiphertext, dest.Value)
}

//export ExportBfvPlaintextRingt
func ExportBfvPlaintextRingt(plaintextRingtHandle uint64, plaintext *C.CPlaintext) {
}

//export ExportCkksPlaintextRingt
func ExportCkksPlaintextRingt(plaintextRingtHandle uint64, plaintext *C.CPlaintext) {
	src := getObject[rlwe.Plaintext](plaintextRingtHandle)
	exportPlaintextPoly(src.Value, plaintext)
}

//export ExportBfvPlaintext
func ExportBfvPlaintext(plaintextHandle uint64, plaintext *C.CPlaintext) {
}

//export ExportCkksPlaintext
func ExportCkksPlaintext(plaintextHandle uint64, plaintext *C.CPlaintext) {
	src := getObject[rlwe.Plaintext](plaintextHandle)
	exportPlaintextPoly(src.Value, plaintext)
}

//export ExportBfvCiphertext
func ExportBfvCiphertext(ciphertextHandle uint64, ciphertext *C.CCiphertext) {
}

//export ExportCkksCiphertext
func ExportCkksCiphertext(ciphertextHandle uint64, ciphertext *C.CCiphertext) {
	src := getObject[rlwe.Ciphertext](ciphertextHandle)
	exportCiphertextPolys(src.Value, src.Level(), src.Degree()+1, ciphertext)
}

//export ExportBfvRelinKey
func ExportBfvRelinKey(parameterHandle uint64, relinKeyHandle uint64, level int, keyMFNBits int, relinKey *C.CRelinKey) {
}

//export ExportCkksRelinKey
func ExportCkksRelinKey(parameterHandle uint64, relinKeyHandle uint64, level int, keyMFNBits int, relinKey *C.CRelinKey) {
	params := getObject[ckks.Parameters](parameterHandle)
	value := cgo.Handle(relinKeyHandle).Value()
	switch key := value.(type) {
	case *rlwe.RelinearizationKey:
		exportEvaluationKey(params.Parameters, &key.EvaluationKey, relinKey, level, key.LevelP(), keyMFNBits)
	case *rlwe.EvaluationKey:
		exportEvaluationKey(params.Parameters, key, relinKey, level, key.LevelP(), keyMFNBits)
	}
}

//export ExportBfvGaloisKey
func ExportBfvGaloisKey(parameterHandle uint64, galoisKeyHandle uint64, level int, keyMFNBits int, galoisKey *C.CGaloisKey) {
}

//export ExportCkksGaloisKey
func ExportCkksGaloisKey(parameterHandle uint64, galoisKeyHandle uint64, level int, keyMFNBits int, galoisKey *C.CGaloisKey) {
	params := getObject[ckks.Parameters](parameterHandle)
	value := cgo.Handle(galoisKeyHandle).Value()

	switch key := value.(type) {
	case *rlwe.GaloisKey:
		exportGaloisKey(params.Parameters, key, galoisKey, level, keyMFNBits)
	case *rlwe.MemEvaluationKeySet:
		galoisElements := key.GetGaloisKeysList()
		galoisKey.n_switching_key = C.int(len(galoisElements))
		galoisKey.galois_elements = mallocUint64s(len(galoisElements))
		galoisKey.switching_keys = mallocSwitchingKeys(len(galoisElements))
		for i, galEl := range galoisElements {
			gk, err := key.GetGaloisKey(galEl)
			if err != nil {
				panic(err)
			}
			*uint64PtrAt(galoisKey.galois_elements, i) = C.uint64_t(galEl)
			exportEvaluationKey(params.Parameters, &gk.EvaluationKey, switchingKeyPtrAt(galoisKey.switching_keys, i), level, gk.LevelP(), keyMFNBits)
		}
	}
}

//export ExportCkksSwitchingKey
func ExportCkksSwitchingKey(parameterHandle uint64, switchingKeyHandle uint64, levelQ int, levelP int, keyMFNBits int, switchingKey *C.CSwitchingKey) {
	params := getObject[ckks.Parameters](parameterHandle)
	value := cgo.Handle(switchingKeyHandle).Value()
	switch key := value.(type) {
	case *rlwe.EvaluationKey:
		exportEvaluationKey(params.Parameters, key, switchingKey, levelQ, levelP, keyMFNBits)
	case *rlwe.RelinearizationKey:
		exportEvaluationKey(params.Parameters, &key.EvaluationKey, switchingKey, levelQ, levelP, keyMFNBits)
	case *rlwe.GaloisKey:
		exportEvaluationKey(params.Parameters, &key.EvaluationKey, switchingKey, levelQ, levelP, keyMFNBits)
	}
}
