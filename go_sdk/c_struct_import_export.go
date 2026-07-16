package main

/*
#include "../../../abi/c_types.h"
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"

	"github.com/cipherflow-fhe/lattigo/bfv"
	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/rlwe"
	"github.com/cipherflow-fhe/lattigo/rlwe/ringqp"
)

func malloc_uint64s(n int) *C.uint64_t {
	return (*C.uint64_t)(C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.uint64_t(0)))))
}

func uint64_ptr_at(data *C.uint64_t, offset int) *C.uint64_t {
	return (*C.uint64_t)(unsafe.Pointer(uintptr(unsafe.Pointer(data)) + uintptr(offset)*unsafe.Sizeof(C.uint64_t(0))))
}

func uint64_slice(data *C.uint64_t, n int) []uint64 {
	return unsafe.Slice((*uint64)(unsafe.Pointer(data)), n)
}

func ring_degree(src *ring.Poly) int {
	return len(src.Coeffs[0])
}

func switching_key_ring_degree(src *rlwe.SwitchingKey) int {
	return len(src.Value[0][0].Value[0].Q.Coeffs[0])
}

func switching_key_decomp_rns(level_q int, level_p int) int {
	return (level_q + level_p + 1) / (level_p + 1)
}

func poly_view_from_flat_rns(data *C.uint64_t, rns_size int, ring_degree int) *ring.Poly {
	poly := &ring.Poly{Coeffs: make([][]uint64, rns_size)}
	for rns_idx := 0; rns_idx < rns_size; rns_idx++ {
		poly.Coeffs[rns_idx] = uint64_slice(uint64_ptr_at(data, rns_idx*ring_degree), ring_degree)
	}
	return poly
}

func export_plaintext_poly(src *ring.Poly, dest *C.CPlaintext) {
	level := src.Level()
	ring_degree := ring_degree(src)
	rns_size := level + 1

	dest.level = C.int(level)
	dest.ring_degree = C.int(ring_degree)
	dest.data = malloc_uint64s(rns_size * ring_degree)

	for rns_idx := 0; rns_idx < rns_size; rns_idx++ {
		copy(uint64_slice(uint64_ptr_at(dest.data, rns_idx*ring_degree), ring_degree), src.Coeffs[rns_idx])
	}
}

func import_ciphertext_polys(src *C.CCiphertext, dest []*ring.Poly) {
	cipher_size := int(src.cipher_size)
	level := int(src.level)
	ring_degree := int(src.ring_degree)
	rns_size := level + 1

	for poly_idx := 0; poly_idx < cipher_size; poly_idx++ {
		for rns_idx := 0; rns_idx < rns_size; rns_idx++ {
			offset := (poly_idx*rns_size + rns_idx) * ring_degree
			copy(dest[poly_idx].Coeffs[rns_idx], uint64_slice(uint64_ptr_at(src.data, offset), ring_degree))
		}
	}
}

func export_ciphertext_polys(src []*ring.Poly, level int, cipher_size int, dest *C.CCiphertext) {
	ring_degree := ring_degree(src[0])
	rns_size := level + 1

	dest.level = C.int(level)
	dest.cipher_size = C.int(cipher_size)
	dest.ring_degree = C.int(ring_degree)
	dest.data = malloc_uint64s(cipher_size * rns_size * ring_degree)

	for poly_idx := 0; poly_idx < cipher_size; poly_idx++ {
		for rns_idx := 0; rns_idx < rns_size; rns_idx++ {
			offset := (poly_idx*rns_size + rns_idx) * ring_degree
			copy(uint64_slice(uint64_ptr_at(dest.data, offset), ring_degree), src[poly_idx].Coeffs[rns_idx])
		}
	}
}

func export_qp_poly(src *ringqp.Poly, data *C.uint64_t, level_q int, level_p int, ring_degree int) {
	q_size := level_q + 1
	p_size := level_p + 1
	for rns_idx := 0; rns_idx < q_size; rns_idx++ {
		copy(uint64_slice(uint64_ptr_at(data, rns_idx*ring_degree), ring_degree), src.Q.Coeffs[rns_idx])
	}
	for rns_idx := 0; rns_idx < p_size; rns_idx++ {
		copy(uint64_slice(uint64_ptr_at(data, (q_size+rns_idx)*ring_degree), ring_degree), src.P.Coeffs[rns_idx])
	}
}

func export_switching_key(params rlwe.Parameters, src *rlwe.SwitchingKey, dest *C.CSwitchingKey, level_q int, level_p int, mf_nbits int) {
	ring_degree := switching_key_ring_degree(src)
	decomp_rns := switching_key_decomp_rns(level_q, level_p)

	q_size := level_q + 1
	p_size := level_p + 1
	rns_size := q_size + p_size

	dest.level_q = C.int(level_q)
	dest.level_p = C.int(level_p)
	dest.ring_degree = C.int(ring_degree)
	dest.data = malloc_uint64s(decomp_rns * 2 * rns_size * ring_degree)

	for decomp_idx := 0; decomp_idx < decomp_rns; decomp_idx++ {
		for poly_idx := 0; poly_idx < 2; poly_idx++ {
			offset := ((decomp_idx*2 + poly_idx) * rns_size) * ring_degree
			export_qp_poly(&src.Value[decomp_idx][0].Value[poly_idx], uint64_ptr_at(dest.data, offset), level_q, level_p, ring_degree)
		}
	}

	diff := mf_nbits - 64
	if diff == 0 {
		return
	}

	ringq := params.RingQ()
	ringp := params.RingP()
	for decomp_idx := 0; decomp_idx < decomp_rns; decomp_idx++ {
		for poly_idx := 0; poly_idx < 2; poly_idx++ {
			offset := ((decomp_idx*2 + poly_idx) * rns_size) * ring_degree
			q_poly := poly_view_from_flat_rns(uint64_ptr_at(dest.data, offset), q_size, ring_degree)
			p_poly := poly_view_from_flat_rns(uint64_ptr_at(dest.data, offset+q_size*ring_degree), p_size, ring_degree)

			if diff == -64 {
				ringq.InvMForm(q_poly, q_poly)
				ringp.InvMForm(p_poly, p_poly)
			} else if diff > 0 {
				ringq.MulByPow2(q_poly, diff, q_poly)
				ringp.MulByPow2(p_poly, diff, p_poly)
			} else {
				ringq.InvMFormAndMulByPow2(q_poly, 64+diff, q_poly)
				ringp.InvMFormAndMulByPow2(p_poly, 64+diff, p_poly)
			}
		}
	}
}

func export_galois_key(params rlwe.Parameters, src *rlwe.RotationKeySet, dest *C.CGaloisKey, level int, mf_nbits int) {
	n_switching_key := int(dest.n_switching_key)
	galois_elements := unsafe.Slice(dest.galois_elements, n_switching_key)
	level_p := src.Keys[uint64(galois_elements[0])].LevelP()

	dest.switching_keys = (*C.CSwitchingKey)(C.malloc(C.size_t(n_switching_key) * C.size_t(unsafe.Sizeof(C.CSwitchingKey{}))))
	switching_keys := unsafe.Slice(dest.switching_keys, n_switching_key)
	for switching_key_idx := range galois_elements {
		switching_key := src.Keys[uint64(galois_elements[switching_key_idx])]
		export_switching_key(params, switching_key, &switching_keys[switching_key_idx], level, level_p, mf_nbits)
	}
}

//export ImportBfvCiphertext
func ImportBfvCiphertext(dest_handle uint64, c_ciphertext *C.CCiphertext) {
	dest := get_object[bfv.Ciphertext](dest_handle)
	import_ciphertext_polys(c_ciphertext, dest.Value)
}

//export ImportCkksCiphertext
func ImportCkksCiphertext(dest_handle uint64, c_ciphertext *C.CCiphertext) {
	dest := get_object[ckks.Ciphertext](dest_handle)
	import_ciphertext_polys(c_ciphertext, dest.Value)
}

//export ExportBfvPlaintextRingt
func ExportBfvPlaintextRingt(plaintext_ringt_handle uint64, c_plaintext *C.CPlaintext) {
	plaintext_ringt := get_object[bfv.PlaintextRingT](plaintext_ringt_handle)
	export_plaintext_poly(plaintext_ringt.Value, c_plaintext)
}

//export ExportCkksPlaintextRingt
func ExportCkksPlaintextRingt(plaintext_ringt_handle uint64, c_plaintext *C.CPlaintext) {
	plaintext_ringt := get_object[ckks.PlaintextRingT](plaintext_ringt_handle)
	export_plaintext_poly(plaintext_ringt.Value, c_plaintext)
}

//export ExportBfvPlaintextMul
func ExportBfvPlaintextMul(parameter_handle uint64, plaintext_mul_handle uint64, mf_nbits int, c_plaintext *C.CPlaintext) {
	param := get_object[bfv.Parameters](parameter_handle)
	plaintext_mul := get_object[bfv.PlaintextMul](plaintext_mul_handle)
	export_plaintext_poly(plaintext_mul.Value, c_plaintext)
	if mf_nbits != 64 {
		c_poly := poly_view_from_flat_rns(c_plaintext.data, int(c_plaintext.level)+1, int(c_plaintext.ring_degree))
		param.RingQ().InvMFormAndMulByPow2(c_poly, mf_nbits, c_poly)
	}
}

//export ExportCkksPlaintextMul
func ExportCkksPlaintextMul(parameter_handle uint64, plaintext_mul_handle uint64, mf_nbits int, c_plaintext *C.CPlaintext) {
	param := get_object[ckks.Parameters](parameter_handle)
	plaintext_mul := get_object[ckks.PlaintextMul](plaintext_mul_handle)
	export_plaintext_poly(plaintext_mul.Value, c_plaintext)
	if mf_nbits != 64 {
		c_poly := poly_view_from_flat_rns(c_plaintext.data, int(c_plaintext.level)+1, int(c_plaintext.ring_degree))
		param.RingQ().InvMFormAndMulByPow2(c_poly, mf_nbits, c_poly)
	}
}

//export ExportBfvPlaintext
func ExportBfvPlaintext(plaintext_handle uint64, c_plaintext *C.CPlaintext) {
	plaintext := get_object[bfv.Plaintext](plaintext_handle)
	export_plaintext_poly(plaintext.Value, c_plaintext)
}

//export ExportCkksPlaintext
func ExportCkksPlaintext(plaintext_handle uint64, c_plaintext *C.CPlaintext) {
	plaintext := get_object[ckks.Plaintext](plaintext_handle)
	export_plaintext_poly(plaintext.Value, c_plaintext)
}

//export ExportBfvCiphertext
func ExportBfvCiphertext(ciphertext_handle uint64, c_ciphertext *C.CCiphertext) {
	ciphertext := get_object[bfv.Ciphertext](ciphertext_handle)
	export_ciphertext_polys(ciphertext.Value, ciphertext.Level(), ciphertext.Degree()+1, c_ciphertext)
}

//export ExportCkksCiphertext
func ExportCkksCiphertext(ciphertext_handle uint64, c_ciphertext *C.CCiphertext) {
	ciphertext := get_object[ckks.Ciphertext](ciphertext_handle)
	export_ciphertext_polys(ciphertext.Value, ciphertext.Level(), ciphertext.Degree()+1, c_ciphertext)
}

//export ExportBfvRelinKey
func ExportBfvRelinKey(parameter_handle uint64, relin_key_handle uint64, level int, key_mf_nbits int, c_relin_key *C.CRelinKey) {
	param := get_object[bfv.Parameters](parameter_handle)
	relin_key := get_object[rlwe.RelinearizationKey](relin_key_handle)
	export_switching_key(param.Parameters, relin_key.Keys[0], c_relin_key, level, relin_key.Keys[0].LevelP(), key_mf_nbits)
}

//export ExportCkksRelinKey
func ExportCkksRelinKey(parameter_handle uint64, relin_key_handle uint64, level int, key_mf_nbits int, c_relin_key *C.CRelinKey) {
	param := get_object[ckks.Parameters](parameter_handle)
	relin_key := get_object[rlwe.RelinearizationKey](relin_key_handle)
	export_switching_key(param.Parameters, relin_key.Keys[0], c_relin_key, level, relin_key.Keys[0].LevelP(), key_mf_nbits)
}

//export ExportBfvGaloisKey
func ExportBfvGaloisKey(parameter_handle uint64, galois_key_handle uint64, level int, key_mf_nbits int, c_galois_key *C.CGaloisKey) {
	param := get_object[bfv.Parameters](parameter_handle)
	galois_key := get_object[rlwe.RotationKeySet](galois_key_handle)
	export_galois_key(param.Parameters, galois_key, c_galois_key, level, key_mf_nbits)
}

//export ExportCkksGaloisKey
func ExportCkksGaloisKey(parameter_handle uint64, galois_key_handle uint64, level int, key_mf_nbits int, c_galois_key *C.CGaloisKey) {
	param := get_object[ckks.Parameters](parameter_handle)
	galois_key := get_object[rlwe.RotationKeySet](galois_key_handle)
	export_galois_key(param.Parameters, galois_key, c_galois_key, level, key_mf_nbits)
}

//export ExportCkksSwitchingKey
func ExportCkksSwitchingKey(parameter_handle uint64, switching_key_handle uint64, level_q int, level_p int, key_mf_nbits int, c_switch_key *C.CSwitchingKey) {
	param := get_object[ckks.Parameters](parameter_handle)
	switch_key := get_object[rlwe.SwitchingKey](switching_key_handle)
	export_switching_key(param.Parameters, switch_key, c_switch_key, level_q, level_p, key_mf_nbits)
}
