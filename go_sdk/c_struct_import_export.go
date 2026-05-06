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

func import_component(src *C.CComponent, dest *[]uint64) {
	N := int(src.n)
	// Zero-copy: dest slice points directly into C memory (src.data).
	// Commented out: risky if C memory is freed before Go finishes using it.
	// *dest = unsafe.Slice((*uint64)(unsafe.Pointer(src.data)), N)

	// Copy: safe for all backends (GPU async D2H, FPGA pvo lifetime).
	// Requires *dest to already have length N (guaranteed by new_ciphertext).
	src_slice := unsafe.Slice((*uint64)(unsafe.Pointer(src.data)), N)
	copy(*dest, src_slice)
}

func export_component(src *[]uint64, dest *C.CComponent) {
	N := len(*src)
	dest.n = C.int(N)
	// dest.data = (*C.ulong)(unsafe.Pointer(&(*src)[0]))
	dest.data = (*C.ulong)(C.malloc(C.size_t(N) * C.size_t(unsafe.Sizeof(C.ulong(0)))))
	copy(unsafe.Slice((*uint64)(unsafe.Pointer(dest.data)), N), *src)
}

// wrap_c_components_as_ring_poly creates a ring.Poly whose Coeffs slices
// point directly into C-allocated CComponent data. This allows ring
// operations (InvMForm, MulByPow2, etc.) to transform C memory in-place
// without an additional copy.
func wrap_c_components_as_ring_poly(comps []C.CComponent) *ring.Poly {
	poly := &ring.Poly{Coeffs: make([][]uint64, len(comps))}
	for i := range comps {
		poly.Coeffs[i] = unsafe.Slice((*uint64)(unsafe.Pointer(comps[i].data)), int(comps[i].n))
	}
	return poly
}

func import_polynomial(src *C.CPolynomial, dest *ring.Poly) {
	component_slice := unsafe.Slice(src.components, src.n_component)
	for i := 0; i < int(src.n_component); i++ {
		import_component(&component_slice[i], &dest.Coeffs[i])
	}
}

func export_polynomial(src *ring.Poly, dest *C.CPolynomial) {
	n_component := src.Level() + 1
	dest.n_component = C.int(n_component)
	dest.components = (*C.CComponent)(C.malloc(C.size_t(unsafe.Sizeof(C.CComponent{})) * C.ulong(n_component)))
	component_slice := unsafe.Slice(dest.components, n_component)
	for i := 0; i < n_component; i++ {
		export_component(&src.Coeffs[i], &component_slice[i])
	}
}

func export_polynomial_qp(src *ringqp.Poly, dest *C.CPolynomial, level int, sp_level int) {
	var n_q_component int
	if level == -1 {
		n_q_component = src.LevelQ() + 1
	} else {
		n_q_component = level + 1
	}
	var n_p_component int
	if sp_level == -1 {
		n_p_component = src.LevelP() + 1
	} else {
		n_p_component = sp_level + 1
	}
	n_component := n_q_component + n_p_component
	dest.n_component = C.int(n_component)
	dest.components = (*C.CComponent)(C.malloc(C.size_t(unsafe.Sizeof(C.CComponent{})) * C.ulong(n_component)))
	component_slice := unsafe.Slice(dest.components, n_component)
	for i := 0; i < n_q_component; i++ {
		export_component(&src.Q.Coeffs[i], &component_slice[i])
	}
	for i := 0; i < n_p_component; i++ {
		export_component(&src.P.Coeffs[i], &component_slice[n_q_component+i])
	}
}

func export_public_key(src *rlwe.CiphertextQP, dest *C.CPublicKey, level int, sp_level int) {
	dest.level = C.int(level)
	dest.degree = C.int(1)
	dest.polys = (*C.CPolynomial)(C.malloc(C.size_t(unsafe.Sizeof(C.CPolynomial{})) * C.ulong(2)))
	poly_slice := unsafe.Slice(dest.polys, 2)
	for i := 0; i < 2; i++ {
		export_polynomial_qp(&src.Value[i], &poly_slice[i], level, sp_level)
	}
}

func export_key_switch_key(params rlwe.Parameters, src *rlwe.SwitchingKey, dest *C.CKeySwitchKey, level int, sp_level int, mf_nbits int) {
	var n_public_key int
	if level == -1 {
		n_public_key = len(src.Value)
	} else {
		if sp_level == -1 {
			n_public_key = (level + 1 + src.LevelP()) / (src.LevelP() + 1)
		} else {
			n_public_key = (level + 1 + sp_level) / (sp_level + 1)
		}
	}

	// Export directly from src (single copy: Go → C)
	dest.n_public_key = C.int(n_public_key)
	dest.public_keys = (*C.CPublicKey)(C.malloc(C.size_t(unsafe.Sizeof(C.CPublicKey{})) * C.ulong(n_public_key)))
	public_key_slice := unsafe.Slice(dest.public_keys, n_public_key)
	for i := 0; i < n_public_key; i++ {
		export_public_key(&src.Value[i][0], &public_key_slice[i], level, sp_level)
	}

	// Transform C memory in-place (avoids CopyNew double-copy)
	diff := mf_nbits - 64
	if diff != 0 {
		ringq := params.RingQ()
		ringp := params.RingP()

		// Determine Q/P component counts
		var n_q_component int
		if level == -1 {
			n_q_component = src.Value[0][0].Value[0].LevelQ() + 1
		} else {
			n_q_component = level + 1
		}

		for i := 0; i < n_public_key; i++ {
			pk_poly_slice := unsafe.Slice(public_key_slice[i].polys, 2)
			for j := 0; j < 2; j++ {
				comp_slice := unsafe.Slice(pk_poly_slice[j].components, int(pk_poly_slice[j].n_component))
				q_poly := wrap_c_components_as_ring_poly(comp_slice[:n_q_component])
				p_poly := wrap_c_components_as_ring_poly(comp_slice[n_q_component:])

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
}

func export_galois_key(params rlwe.Parameters, src *rlwe.RotationKeySet, dest *C.CGaloisKey, level int, mf_nbits int) {
	n_key_switch_key := int(dest.n_key_switch_key)
	dest.key_switch_keys = (*C.CKeySwitchKey)(C.malloc(C.size_t(unsafe.Sizeof(C.CKeySwitchKey{})) * C.ulong(n_key_switch_key)))
	gl_slice := unsafe.Slice(dest.galois_elements, n_key_switch_key)
	key_switch_key_slice := unsafe.Slice(dest.key_switch_keys, n_key_switch_key)
	for i := range gl_slice {
		export_key_switch_key(params, src.Keys[uint64(gl_slice[i])], &key_switch_key_slice[i], level, -1, mf_nbits)
	}
}

//export ImportBfvCiphertext
func ImportBfvCiphertext(dest_handle uint64, c_ciphertext *C.CCiphertext) {
	dest := get_object[bfv.Ciphertext](dest_handle)
	degree := int(c_ciphertext.degree)
	poly_slice := unsafe.Slice(c_ciphertext.polys, degree+1)
	for i := 0; i < degree+1; i++ {
		import_polynomial(&poly_slice[i], dest.Value[i])
	}
}

//export ImportCkksCiphertext
func ImportCkksCiphertext(dest_handle uint64, c_ciphertext *C.CCiphertext) {
	dest := get_object[ckks.Ciphertext](dest_handle)
	degree := int(c_ciphertext.degree)
	poly_slice := unsafe.Slice(c_ciphertext.polys, degree+1)
	for i := 0; i < degree+1; i++ {
		import_polynomial(&poly_slice[i], dest.Value[i])
	}
}

//export ExportBfvPlaintextRingt
func ExportBfvPlaintextRingt(plaintext_ringt_handle uint64, c_plaintext *C.CPlaintext) {
	plaintext_ringt := get_object[bfv.PlaintextRingT](plaintext_ringt_handle)
	c_plaintext.level = 0
	export_polynomial(plaintext_ringt.Value, &c_plaintext.poly)
}

//export ExportCkksPlaintextRingt
func ExportCkksPlaintextRingt(plaintext_ringt_handle uint64, c_plaintext *C.CPlaintext) {
	plaintext_ringt := get_object[ckks.PlaintextRingT](plaintext_ringt_handle)
	c_plaintext.level = 0
	export_polynomial(plaintext_ringt.Value, &c_plaintext.poly)
}

//export ExportBfvPlaintextMul
func ExportBfvPlaintextMul(parameter_handle uint64, plaintext_mul_handle uint64, mf_nbits int, c_plaintext *C.CPlaintext) {
	param := get_object[bfv.Parameters](parameter_handle)
	plaintext_mul := get_object[bfv.PlaintextMul](plaintext_mul_handle)
	c_plaintext.level = C.int(plaintext_mul.Level())
	export_polynomial(plaintext_mul.Value, &c_plaintext.poly)
	// Transform C memory in-place (avoids CopyNew double-copy)
	if mf_nbits != 64 {
		comp_slice := unsafe.Slice(c_plaintext.poly.components, int(c_plaintext.poly.n_component))
		c_poly := wrap_c_components_as_ring_poly(comp_slice)
		param.RingQ().InvMFormAndMulByPow2(c_poly, mf_nbits, c_poly)
	}
}

//export ExportCkksPlaintextMul
func ExportCkksPlaintextMul(parameter_handle uint64, plaintext_mul_handle uint64, mf_nbits int, c_plaintext *C.CPlaintext) {
	param := get_object[ckks.Parameters](parameter_handle)
	plaintext_mul := get_object[ckks.PlaintextMul](plaintext_mul_handle)
	c_plaintext.level = C.int(plaintext_mul.Level())
	export_polynomial(plaintext_mul.Value, &c_plaintext.poly)
	// Transform C memory in-place (avoids CopyNew double-copy)
	if mf_nbits != 64 {
		comp_slice := unsafe.Slice(c_plaintext.poly.components, int(c_plaintext.poly.n_component))
		c_poly := wrap_c_components_as_ring_poly(comp_slice)
		param.RingQ().InvMFormAndMulByPow2(c_poly, mf_nbits, c_poly)
	}
}

//export ExportBfvPlaintext
func ExportBfvPlaintext(plaintext_handle uint64, c_plaintext *C.CPlaintext) {
	plaintext := get_object[bfv.Plaintext](plaintext_handle)
	c_plaintext.level = C.int(plaintext.Level())
	export_polynomial(plaintext.Value, &c_plaintext.poly)
}

//export ExportCkksPlaintext
func ExportCkksPlaintext(plaintext_handle uint64, c_plaintext *C.CPlaintext) {
	plaintext := get_object[ckks.Plaintext](plaintext_handle)
	c_plaintext.level = C.int(plaintext.Level())
	export_polynomial(plaintext.Value, &c_plaintext.poly)
}

//export ExportBfvCiphertext
func ExportBfvCiphertext(ciphertext_handle uint64, c_ciphertext *C.CCiphertext) {
	ciphertext := get_object[bfv.Ciphertext](ciphertext_handle)
	c_ciphertext.level = C.int(ciphertext.Level())
	c_ciphertext.degree = C.int(ciphertext.Degree())
	c_ciphertext.polys = (*C.CPolynomial)(C.malloc(C.size_t(unsafe.Sizeof(C.CPolynomial{})) * C.ulong(ciphertext.Degree()+1)))
	poly_slice := unsafe.Slice(c_ciphertext.polys, ciphertext.Degree()+1)
	for i := 0; i < ciphertext.Degree()+1; i++ {
		export_polynomial(ciphertext.Value[i], &poly_slice[i])
	}
}

//export ExportCkksCiphertext
func ExportCkksCiphertext(ciphertext_handle uint64, c_ciphertext *C.CCiphertext) {
	ciphertext := get_object[ckks.Ciphertext](ciphertext_handle)
	c_ciphertext.level = C.int(ciphertext.Level())
	c_ciphertext.degree = C.int(ciphertext.Degree())
	c_ciphertext.polys = (*C.CPolynomial)(C.malloc(C.size_t(unsafe.Sizeof(C.CPolynomial{})) * C.ulong(ciphertext.Degree()+1)))
	poly_slice := unsafe.Slice(c_ciphertext.polys, ciphertext.Degree()+1)
	for i := 0; i < ciphertext.Degree()+1; i++ {
		export_polynomial(ciphertext.Value[i], &poly_slice[i])
	}
}

//export ExportBfvRelinKey
func ExportBfvRelinKey(parameter_handle uint64, relin_key_handle uint64, level int, key_mf_nbits int, c_relin_key *C.CRelinKey) {
	param := get_object[bfv.Parameters](parameter_handle)
	relin_key := get_object[rlwe.RelinearizationKey](relin_key_handle)
	export_key_switch_key(param.Parameters, relin_key.Keys[0], c_relin_key, level, -1, key_mf_nbits)
}

//export ExportCkksRelinKey
func ExportCkksRelinKey(parameter_handle uint64, relin_key_handle uint64, level int, key_mf_nbits int, c_relin_key *C.CRelinKey) {
	param := get_object[ckks.Parameters](parameter_handle)
	relin_key := get_object[rlwe.RelinearizationKey](relin_key_handle)
	export_key_switch_key(param.Parameters, relin_key.Keys[0], c_relin_key, level, -1, key_mf_nbits)
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
func ExportCkksSwitchingKey(parameter_handle uint64, switching_key_handle uint64, level int, sp_level int, key_mf_nbits int, c_switch_key *C.CKeySwitchKey) {
	param := get_object[ckks.Parameters](parameter_handle)
	switch_key := get_object[rlwe.SwitchingKey](switching_key_handle)
	export_key_switch_key(param.Parameters, switch_key, c_switch_key, level, sp_level, key_mf_nbits)
}
