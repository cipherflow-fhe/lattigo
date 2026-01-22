package main

/*
#include "../../fhe_types_v2.h"
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
	data_slice := unsafe.Slice(src.data, N)
	for i := 0; i < N; i++ {
		(*dest)[i] = uint64(data_slice[i])
	}
}

func export_component(src *[]uint64, dest *C.CComponent) {
	N := len(*src)
	dest.n = C.int(N)
	dest.data = (*C.ulong)(unsafe.Pointer(&(*src)[0]))
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

func export_key_switch_key(src *rlwe.SwitchingKey, dest *C.CKeySwitchKey, level int, sp_level int) {
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
	dest.n_public_key = C.int(n_public_key)
	dest.public_keys = (*C.CPublicKey)(C.malloc(C.size_t(unsafe.Sizeof(C.CPublicKey{})) * C.ulong(n_public_key)))
	public_key_slice := unsafe.Slice(dest.public_keys, n_public_key)
	for i := 0; i < n_public_key; i++ {
		export_public_key(&src.Value[i][0], &public_key_slice[i], level, sp_level)
	}
}

func export_galois_key(src *rlwe.RotationKeySet, dest *C.CGaloisKey, level int) {
	n_key_switch_key := int(dest.n_key_switch_key)
	dest.key_switch_keys = (*C.CKeySwitchKey)(C.malloc(C.size_t(unsafe.Sizeof(C.CKeySwitchKey{})) * C.ulong(n_key_switch_key)))
	gl_slice := unsafe.Slice(dest.galois_elements, n_key_switch_key)
	key_switch_key_slice := unsafe.Slice(dest.key_switch_keys, n_key_switch_key)
	for i := range gl_slice {
		export_key_switch_key(src.Keys[uint64(gl_slice[i])], &key_switch_key_slice[i], level, -1)
	}
}

//export ImportBfvCiphertext
func ImportBfvCiphertext(parameter_handle uint64, c_ciphertext *C.CCiphertext) uint64 {
	param := get_object[bfv.Parameters](parameter_handle)
	level := int(c_ciphertext.level)
	degree := int(c_ciphertext.degree)

	poly_slice := unsafe.Slice(c_ciphertext.polys, degree+1)
	ciphertext := bfv.NewCiphertextLvl(*param, degree, level)
	for i := 0; i < degree+1; i++ {
		import_polynomial(&poly_slice[i], ciphertext.Value[i])
	}
	id := insert_object(ciphertext)
	return id
}

//export ImportCkksCiphertext
func ImportCkksCiphertext(parameter_handle uint64, c_ciphertext *C.CCiphertext) uint64 {
	param := get_object[ckks.Parameters](parameter_handle)
	level := int(c_ciphertext.level)
	degree := int(c_ciphertext.degree)

	poly_slice := unsafe.Slice(c_ciphertext.polys, degree+1)
	ciphertext := ckks.NewCiphertext(*param, degree, level, param.DefaultScale())
	for i := 0; i < degree+1; i++ {
		import_polynomial(&poly_slice[i], ciphertext.Value[i])
	}
	id := insert_object(ciphertext)
	return id
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
func ExportBfvPlaintextMul(plaintext_mul_handle uint64, c_plaintext *C.CPlaintext) {
	plaintext_mul := get_object[bfv.PlaintextMul](plaintext_mul_handle)
	c_plaintext.level = C.int(plaintext_mul.Level())
	export_polynomial(plaintext_mul.Value, &c_plaintext.poly)
}

//export ExportCkksPlaintextMul
func ExportCkksPlaintextMul(plaintext_mul_handle uint64, c_plaintext *C.CPlaintext) {
	plaintext_mul := get_object[ckks.PlaintextMul](plaintext_mul_handle)
	c_plaintext.level = C.int(plaintext_mul.Level())
	export_polynomial(plaintext_mul.Value, &c_plaintext.poly)
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

//export ExportRelinKey
func ExportRelinKey(relin_key_handle uint64, level int, c_relin_key *C.CRelinKey) {
	relin_key := get_object[rlwe.RelinearizationKey](relin_key_handle)
	export_key_switch_key(relin_key.Keys[0], c_relin_key, level, -1)
}

//export ExportGaloisKey
func ExportGaloisKey(galois_key_handle uint64, level int, c_galois_key *C.CGaloisKey) {
	galois_key := get_object[rlwe.RotationKeySet](galois_key_handle)
	export_galois_key(galois_key, c_galois_key, level)
}

//export ExportSwitchingKey
func ExportSwitchingKey(switch_key_handle uint64, level int, sp_level int, c_switch_key *C.CKeySwitchKey) {
	switch_key := get_object[rlwe.SwitchingKey](switch_key_handle)
	export_key_switch_key(switch_key, c_switch_key, level, sp_level)
}
