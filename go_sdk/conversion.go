package main

// #include <stdint.h>
import "C"
import (
	"unsafe"

	"github.com/cipherflow-fhe/lattigo/bfv"
	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/ring"
)

//export BfvComponentNttInplace
func BfvComponentNttInplace(parameter_handle uint64, coeff *C.uint64_t, lvl_idx int) {
	param := get_object[bfv.Parameters](parameter_handle)
	ringq := param.RingQ()
	data_slice := unsafe.Slice((*uint64)(unsafe.Pointer(coeff)), ringq.N)

	if lvl_idx < param.QCount() {
		ring.NTT(data_slice, data_slice, ringq.N, ringq.NttPsi[lvl_idx], ringq.Modulus[lvl_idx], ringq.MredParams[lvl_idx], ringq.BredParams[lvl_idx])
	} else {
		ringp := param.RingP()
		sp_lvl_idx := lvl_idx - param.QCount()
		ring.NTT(data_slice, data_slice, ringp.N, ringp.NttPsi[sp_lvl_idx], ringp.Modulus[sp_lvl_idx], ringp.MredParams[sp_lvl_idx], ringp.BredParams[sp_lvl_idx])
	}

}

//export BfvComponentInvNttInplace
func BfvComponentInvNttInplace(parameter_handle uint64, coeff *C.uint64_t, lvl_idx int) {
	param := get_object[bfv.Parameters](parameter_handle)
	ringq := param.RingQ()
	data_slice := unsafe.Slice((*uint64)(unsafe.Pointer(coeff)), ringq.N)

	if lvl_idx < param.QCount() {
		ring.InvNTT(data_slice, data_slice, ringq.N, ringq.NttPsiInv[lvl_idx], ringq.NttNInv[lvl_idx], ringq.Modulus[lvl_idx], ringq.MredParams[lvl_idx])
	} else {
		ringp := param.RingP()
		sp_lvl_idx := lvl_idx - param.QCount()
		ring.InvNTT(data_slice, data_slice, ringp.N, ringp.NttPsiInv[sp_lvl_idx], ringp.NttNInv[sp_lvl_idx], ringp.Modulus[sp_lvl_idx], ringp.MredParams[sp_lvl_idx])
	}
}

//export CkksComponentNttInplace
func CkksComponentNttInplace(parameter_handle uint64, coeff *C.uint64_t, lvl_idx int) {
	param := get_object[ckks.Parameters](parameter_handle)
	ringq := param.RingQ()
	data_slice := unsafe.Slice((*uint64)(unsafe.Pointer(coeff)), ringq.N)

	if lvl_idx < param.QCount() {
		ring.NTT(data_slice, data_slice, ringq.N, ringq.NttPsi[lvl_idx], ringq.Modulus[lvl_idx], ringq.MredParams[lvl_idx], ringq.BredParams[lvl_idx])
	} else {
		ringp := param.RingP()
		sp_lvl_idx := lvl_idx - param.QCount()
		ring.NTT(data_slice, data_slice, ringp.N, ringp.NttPsi[sp_lvl_idx], ringp.Modulus[sp_lvl_idx], ringp.MredParams[sp_lvl_idx], ringp.BredParams[sp_lvl_idx])
	}

}

//export CkksComponentInvNttInplace
func CkksComponentInvNttInplace(parameter_handle uint64, coeff *C.uint64_t, lvl_idx int) {
	param := get_object[ckks.Parameters](parameter_handle)
	ringq := param.RingQ()
	data_slice := unsafe.Slice((*uint64)(unsafe.Pointer(coeff)), ringq.N)

	if lvl_idx < param.QCount() {
		ring.InvNTT(data_slice, data_slice, ringq.N, ringq.NttPsiInv[lvl_idx], ringq.NttNInv[lvl_idx], ringq.Modulus[lvl_idx], ringq.MredParams[lvl_idx])
	} else {
		ringp := param.RingP()
		sp_lvl_idx := lvl_idx - param.QCount()
		ring.InvNTT(data_slice, data_slice, ringp.N, ringp.NttPsiInv[sp_lvl_idx], ringp.NttNInv[sp_lvl_idx], ringp.Modulus[sp_lvl_idx], ringp.MredParams[sp_lvl_idx])
	}
}

//export BfvComponentMulByPow2Inplace
func BfvComponentMulByPow2Inplace(parameter_handle uint64, coeff *C.uint64_t, lvl_idx int, pow2 int) {
	param := get_object[bfv.Parameters](parameter_handle)
	ringq := param.RingQ()
	data_slice := unsafe.Slice((*uint64)(unsafe.Pointer(coeff)), ringq.N)

	if lvl_idx < param.QCount() {
		ring.MFormVec(data_slice, data_slice, ringq.Modulus[lvl_idx], ringq.BredParams[lvl_idx])
		ring.MulByPow2Vec(data_slice, data_slice, pow2, ringq.Modulus[lvl_idx], ringq.MredParams[lvl_idx])
	} else {
		ringp := param.RingP()
		sp_lvl_idx := lvl_idx - param.QCount()
		ring.MFormVec(data_slice, data_slice, ringp.Modulus[sp_lvl_idx], ringp.BredParams[sp_lvl_idx])
		ring.MulByPow2Vec(data_slice, data_slice, pow2, ringp.Modulus[sp_lvl_idx], ringp.MredParams[sp_lvl_idx])
	}

}

//export CkksComponentMulByPow2Inplace
func CkksComponentMulByPow2Inplace(parameter_handle uint64, coeff *C.uint64_t, lvl_idx int, pow2 int) {
	param := get_object[ckks.Parameters](parameter_handle)
	ringq := param.RingQ()
	data_slice := unsafe.Slice((*uint64)(unsafe.Pointer(coeff)), ringq.N)

	if lvl_idx < param.QCount() {
		ring.MFormVec(data_slice, data_slice, ringq.Modulus[lvl_idx], ringq.BredParams[lvl_idx])
		ring.MulByPow2Vec(data_slice, data_slice, pow2, ringq.Modulus[lvl_idx], ringq.MredParams[lvl_idx])
	} else {
		ringp := param.RingP()
		sp_lvl_idx := lvl_idx - param.QCount()
		ring.MFormVec(data_slice, data_slice, ringp.Modulus[sp_lvl_idx], ringp.BredParams[sp_lvl_idx])
		ring.MulByPow2Vec(data_slice, data_slice, pow2, ringp.Modulus[sp_lvl_idx], ringp.MredParams[sp_lvl_idx])
	}

}

