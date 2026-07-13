package main

// #include <stdint.h>
import "C"
import (
	"github.com/cipherflow-fhe/lattigo/bfv"
	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/ring"
)

func qp_poly_views(data *C.uint64_t, ring_degree int, level_q int, level_p int) (*ring.Poly, *ring.Poly) {
	q_size := level_q + 1
	q_poly := poly_view_from_flat_rns(data, q_size, ring_degree)
	if level_p < 0 {
		return q_poly, nil
	}
	p_poly := poly_view_from_flat_rns(uint64_ptr_at(data, q_size*ring_degree), level_p+1, ring_degree)
	return q_poly, p_poly
}

//export BfvPolyNttInplace
func BfvPolyNttInplace(parameter_handle uint64, data *C.uint64_t, level_q int, level_p int) {
	param := get_object[bfv.Parameters](parameter_handle)
	q_poly, p_poly := qp_poly_views(data, param.RingQ().N, level_q, level_p)
	param.RingQ().NTTLvl(level_q, q_poly, q_poly)
	if p_poly != nil {
		param.RingP().NTTLvl(level_p, p_poly, p_poly)
	}
}

//export BfvPolyInvNttInplace
func BfvPolyInvNttInplace(parameter_handle uint64, data *C.uint64_t, level_q int, level_p int) {
	param := get_object[bfv.Parameters](parameter_handle)
	q_poly, p_poly := qp_poly_views(data, param.RingQ().N, level_q, level_p)
	param.RingQ().InvNTTLvl(level_q, q_poly, q_poly)
	if p_poly != nil {
		param.RingP().InvNTTLvl(level_p, p_poly, p_poly)
	}
}

//export BfvPolyMulByPow2Inplace
func BfvPolyMulByPow2Inplace(parameter_handle uint64, data *C.uint64_t, level_q int, level_p int, pow2 int) {
	param := get_object[bfv.Parameters](parameter_handle)
	q_poly, p_poly := qp_poly_views(data, param.RingQ().N, level_q, level_p)
	param.RingQ().MulByPow2Lvl(level_q, q_poly, pow2, q_poly)
	if p_poly != nil {
		param.RingP().MulByPow2Lvl(level_p, p_poly, pow2, p_poly)
	}
}

//export CkksPolyNttInplace
func CkksPolyNttInplace(parameter_handle uint64, data *C.uint64_t, level_q int, level_p int) {
	param := get_object[ckks.Parameters](parameter_handle)
	q_poly, p_poly := qp_poly_views(data, param.RingQ().N, level_q, level_p)
	param.RingQ().NTTLvl(level_q, q_poly, q_poly)
	if p_poly != nil {
		param.RingP().NTTLvl(level_p, p_poly, p_poly)
	}
}

//export CkksPolyInvNttInplace
func CkksPolyInvNttInplace(parameter_handle uint64, data *C.uint64_t, level_q int, level_p int) {
	param := get_object[ckks.Parameters](parameter_handle)
	q_poly, p_poly := qp_poly_views(data, param.RingQ().N, level_q, level_p)
	param.RingQ().InvNTTLvl(level_q, q_poly, q_poly)
	if p_poly != nil {
		param.RingP().InvNTTLvl(level_p, p_poly, p_poly)
	}
}

//export CkksPolyMulByPow2Inplace
func CkksPolyMulByPow2Inplace(parameter_handle uint64, data *C.uint64_t, level_q int, level_p int, pow2 int) {
	param := get_object[ckks.Parameters](parameter_handle)
	q_poly, p_poly := qp_poly_views(data, param.RingQ().N, level_q, level_p)
	param.RingQ().MulByPow2Lvl(level_q, q_poly, pow2, q_poly)
	if p_poly != nil {
		param.RingP().MulByPow2Lvl(level_p, p_poly, pow2, p_poly)
	}
}
