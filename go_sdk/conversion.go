package main

// #include <stdint.h>
import "C"

//export BfvPolyNttInplace
func BfvPolyNttInplace(parameter_handle uint64, data *C.uint64_t, level_q int, level_p int) {
}

//export BfvPolyInvNttInplace
func BfvPolyInvNttInplace(parameter_handle uint64, data *C.uint64_t, level_q int, level_p int) {
}

//export BfvPolyMulByPow2Inplace
func BfvPolyMulByPow2Inplace(parameter_handle uint64, data *C.uint64_t, level_q int, level_p int, pow2 int) {
}

//export CkksPolyNttInplace
func CkksPolyNttInplace(parameter_handle uint64, data *C.uint64_t, level_q int, level_p int) {
}

//export CkksPolyInvNttInplace
func CkksPolyInvNttInplace(parameter_handle uint64, data *C.uint64_t, level_q int, level_p int) {
}

//export CkksPolyMulByPow2Inplace
func CkksPolyMulByPow2Inplace(parameter_handle uint64, data *C.uint64_t, level_q int, level_p int, pow2 int) {
}
