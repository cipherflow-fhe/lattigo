package main

/*
#include <stdint.h>
*/
import "C"

//export CreateRandomDBfvContext
func CreateRandomDBfvContext(context_handle uint64, crs_seed *byte, sigma_smudging float64) uint64 {
	return 0
}

//export GetDBfvBfvContext
func GetDBfvBfvContext(context_handle uint64) uint64 {
	return 0
}

//export CreateCKGContext
func CreateCKGContext(context_handle uint64) uint64 {
	return 0
}

//export GenDBfvPublicKeyShare
func GenDBfvPublicKeyShare(context_handle uint64) uint64 {
	return 0
}

//export AggregateDBfvPublicKeyShare
func AggregateDBfvPublicKeyShare(context_handle uint64, x0_share_handle uint64, x1_share_handle uint64) uint64 {
	return 0
}

//export SetDBfvPublicKey
func SetDBfvPublicKey(context_handle uint64, share_handle uint64) {
}

//export SerializeDBfvPublicKeyShare
func SerializeDBfvPublicKeyShare(share_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	return 0
}

//export DeserializeDBfvPublicKeyShare
func DeserializeDBfvPublicKeyShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	return 0
}

//export CreateE2SContext
func CreateE2SContext(context_handle uint64) uint64 {
	return 0
}

//export GenDBfvE2SPublicAndSecretShare
func GenDBfvE2SPublicAndSecretShare(context_handle uint64, ciphertext_handle uint64, secret_share_handle *C.uint64_t) uint64 {
	return 0
}

//export AggregateDBfvE2SCKSShare
func AggregateDBfvE2SCKSShare(context_handle uint64, x0_share_handle uint64, x1_share_handle uint64) uint64 {
	return 0
}

//export GetDBfvE2SSecretShare
func GetDBfvE2SSecretShare(context_handle uint64, ciphertext_handle uint64, public_share_handle uint64, secret_share_handle uint64) uint64 {
	return 0
}

//export AggregateDBfvAdditiveShare
func AggregateDBfvAdditiveShare(context_handle uint64, x0_share_handle uint64, x1_share_handle uint64) uint64 {
	return 0
}

//export SetDBfvE2SPlaintextRingT
func SetDBfvE2SPlaintextRingT(context_handle uint64, secret_share_handle uint64) uint64 {
	return 0
}

//export SerializeDBfvCKSShare
func SerializeDBfvCKSShare(share_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	return 0
}

//export DeserializeDBfvE2SCKSShare
func DeserializeDBfvE2SCKSShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	return 0
}

//export SerializeDBfvAdditiveShare
func SerializeDBfvAdditiveShare(share_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	return 0
}

//export DeserializeDBfvAdditiveShare
func DeserializeDBfvAdditiveShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	return 0
}

//export CreateS2EContext
func CreateS2EContext(context_handle uint64) uint64 {
	return 0
}

//export GenDBfvS2EPublicShare
func GenDBfvS2EPublicShare(context_handle uint64, secret_share_handle uint64) uint64 {
	return 0
}

//export AggregateDBfvS2ECKSShare
func AggregateDBfvS2ECKSShare(context_handle uint64, x0_share_handle uint64, x1_share_handle uint64) uint64 {
	return 0
}

//export SetDBfvS2ECiphertext
func SetDBfvS2ECiphertext(context_handle uint64, public_share_handle uint64) uint64 {
	return 0
}

//export DeserializeDBfvS2ECKSShare
func DeserializeDBfvS2ECKSShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	return 0
}

//export CreateRKGContext
func CreateRKGContext(context_handle uint64) uint64 {
	return 0
}

//export GenDBfvRelinKeyShareRoundOne
func GenDBfvRelinKeyShareRoundOne(context_handle uint64, eph_sk_handle *C.uint64_t) uint64 {
	return 0
}

//export AggregateDBfvRelinKeyShare
func AggregateDBfvRelinKeyShare(context_handle uint64, x0_share_handle uint64, x1_share_handle uint64) uint64 {
	return 0
}

//export GenDBfvRelinKeyShareRoundTwo
func GenDBfvRelinKeyShareRoundTwo(context_handle uint64, eph_sk_handle uint64, share1_handle uint64) uint64 {
	return 0
}

//export SetDBfvRelinKey
func SetDBfvRelinKey(context_handle uint64, share1_handle uint64, share2_handle uint64) {
}

//export SerializeDBfvRelinKeyShare
func SerializeDBfvRelinKeyShare(share_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	return 0
}

//export DeserializeDBfvRelinKeyShare
func DeserializeDBfvRelinKeyShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	return 0
}

//export CreateRTGContext
func CreateRTGContext(context_handle uint64) uint64 {
	return 0
}

//export GenDBfvGaloisKeyShare
func GenDBfvGaloisKeyShare(context_handle uint64, rots *int32, rots_length int, include_swap_rows bool, share_handles *C.uint64_t) int {
	return 0
}

//export AggregateDBfvGaloisKeyShare
func AggregateDBfvGaloisKeyShare(context_handle uint64, x0_share_handles *C.uint64_t, x1_share_handles *C.uint64_t, length int, y_share_handles *C.uint64_t) int {
	return 0
}

//export SetDBfvRotationKey
func SetDBfvRotationKey(context_handle uint64, rots *int32, rots_length int, include_swap_rows bool, share_handles *C.uint64_t) {
}

//export SerializeDBfvGaloisKeyShare
func SerializeDBfvGaloisKeyShare(share_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	return 0
}

//export DeserializeDBfvGaloisKeyShare
func DeserializeDBfvGaloisKeyShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	return 0
}

//export CreateRefreshContext
func CreateRefreshContext(context_handle uint64) uint64 {
	return 0
}

//export GenDBfvRefreshShare
func GenDBfvRefreshShare(context_handle uint64, ciphertext_handle uint64) uint64 {
	return 0
}

//export AggregateDBfvRefreshShare
func AggregateDBfvRefreshShare(context_handle uint64, x0_share_handle uint64, x1_share_handle uint64) uint64 {
	return 0
}

//export DBfvRefreshFinalize
func DBfvRefreshFinalize(context_handle uint64, ciphertext_handle uint64, share_handle uint64) uint64 {
	return 0
}

//export SerializeDBfvRefreshShare
func SerializeDBfvRefreshShare(share_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	return 0
}

//export DeserializeDBfvRefreshShare
func DeserializeDBfvRefreshShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	return 0
}

//export CreateRefreshAndPermuteContext
func CreateRefreshAndPermuteContext(context_handle uint64) uint64 {
	return 0
}

//export GenDBfvRefreshAndPermuteShare
func GenDBfvRefreshAndPermuteShare(context_handle uint64, ciphertext_handle uint64, permute *C.uint64_t) uint64 {
	return 0
}

//export AggregateDBfvRefreshAndPermuteShare
func AggregateDBfvRefreshAndPermuteShare(context_handle uint64, x0_share_handle uint64, x1_share_handle uint64) uint64 {
	return 0
}

//export DBfvRefreshAndPermuteTransform
func DBfvRefreshAndPermuteTransform(context_handle uint64, ciphertext_handle uint64, permute *C.uint64_t, share_handle uint64) uint64 {
	return 0
}

//export SerializeDBfvRefreshAndPermuteShare
func SerializeDBfvRefreshAndPermuteShare(share_handle uint64, raw_data **byte, length *C.uint64_t) uint64 {
	return 0
}

//export DeserializeDBfvvRefreshAndPermuteShare
func DeserializeDBfvvRefreshAndPermuteShare(context_handle uint64, raw_data *byte, length C.uint64_t) uint64 {
	return 0
}
