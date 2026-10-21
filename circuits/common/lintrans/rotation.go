package lintrans

import "math/bits"

// NAFRotationSubsteps decomposes the rotation by step into a shortest chain of
// substeps, each of which is a signed power of two. It is assumed that Galois keys are
// available only for the rotations ±2^i, so an arbitrary rotation must be evaluated by
// successively rotating by each substep.
//
// The decomposition uses the non-adjacent form (NAF) of step modulo slots. The returned
// substeps sum to step modulo slots and every substep satisfies |substep| < slots.
// Substeps that are multiples of slots (identity rotations) are omitted.
//
// For example, with slots = 32, step = 11 returns [16, -4, -1] (16 - 4 - 1 = 11).
//
// @company CipherFlow
func NAFRotationSubsteps(step, slots int) []int {

	k := step % slots
	if k < 0 {
		k += slots
	}

	xh := k >> 1
	x3 := k + xh
	changed := xh ^ x3
	pos := x3 & changed
	neg := xh & changed

	substeps := make([]int, 0, bits.OnesCount(uint(pos))+bits.OnesCount(uint(neg)))

	for i := bits.Len(uint(pos)) - 1; i >= 0; i-- {
		if pos&(1<<i) != 0 {
			substeps = append(substeps, 1<<i)
		}
	}

	for i := bits.Len(uint(neg)) - 1; i >= 0; i-- {
		if neg&(1<<i) != 0 {
			substeps = append(substeps, -(1 << i))
		}
	}

	// Drop the identity substeps (multiples of slots).
	out := substeps[:0]
	for _, substep := range substeps {
		if substep < slots && substep > -slots {
			out = append(out, substep)
		}
	}

	return out
}
