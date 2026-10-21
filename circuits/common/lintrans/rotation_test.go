package lintrans

import (
	"math/bits"
	"testing"

	"github.com/stretchr/testify/require"
)

// @company CipherFlow
func rotationTestAbs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// @company CipherFlow
func rotationTestMod(x, m int) int {
	x %= m
	if x < 0 {
		x += m
	}
	return x
}

// @company CipherFlow
func TestNAFRotationSubsteps(t *testing.T) {

	for logSlots := 1; logSlots <= 10; logSlots++ {

		slots := 1 << logSlots

		for step := -2 * slots; step <= 2*slots; step++ {

			substeps := NAFRotationSubsteps(step, slots)

			sum := 0
			for _, substep := range substeps {
				require.NotZero(t, substep, "step=%d slots=%d returned a zero substep", step, slots)
				require.Equal(t, 1, bits.OnesCount(uint(rotationTestAbs(substep))), "step=%d slots=%d substep=%d is not a power of two", step, slots, substep)
				require.Less(t, rotationTestAbs(substep), slots, "step=%d slots=%d substep=%d is not smaller than slots", step, slots, substep)
				sum += substep
			}

			require.Equal(t, rotationTestMod(step, slots), rotationTestMod(sum, slots), "step=%d slots=%d substeps=%v do not sum to step", step, slots, substeps)
		}
	}

	// Explicit cases.
	require.Equal(t, []int{16, -4, -1}, NAFRotationSubsteps(11, 32))
	require.Equal(t, []int{}, NAFRotationSubsteps(0, 32))
	require.Equal(t, []int{}, NAFRotationSubsteps(32, 32)) // Identity.
	require.Equal(t, []int{1}, NAFRotationSubsteps(1, 32))
	require.Equal(t, []int{-1}, NAFRotationSubsteps(31, 32)) // 31 = -1 mod 32.
	require.Equal(t, []int{-1}, NAFRotationSubsteps(-1, 32))
}
