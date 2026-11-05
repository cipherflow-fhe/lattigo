// @company CipherFlow
package realdft

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	ltcommon "github.com/cipherflow-fhe/lattigo/circuits/ckks/lintrans"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
)

func TestMatrixLiteralMarshalling(t *testing.T) {
	m := MatrixLiteral{
		Type:         HomomorphicDecode,
		LogSlots:     6,
		LevelQ:       12,
		LevelP:       1,
		Levels:       []int{1, 1, 1},
		LogBSGSRatio: 2,
	}

	data, err := m.MarshalBinary()
	require.NoError(t, err)

	mNew := new(MatrixLiteral)
	require.NoError(t, mNew.UnmarshalBinary(data))
	require.Equal(t, m, *mNew)
}

// oneEachLevels returns a factorization description with one matrix per rescale
// group, summing to maxDepth.
func oneEachLevels(maxDepth int) []int {
	levels := make([]int, maxDepth)
	for i := range levels {
		levels[i] = 1
	}
	return levels
}

// ============================================================================
// Dense reference tests
// ============================================================================

func denseFromDiags(N int, diags ltcommon.Diagonals[float64]) [][]float64 {
	M := make([][]float64, N)
	for i := range M {
		M[i] = make([]float64, N)
	}
	for k, d := range diags {
		for row := 0; row < N; row++ {
			if d[row] != 0 {
				M[row][(row+k)%N] += d[row]
			}
		}
	}
	return M
}

func matMul(A, B [][]float64) [][]float64 {
	N := len(A)
	C := make([][]float64, N)
	for i := range C {
		C[i] = make([]float64, N)
		for k := 0; k < N; k++ {
			if A[i][k] == 0 {
				continue
			}
			for j := 0; j < N; j++ {
				C[i][j] += A[i][k] * B[k][j]
			}
		}
	}
	return C
}

func identity(N int) [][]float64 {
	I := make([][]float64, N)
	for i := range I {
		I[i] = make([]float64, N)
		I[i][i] = 1
	}
	return I
}

func relErr(A, B [][]float64) float64 {
	var num, den float64
	for i := range A {
		for j := range A {
			d := A[i][j] - B[i][j]
			num += d * d
			den += B[i][j] * B[i][j]
		}
	}
	return math.Sqrt(num) / math.Sqrt(den)
}

// TestInverse verifies that the generated real DFT factorization is exactly
// inverted by the corresponding inverse factorization, for both the naive
// (one matrix per stage) and level-collapsed factorizations.
func TestInverse(t *testing.T) {
	for _, logN := range []int{3, 4, 5, 6, 7} {
		N := 1 << logN
		for _, maxDepth := range []int{1, 2, 3, logN} {
			if maxDepth > logN {
				continue
			}
			enc := MatrixLiteral{Type: HomomorphicEncode, LogSlots: logN, Levels: oneEachLevels(maxDepth)}.genDiagonals()
			dec := MatrixLiteral{Type: HomomorphicDecode, LogSlots: logN, Levels: oneEachLevels(maxDepth)}.genDiagonals()

			E := identity(N)
			for _, d := range enc {
				E = matMul(denseFromDiags(N, d), E)
			}
			D := identity(N)
			for _, d := range dec {
				D = matMul(denseFromDiags(N, d), D)
			}

			if err := relErr(matMul(D, E), identity(N)); err > 1e-12 {
				t.Fatalf("logN=%d maxDepth=%d: StC*CtS != I, relerr=%v", logN, maxDepth, err)
			}

			// The diagonal count bound (<=6) only holds for the naive factorization.
			if maxDepth == logN {
				for idx, d := range enc {
					if n := len(d.DiagonalsIndexList()); n > 6 && idx != len(enc)-1 {
						t.Fatalf("logN=%d: encode layer %d has %d diagonals (>6)", logN, idx, n)
					}
				}
			}
		}
	}
}

// TestAgainstEncoder verifies that the generated encoding matrix equals
// Lattigo's encoder IFFT (V^{-1}) up to a permutation of the output rows,
// confirming that the slot ordering matches.
func TestAgainstEncoder(t *testing.T) {
	for _, logN := range []int{4, 5, 6} {
		N := 1 << logN

		params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            logN,
			LogQ:            []int{40},
			RingType:        ring.ConjugateInvariant,
			LogDefaultScale: 20,
		})
		require.NoError(t, err)

		enc := MatrixLiteral{Type: HomomorphicEncode, LogSlots: logN, Levels: oneEachLevels(logN)}.genDiagonals()
		E := identity(N)
		for _, d := range enc {
			E = matMul(denseFromDiags(N, d), E)
		}

		ecd := ckks.NewEncoder(params)

		// Column j of Vlat is encoder.IFFT(e_j): coefficient vector for slot basis e_j.
		Vlat := make([][]float64, N)
		for i := range Vlat {
			Vlat[i] = make([]float64, N)
		}
		for j := 0; j < N; j++ {
			vals := make([]complex128, N)
			vals[j] = 1
			if err := ecd.IFFT(vals, logN); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < N; i++ {
				Vlat[i][j] = real(vals[i])
			}
		}

		// Match each row of E to an unused row of Vlat.
		used := make([]bool, N)
		for i := 0; i < N; i++ {
			best, bestErr := -1, math.Inf(1)
			for r := 0; r < N; r++ {
				if used[r] {
					continue
				}
				var num, den float64
				for j := 0; j < N; j++ {
					d := E[i][j] - Vlat[r][j]
					num += d * d
					den += Vlat[r][j] * Vlat[r][j]
				}
				e := math.Sqrt(num) / math.Sqrt(den+1e-30)
				if e < bestErr {
					bestErr, best = e, r
				}
			}
			if bestErr > 1e-9 {
				t.Fatalf("logN=%d: row %d does not match any encoder row (err=%v)", logN, i, bestErr)
			}
			used[best] = true
		}
	}
}

func TestDiagonalsApplyDirection(t *testing.T) {
	const N = 8
	M := make([][]float64, N)
	for i := range M {
		M[i] = make([]float64, N)
		for j := range M[i] {
			M[i][j] = float64((i*3+j*7)%5) - 2
		}
	}

	diags := make(ltcommon.Diagonals[float64])
	for i := 0; i < N; i++ {
		for j := 0; j < N; j++ {
			if M[i][j] != 0 {
				k := ((j-i)%N + N) % N
				if diags[k] == nil {
					diags[k] = make([]float64, N)
				}
				diags[k][i] += M[i][j]
			}
		}
	}

	v := make([]float64, N)
	for i := range v {
		v[i] = float64(i*i%7) - 3
	}

	got := diags.Evaluate(v,
		func(n int) []float64 { return make([]float64, n) },
		func(a, b, c []float64) {
			for i := range c {
				c[i] = a[i] + b[i]
			}
		},
		func(a, b, c []float64) {
			for i := range c {
				c[i] += a[i] * b[i]
			}
		},
	)

	// Expected: out[q] = sum_t v[t] * M[q][t]
	for q := 0; q < N; q++ {
		var want float64
		for tt := 0; tt < N; tt++ {
			want += v[tt] * M[q][tt]
		}
		if math.Abs(got[q]-want) > 1e-12 {
			t.Fatalf("diagonals apply direction mismatch at %d: got %v want %v", q, got[q], want)
		}
	}
}
