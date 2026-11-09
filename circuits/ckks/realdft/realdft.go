// Package realdft implements a factorized real DFT/IDFT for the
// conjugate-invariant CKKS ring.
//
// In the conjugate-invariant ring Z[X]/(X^N+1) a plaintext holds N real
// slots. The encoding matrix V maps the coefficient vector of a plaintext
// to its slot vector; its inverse V^{-1} is the map that converts a
// coefficient-encoded ciphertext (the output of the bootstrapping ModRaise)
// into the slot domain, and V is its inverse used to go back.
//
// Following the real iFFT construction of the CI-CKKS bootstrapping paper
// (ePrint 2026/2618, §3.1), V^{-1} factors as
//
//	V^{-1} = (1/N) * P * S_{N/2} * ... * S_2 * S_1
//
// where every layer S_{2m} (stage m -> 2m) has at most 6 non-zero diagonals
// and the final phase-removal map P (expressed in the physical stage-N
// coordinate order) has 3 non-zero diagonals. The phase map P is merged into
// the last butterfly layer S_{N/2}, so the factorization has log2(N) matrices,
// the last one having at most 7 non-zero diagonals. Its inverse V factors as
//
//	V = S_1^T * S_2^T * ... * S_{N/2}^T * P^{-1},
//
// where the scale is one because N/2^{log2 N} = 1 and S_m^{-1} = S_m^T/2.
//
// All matrices are expressed in the slot ordering used by [ckks.Encoder]
// (slot j corresponds to the root ζ_{4N}^{5^j}) so that they can be
// evaluated homomorphically with the generic lintrans machinery: a diagonal
// with index k stores M[row][row+k].
//
// @company CipherFlow
package realdft

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"

	ltcommon "github.com/cipherflow-fhe/lattigo/circuits/ckks/lintrans"
	"github.com/cipherflow-fhe/lattigo/circuits/common/lintrans"
	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
	"github.com/cipherflow-fhe/lattigo/utils/bignum"
)

// Type distinguishes between the two real transforms.
const (
	// HomomorphicEncode is the CoeffsToSlots transform (V^{-1}).
	HomomorphicEncode = Type(0)
	// HomomorphicDecode is the SlotsToCoeffs transform (V).
	HomomorphicDecode = Type(1)
)

// Type is the type of real DFT to generate.
type Type int

// MatrixLiteral is the literal description of a factorized real DFT.
type MatrixLiteral struct {
	// Type is HomomorphicEncode (CoeffsToSlots) or HomomorphicDecode (SlotsToCoeffs).
	Type Type
	// LogSlots is log2 of the number of real slots. Full packing is required,
	// so it must be equal to params.LogMaxDimensions().Cols (= params.LogN()).
	LogSlots int
	// LevelQ is the starting level of the linear transformation.
	LevelQ int
	// LevelP is the number of auxiliary primes used during the automorphisms.
	LevelP int
	// Levels is the factorization depth of each rescale group. Its sum must be
	// in [1, LogSlots]: consecutive butterfly stages are merged (level
	// collapsing) according to this grouping.
	Levels []int
	// LogBSGSRatio is log2 of the baby-step giant-step ratio.
	LogBSGSRatio int
	// Scaling is an optional constant by which the whole transform is multiplied.
	// It is spread uniformly across the factorized matrices. Default 1.0.
	Scaling *big.Float
	// UseDefaultRotationKeys: if true, rotations are evaluated as chains of the
	// default rotations ±2^i instead of being keyed exactly. Default: false.
	UseDefaultRotationKeys bool
}

// Matrix stores the factorized real DFT matrices.
type Matrix struct {
	MatrixLiteral
	Matrices []ltcommon.LinearTransformation
}

// Depth returns the number of matrices in the factorization when actual is
// false, and the number of rescale groups (i.e. consumed levels) otherwise.
func (d MatrixLiteral) Depth(actual bool) (depth int) {
	if actual {
		return len(d.Levels)
	}
	for _, v := range d.Levels {
		depth += v
	}
	return
}

// GaloisElements returns the list of Galois elements required to evaluate the transform.
func (d MatrixLiteral) GaloisElements(params ckks.Parameters) (galEls []uint64) {
	diags := d.genDiagonals()
	identity := params.GaloisElement(0) // the identity rotation needs no key
	seen := make(map[uint64]bool)
	for _, vec := range diags {
		for _, ge := range lintrans.GaloisElements(params, vec.DiagonalsIndexList(), 1<<d.LogSlots, d.LogBSGSRatio) {
			if ge == identity {
				continue
			}
			if !seen[ge] {
				seen[ge] = true
				galEls = append(galEls, ge)
			}
		}
	}
	return
}

// MarshalBinary returns a JSON representation of the target [MatrixLiteral] on a slice of bytes.
// See `Marshal` from the `encoding/json` package.
func (d MatrixLiteral) MarshalBinary() (data []byte, err error) {
	return json.Marshal(d)
}

// UnmarshalBinary reads a JSON representation on the target [MatrixLiteral] struct.
// See `Unmarshal` from the `encoding/json` package.
func (d *MatrixLiteral) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, d)
}

// NewMatrixFromLiteral generates the factorized real DFT matrices.
func NewMatrixFromLiteral(params ckks.Parameters, d MatrixLiteral, encoder *ckks.Encoder) (Matrix, error) {
	if params.RingType() != ring.ConjugateInvariant {
		return Matrix{}, fmt.Errorf("cannot NewMatrixFromLiteral: realdft requires the conjugate-invariant ring type but got %v", params.RingType())
	}
	if maxLogSlots := params.LogMaxDimensions().Cols; d.LogSlots != maxLogSlots {
		return Matrix{}, fmt.Errorf("cannot NewMatrixFromLiteral: realdft requires full packing, LogSlots=%d but max is %d", d.LogSlots, maxLogSlots)
	}
	if d.Depth(false) < 1 || d.Depth(false) > d.LogSlots {
		return Matrix{}, fmt.Errorf("cannot NewMatrixFromLiteral: sum(Levels)=%d must be in [1, LogSlots=%d]", d.Depth(false), d.LogSlots)
	}

	diags := d.genDiagonals()

	nbModuliPerRescale := params.LevelsConsumedPerRescaling()

	level := d.LevelQ
	var idx int
	matrices := make([]ltcommon.LinearTransformation, 0, len(diags))

	for i := range d.Levels {
		scale := rlwe.NewScale(params.Q()[level])

		for j := 1; j < nbModuliPerRescale; j++ {
			scale = scale.Mul(rlwe.NewScale(params.Q()[level-j]))
		}

		if d.Levels[i] > 1 {
			y := new(big.Float).SetPrec(scale.Value.Prec()).SetInt64(1)
			y.Quo(y, new(big.Float).SetPrec(scale.Value.Prec()).SetInt64(int64(d.Levels[i])))
			scale.Value = *bignum.Pow(&scale.Value, y)
		}

		for j := 0; j < d.Levels[i]; j++ {
			ltparams := ltcommon.Parameters{
				DiagonalsIndexList:        diags[idx].DiagonalsIndexList(),
				LevelQ:                    d.LevelQ,
				LevelP:                    d.LevelP,
				Scale:                     scale,
				LogDimensions:             ring.Dimensions{Rows: 0, Cols: d.LogSlots},
				LogBabyStepGiantStepRatio: d.LogBSGSRatio,
				UseDefaultRotationKeys:    d.UseDefaultRotationKeys,
			}

			mat := ltcommon.NewTransformation(params, ltparams)
			if err := ltcommon.Encode(encoder, diags[idx], mat); err != nil {
				return Matrix{}, fmt.Errorf("cannot NewMatrixFromLiteral: %w", err)
			}

			matrices = append(matrices, mat)
			idx++
		}

		level -= nbModuliPerRescale
	}

	return Matrix{MatrixLiteral: d, Matrices: matrices}, nil
}

// ============================================================================
// Matrix generation
// ============================================================================

type part int

const (
	partReal part = iota
	partRe
	partIm
)

// coord is a coordinate of the real representation of the stage-S vectors of
// the real iFFT factorization.
type coord struct {
	r int
	p part
	j int
}

type unit struct {
	r    int
	pair bool
}

// unitsStage returns the units of the real representation at stage m.
// A "real" unit is a real sub-vector, a "pair" unit is a conjugate pair of
// complex sub-vectors stored as (sqrt2 Re, sqrt2 Im).
func unitsStage(m int) []unit {
	us := []unit{{0, false}}
	for s := 1; s < m; s <<= 1 {
		next := make([]unit, 0, 2*len(us))
		for _, u := range us {
			if !u.pair {
				if u.r == 0 {
					next = append(next, unit{0, false}, unit{s, false})
				} else {
					next = append(next, unit{s >> 1, true})
				}
			} else {
				next = append(next, unit{u.r, true}, unit{s - u.r, true})
			}
		}
		us = next
	}
	return us
}

// coordsStage returns the ordering of the N real coordinates at stage S.
// Each unit's coordinates are contiguous, and inside a pair unit the real
// parts of all j come before the imaginary parts of all j (Figure 2 of the paper).
func coordsStage(N, S int) []coord {
	L := N / S
	us := unitsStage(S)
	out := make([]coord, 0, N)
	for _, u := range us {
		if !u.pair {
			for j := 0; j < L; j++ {
				out = append(out, coord{u.r, partReal, j})
			}
		} else {
			for j := 0; j < L; j++ {
				out = append(out, coord{u.r, partRe, j})
			}
			for j := 0; j < L; j++ {
				out = append(out, coord{u.r, partIm, j})
			}
		}
	}
	return out
}

func indexMap(cs []coord) map[coord]int {
	m := make(map[coord]int, len(cs))
	for i, c := range cs {
		m[c] = i
	}
	return m
}

// dcoef is the sqrt2 storage factor of a coordinate.
func dcoef(c coord) float64 {
	if c.p == partReal {
		return 1
	}
	return math.Sqrt2
}

// omega returns omega_{m,j,r} = zeta^{-r (5^{j+L} - 5^j)} with L = N/(2m) and
// zeta = exp(2*pi*i/(4N)). The roots of unity and powers of five are taken from
// the precomputed tables.
func omega(roots []complex128, pow5 []int, N, m, j, r int) complex128 {
	L := N / (2 * m)
	mod := 4 * N
	e := -(r * (pow5[j+L] - pow5[j]))
	e = ((e % mod) + mod) % mod
	return roots[e]
}

// buildLayer returns the diagonals of the stored (sqrt2) layer S_{2m} mapping
// the stage-m coordinates to the stage-2m coordinates.
func buildLayer(roots []complex128, pow5 []int, N, m int) ltcommon.Diagonals[float64] {

	L := N / (2 * m)
	inCoords := coordsStage(N, m)
	outCoords := coordsStage(N, 2*m)
	inPos := indexMap(inCoords)
	outPos := indexMap(outCoords)

	diags := make(ltcommon.Diagonals[float64])

	add := func(oc, ic coord, coef float64) {
		if math.Abs(coef) < 1e-12 {
			return
		}
		o, ok := outPos[oc]
		if !ok {
			panic(fmt.Sprintf("realdft: missing output coordinate %v", oc))
		}
		i, ok := inPos[ic]
		if !ok {
			panic(fmt.Sprintf("realdft: missing input coordinate %v", ic))
		}
		k := ((i-o)%N + N) % N
		if diags[k] == nil {
			diags[k] = make([]float64, N)
		}
		diags[k][o] += coef / math.Sqrt2 * dcoef(oc) / dcoef(ic)
	}

	// G_real (r = 0)
	for j := 0; j < L; j++ {
		add(coord{0, partReal, j}, coord{0, partReal, j}, 1)
		add(coord{0, partReal, j}, coord{0, partReal, j + L}, 1)
		add(coord{m, partReal, j}, coord{0, partReal, j}, 1)
		add(coord{m, partReal, j}, coord{0, partReal, j + L}, -1)
	}

	// G_split (r = m/2), only for m >= 2
	if m >= 2 {
		for j := 0; j < L; j++ {
			add(coord{m / 2, partRe, j}, coord{m / 2, partReal, j}, 1)
			add(coord{m / 2, partIm, j}, coord{m / 2, partReal, j + L}, imag(omega(roots, pow5, N, m, j, m/2)))
		}
	}

	// G_r
	for r := 1; r < m/2; r++ {
		for j := 0; j < L; j++ {
			w := omega(roots, pow5, N, m, j, r)
			a, b := real(w), imag(w)

			ins := [4]coord{
				{r, partRe, j},
				{r, partRe, j + L},
				{r, partIm, j},
				{r, partIm, j + L},
			}

			rows := [4]struct {
				oc  coord
				row [4]float64
			}{
				{coord{r, partRe, j}, [4]float64{1, a, 0, -b}},
				{coord{r, partIm, j}, [4]float64{0, b, 1, a}},
				{coord{m - r, partRe, j}, [4]float64{1, -a, 0, b}},
				{coord{m - r, partIm, j}, [4]float64{0, b, -1, a}},
			}

			for _, rr := range rows {
				for k, c := range rr.row {
					add(rr.oc, ins[k], c)
				}
			}
		}
	}

	return diags
}

// phaseEntries returns the diagonals of the phase-removal map P in the physical
// stage-N coordinate order. P is block diagonal: two scalar entries and N/2-1
// 2x2 blocks, hence 3 non-zero diagonals.
func phaseEntries(N int) ltcommon.Diagonals[float64] {
	pos := indexMap(coordsStage(N, N))
	diags := make(ltcommon.Diagonals[float64])

	add := func(row, col int, v float64) {
		k := ((col-row)%N + N) % N
		if diags[k] == nil {
			diags[k] = make([]float64, N)
		}
		diags[k][row] += v
	}

	p0 := pos[coord{0, partReal, 0}]
	add(p0, p0, 1)

	pk := pos[coord{N / 2, partReal, 0}]
	add(pk, pk, math.Cos(2*math.Pi*float64(N/2)/float64(4*N))) // sqrt2/2

	for r := 1; r < N/2; r++ {
		pr := pos[coord{r, partRe, 0}]
		pi := pos[coord{r, partIm, 0}]
		th := math.Pi * float64(r) / float64(2*N)
		c, s := math.Cos(th), math.Sin(th)
		add(pr, pr, c/math.Sqrt2)
		add(pr, pi, s/math.Sqrt2)
		add(pi, pr, s/math.Sqrt2)
		add(pi, pi, -c/math.Sqrt2)
	}

	return diags
}

// phaseInvEntries returns the diagonals of P^{-1}. Each 2x2 block B satisfies
// B^2 = I/2, hence B^{-1} = 2B; only the r=N/2 scalar also differs from P.
func phaseInvEntries(N int) ltcommon.Diagonals[float64] {
	pos := indexMap(coordsStage(N, N))
	diags := make(ltcommon.Diagonals[float64])

	add := func(row, col int, v float64) {
		k := ((col-row)%N + N) % N
		if diags[k] == nil {
			diags[k] = make([]float64, N)
		}
		diags[k][row] += v
	}

	p0 := pos[coord{0, partReal, 0}]
	add(p0, p0, 1)

	pk := pos[coord{N / 2, partReal, 0}]
	add(pk, pk, math.Sqrt2)

	for r := 1; r < N/2; r++ {
		pr := pos[coord{r, partRe, 0}]
		pi := pos[coord{r, partIm, 0}]
		th := math.Pi * float64(r) / float64(2*N)
		c, s := math.Cos(th), math.Sin(th)
		add(pr, pr, math.Sqrt2*c)
		add(pr, pi, math.Sqrt2*s)
		add(pi, pr, math.Sqrt2*s)
		add(pi, pi, -math.Sqrt2*c)
	}

	return diags
}

// transposeDiagonals returns the diagonals of the transpose of the matrix
// described by diags.
func transposeDiagonals(N int, diags ltcommon.Diagonals[float64]) ltcommon.Diagonals[float64] {
	out := make(ltcommon.Diagonals[float64])
	for k, d := range diags {
		nk := ((-k)%N + N) % N
		if out[nk] == nil {
			out[nk] = make([]float64, N)
		}
		for i := 0; i < N; i++ {
			out[nk][i] += d[((i-k)%N+N)%N]
		}
	}
	return out
}

// mulDiagonals returns the diagonals of the matrix product A*B.
func mulDiagonals(N int, A, B ltcommon.Diagonals[float64]) ltcommon.Diagonals[float64] {
	C := make(ltcommon.Diagonals[float64])
	for kA, dA := range A {
		for kB, dB := range B {
			m := (kA + kB) % N
			if C[m] == nil {
				C[m] = make([]float64, N)
			}
			for i := 0; i < N; i++ {
				C[m][i] += dA[i] * dB[(i+kA)%N]
			}
		}
	}
	return C
}

// scaleDiagonals multiplies every entry of diags by norm, in place.
func scaleDiagonals(diags ltcommon.Diagonals[float64], norm float64) ltcommon.Diagonals[float64] {
	for _, d := range diags {
		for i := range d {
			d[i] *= norm
		}
	}
	return diags
}

// genDiagonals returns the ordered list of matrices to be applied sequentially.
//
// The factorization has d.Depth(false) matrices (one per rescale group): the
// LogSlots butterfly stages are merged (level collapsing) according to the
// rescale grouping described by d.Levels. The phase map P (encode) or its
// inverse P^{-1} (decode) is merged into the last/first butterfly stage.
func (d MatrixLiteral) genDiagonals() []ltcommon.Diagonals[float64] {

	N := 1 << d.LogSlots

	roots := ckks.GetRootsComplex128(4 * N)
	pow5 := make([]int, N)
	pow5[0] = 1
	for i := 1; i < N; i++ {
		pow5[i] = pow5[i-1] * 5
		pow5[i] &= (N << 2) - 1
	}

	maxDepth := d.Depth(false)
	mats := make([]ltcommon.Diagonals[float64], 0, maxDepth)

	// Spread the optional constant scaling uniformly across the maxDepth
	// factorized matrices so that their product equals d.Scaling.
	perMatScale := 1.0
	if d.Scaling != nil {
		total, _ := d.Scaling.Float64()
		perMatScale = math.Pow(total, 1/float64(maxDepth))
	}

	// The global normalization of the transform is spread uniformly across the
	// LogSlots butterfly stages instead of being concentrated into the
	// phase-removal stage. Concentrating it (√N for V, 1/√N for V^{-1}) into a
	// single matrix makes that matrix's coefficients √N times larger than the
	// others, which degrades the precision of the homomorphic evaluation.
	// Spreading it keeps every factorized matrix at a comparable magnitude.
	var perStageScale float64
	if d.Type == HomomorphicEncode {
		perStageScale = math.Pow(1.0/math.Sqrt(float64(N)), 1.0/float64(d.LogSlots))
	} else {
		perStageScale = math.Pow(math.Sqrt(float64(N)), 1.0/float64(d.LogSlots))
	}

	// Generates the LogSlots butterfly stages.
	stages := make([]ltcommon.Diagonals[float64], 0, d.LogSlots)
	if d.Type == HomomorphicEncode {
		for m := 1; m < N/2; m <<= 1 {
			stages = append(stages, scaleDiagonals(buildLayer(roots, pow5, N, m), perStageScale))
		}
		stages = append(stages, scaleDiagonals(mulDiagonals(N, phaseEntries(N), buildLayer(roots, pow5, N, N/2)), perStageScale))
	} else {
		stages = append(stages, scaleDiagonals(mulDiagonals(N, transposeDiagonals(N, buildLayer(roots, pow5, N, N/2)), phaseInvEntries(N)), perStageScale))
		for m := N / 4; m >= 1; m >>= 1 {
			stages = append(stages, scaleDiagonals(transposeDiagonals(N, buildLayer(roots, pow5, N, m)), perStageScale))
		}
	}

	// Distributes the LogSlots stages across the maxDepth matrices (level
	// collapsing). As in the standard DFT, the merging order differs between
	// encode and decode because it impacts the total number of rotations.
	merge := make([]int, maxDepth)
	level := d.LogSlots
	for i := 0; i < maxDepth; i++ {
		depth := int(math.Ceil(float64(level) / float64(maxDepth-i)))
		if d.Type == HomomorphicEncode {
			merge[i] = depth
		} else {
			merge[maxDepth-1-i] = depth
		}
		level -= depth
	}

	// Merges the stages of each rescale group and applies the uniform scaling.
	start := 0
	for i := 0; i < maxDepth; i++ {
		merged := stages[start+merge[i]-1]
		for k := start + merge[i] - 2; k >= start; k-- {
			merged = mulDiagonals(N, merged, stages[k])
		}
		mats = append(mats, scaleDiagonals(merged, perMatScale))
		start += merge[i]
	}

	return mats
}
