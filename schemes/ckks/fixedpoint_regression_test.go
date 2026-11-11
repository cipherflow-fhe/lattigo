package ckks

import (
	"math"
	"math/big"
	"testing"

	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/utils/bignum"
)

func TestFixedPointCRTMatchesLegacy(t *testing.T) {
	for _, typ := range []ring.Type{ring.Standard, ring.ConjugateInvariant} {
		r, err := ring.NewRingFromType(16, []uint64{0x10000000006e0001, 0x1000000000860001}, typ)
		if err != nil {
			t.Fatal(err)
		}
		for level := 0; level <= r.MaxLevel(); level++ {
			rr := r.AtLevel(level)
			want, got := rr.NewPoly(), rr.NewPoly()
			for _, scale := range []float64{1, math.Exp2(40), math.Exp2(64)} {
				for _, v := range []float64{0, math.Copysign(0, -1), 1, -1, 0.5, -0.5, 1e-20, -1e-20, math.Exp2(61), -math.Exp2(61), math.Nextafter(math.Exp2(64), 0), math.Exp2(64), -math.Exp2(64), 1e30, -1e30} {
					legacySingleFloat64ToFixedPointCRT(rr, 0, v, scale, want.Coeffs)
					SingleFloat64ToFixedPointCRT(rr, 0, v, scale, got.Coeffs)
					for j := 0; j <= level; j++ {
						if got.Coeffs[j][0] != want.Coeffs[j][0] {
							t.Fatalf("type=%v level=%d v=%g scale=%g: got %d want %d", typ, level, v, scale, got.Coeffs[j][0], want.Coeffs[j][0])
						}
					}
				}
			}
		}
	}
}

func BenchmarkRingTCoefficients(b *testing.B) {
	r, err := ring.NewRingFromType(32768, []uint64{2251799813554177, 1099512938497, 1099510054913, 1099507695617, 1099515691009, 1099516870657, 1099506515969, 1099504549889, 1099503894529, 1099503370241, 1099502714881, 1099521458177, 1099522375681}, ring.ConjugateInvariant)
	if err != nil {
		b.Fatal(err)
	}
	values := make([]complex128, 32768)
	for i := range values {
		values[i] = complex(float64(i%101-50)/51, 0)
	}
	coeffs := make([]uint64, 32768)
	b.Run("legacy", func(b *testing.B) {
		rr := r.AtLevel(0)
		crt := [][]uint64{coeffs}
		b.ReportAllocs()
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			for i, v := range values {
				legacySingleFloat64ToFixedPointCRT(rr, i, real(v), math.Exp2(40), crt)
			}
		}
	})
	b.Run("direct", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			Complex128ToFixedPointRingT(r, values, math.Exp2(40), coeffs)
		}
	})
}

func legacySingleFloat64ToFixedPointCRT(r *ring.Ring, i int, value float64, scale float64, coeffs [][]uint64) {

	if value == 0 {
		for j := range coeffs {
			coeffs[j][i] = 0
		}

		return
	}

	var isNegative bool
	var xFlo *big.Float
	var xInt *big.Int
	tmp := new(big.Int)
	var c uint64

	isNegative = false

	if value < 0 {
		isNegative = true
		scale *= -1
	}

	value *= scale

	moduli := r.ModuliChain()[:r.Level()+1]

	if value >= 1.8446744073709552e+19 {
		xFlo = big.NewFloat(value)
		xFlo.Add(xFlo, big.NewFloat(0.5))
		xInt = new(big.Int)
		xFlo.Int(xInt)
		for j := range moduli {
			tmp.Mod(xInt, bignum.NewInt(moduli[j]))
			if isNegative {
				coeffs[j][i] = moduli[j] - tmp.Uint64()
			} else {
				coeffs[j][i] = tmp.Uint64()
			}
		}

	} else {
		brc := r.BRedConstants()

		c = uint64(value + 0.5)
		if isNegative {
			for j, qi := range moduli {
				if c > qi {
					coeffs[j][i] = qi - ring.BRedAdd(c, qi, brc[j])
				} else {
					coeffs[j][i] = qi - c
				}
			}
		} else {
			for j, qi := range moduli {
				if c > 0x1fffffffffffffff {
					coeffs[j][i] = ring.BRedAdd(c, qi, brc[j])
				} else {
					coeffs[j][i] = c
				}
			}
		}
	}
}
