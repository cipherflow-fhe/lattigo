package main

import (
	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
	"testing"
)

func TestCustomCkksSecretWeight(t *testing.T) {
	base, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 10, LogQ: []int{50, 40}, LogP: []int{50}, LogDefaultScale: 40,
	})
	if err != nil {
		t.Fatal(err)
	}
	params, err := newCustomCkksParameters(10, 40, base.Q(), base.P(), ring.Standard, 192)
	if err != nil {
		t.Fatal(err)
	}
	if params.Xs().(ring.Ternary).H != 192 {
		t.Fatal("H192 not applied")
	}
	sk := rlwe.NewKeyGenerator(params).GenSecretKeyNew()
	coeffs := sk.Value.Q.CopyNew()
	params.RingQ().INTT(*coeffs, *coeffs)
	params.RingQ().IMForm(*coeffs, *coeffs)
	count := 0
	for _, c := range coeffs.Coeffs[0] {
		if c != 0 {
			count++
		}
	}
	if count != 192 {
		t.Fatalf("sampled secret has weight %d", count)
	}
	raw, err := params.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var restored ckks.Parameters
	if err = restored.UnmarshalBinary(raw); err != nil || !params.Equal(&restored) {
		t.Fatalf("secret distribution lost on restore: %v", err)
	}
	def, err := newCustomCkksParameters(10, 40, base.Q(), base.P(), ring.Standard, 0)
	if err != nil || !def.Equal(&base) {
		t.Fatalf("default distribution changed: %v", err)
	}
	for _, h := range []int{-1, 1025} {
		if _, err := newCustomCkksParameters(10, 40, base.Q(), base.P(), ring.Standard, h); err == nil {
			t.Fatalf("invalid weight %d accepted", h)
		}
	}
}
