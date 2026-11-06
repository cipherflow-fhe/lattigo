package clientcontext

import (
	"slices"

	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
)

// KeyCapability describes an actual generated v6 key without allocating it.
// uint64 fields remain exact when the profile crosses a JSON/JavaScript boundary.
type KeyCapability struct {
	Role                 string `json:"role"`
	Kind                 string `json:"kind"`
	GaloisElement        uint64 `json:"galoisElement,string,omitempty"`
	LogN                 int    `json:"logN"`
	RingType             int    `json:"ringType"`
	NthRoot              uint64 `json:"nthRoot,string"`
	LevelQ               int    `json:"levelQ"`
	LevelP               int    `json:"levelP"`
	BaseTwoDecomposition int    `json:"baseTwoDecomposition"`
	DecompositionRNS     int    `json:"decompositionRNS"`
	Compressed           bool   `json:"compressed"`
}

// DescribeKeyPlan uses the same parameter/rotation derivation as WriteEval.
// The SDK currently generates uncompressed keys with the v6 default base two
// decomposition; no compatibility mapping or second key state is introduced.
func DescribeKeyPlan(params ckks.Parameters, plan KeyPlan) ([]KeyCapability, error) {
	c, err := prepare(params, plan)
	if err != nil {
		return nil, err
	}
	keys := []KeyCapability{}
	add := func(p rlwe.Parameters, role, kind string, galEl uint64) {
		q, special, baseTwo, compressed := rlwe.ResolveEvaluationKeyParameters(p, nil)
		keys = append(keys, KeyCapability{Role: role, Kind: kind, GaloisElement: galEl,
			LogN: p.LogN(), RingType: int(p.RingType()), NthRoot: p.RingQ().NthRoot(),
			LevelQ: q, LevelP: special, BaseTwoDecomposition: baseTwo,
			DecompositionRNS: p.BaseRNSDecompositionVectorSize(q, special), Compressed: compressed})
	}
	add(params.Parameters, "residual", "rlk", 0)
	for _, element := range c.galEls {
		add(params.Parameters, "residual", "glk", element)
	}
	if c.btp == nil {
		return keys, nil
	}
	boot := c.btp.BootstrappingParameters
	if params.N() != boot.N() {
		if params.RingType() == ring.ConjugateInvariant {
			add(boot.Parameters, "bootstrap", "evk_ci_to_std", 0)
			add(boot.Parameters, "bootstrap", "evk_std_to_ci", 0)
		} else {
			add(boot.Parameters, "bootstrap", "evk_n1_to_n2", 0)
			add(boot.Parameters, "bootstrap", "evk_n2_to_n1", 0)
		}
	}
	if c.btp.EphemeralSecretWeight != 0 {
		sparse, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{LogN: boot.LogN(), Q: boot.Q()[:1], P: boot.P()})
		if err != nil {
			return nil, err
		}
		add(sparse, "bootstrap", "evk_dense_to_sparse", 0)
		add(boot.Parameters, "bootstrap", "evk_sparse_to_dense", 0)
	}
	add(boot.Parameters, "bootstrap", "rlk", 0)
	elements := append(c.btp.GaloisElements(boot), boot.GaloisElementForComplexConjugation())
	slices.Sort(elements)
	for _, element := range slices.Compact(elements) {
		add(boot.Parameters, "bootstrap", "glk", element)
	}
	return keys, nil
}
