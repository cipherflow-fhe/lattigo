// Package clientcontext shares v6 client key state and streaming persistence
// between the native SDK and pure-Go/WASM clients.
package clientcontext

import (
	"fmt"

	"github.com/cipherflow-fhe/lattigo/circuits/ckks/bootstrapping"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
	"github.com/cipherflow-fhe/lattigo/utils"
)

// BootstrappingParameters is the SDK's residual-to-circuit parameter derivation.
// Keep it shared: native and WASM must not maintain independent parameter tables.
func BootstrappingParameters(params ckks.Parameters) (bootstrapping.Parameters, error) {
	switch params.LogN() {
	case 14, 15, 16:
	default:
		return bootstrapping.Parameters{}, fmt.Errorf("no bootstrapping parameter set for residual LogN=%d", params.LogN())
	}
	const bootLogN = 16
	if params.RingType() == ring.ConjugateInvariant && bootLogN != params.LogN()+1 {
		return bootstrapping.Parameters{}, fmt.Errorf("bootstrapping LogN must be residual LogN + 1 for the conjugate invariant ring, got %d", bootLogN)
	}
	p, err := bootstrapping.NewParametersFromLiteral(params, bootstrapping.ParametersLiteral{
		LogN: utils.Pointy(bootLogN),
		SlotsToCoeffsFactorizationDepthAndLogScales: [][]int{{39}, {39}, {39}},
		CoeffsToSlotsFactorizationDepthAndLogScales: [][]int{{56}, {56}, {56}, {56}},
		EvalModLogScale: utils.Pointy(60),
	})
	if err != nil {
		return bootstrapping.Parameters{}, err
	}
	p.SlotsToCoeffsParameters.LogSlots = bootLogN - 1
	p.CoeffsToSlotsParameters.LogSlots = bootLogN - 1
	p.Mod1ParametersLiteral.LogMessageRatio += bootLogN - params.LogN()
	return p, nil
}
