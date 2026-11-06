//go:build js && wasm

package clientcontext

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall/js"
	"testing"
	"time"

	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
)

// TestWASMMemoryProbe is opt-in: real PN15 keys are expensive to generate.
func TestWASMMemoryProbe(t *testing.T) {
	mode := os.Getenv("TAA_WASM_PROBE")
	if mode == "" {
		t.Skip("set TAA_WASM_PROBE to residual, ring-swap, or boot")
	}
	data, err := os.ReadFile(os.Getenv("TAA_PARAMETER_JSON"))
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		CKKS map[string]struct {
			Q, P            []uint64
			LogDefaultScale int `json:"log_default_scale"`
		} `json:"CKKS"`
	}
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatal(err)
	}
	p := table.CKKS["15"]
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 15, Q: p.Q, P: p.P, LogDefaultScale: p.LogDefaultScale, RingType: ring.ConjugateInvariant})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	report := func(stage string, n int64) {
		fmt.Printf("PROBE mode=%s stage=%s elapsed=%s wasm_bytes=%.0f key_bytes=%d\n", mode, stage, time.Since(started), js.Global().Get("taaWasmMemoryBytes").Invoke().Float(), n)
	}
	write := func(label string, key io.WriterTo) {
		n, err := key.WriteTo(io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		report(label, n)
	}
	sk := rlwe.NewKeyGenerator(params).GenSecretKeyNew()
	report("residual_secret", 0)
	if mode == "residual" {
		key := rlwe.NewKeyGenerator(params).GenRelinearizationKeyNew(sk)
		report("generated", 0)
		write("written", key)
		return
	}
	btp, err := BootstrappingParameters(params)
	if err != nil {
		t.Fatal(err)
	}
	kgen := rlwe.NewKeyGenerator(btp.BootstrappingParameters)
	bootSK := kgen.GenSecretKeyNew()
	report("boot_secret", 0)
	switch mode {
	case "ring-swap":
		a, b := kgen.GenEvaluationKeysForRingSwapNew(bootSK, sk)
		report("generated_pair", 0)
		write("first_written", a)
		write("second_written", b)
	case "boot":
		key := kgen.GenGaloisKeyNew(btp.BootstrappingParameters.GaloisElementForRotation(1), bootSK)
		report("generated", 0)
		write("written", key)
	default:
		t.Fatalf("unknown probe mode %q", mode)
	}
	runtime.KeepAlive(sk)
}
