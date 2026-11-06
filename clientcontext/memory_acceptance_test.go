package clientcontext

import (
	"encoding/json"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cipherflow-fhe/lattigo/circuits/ckks/bootstrapping"
	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
)

// Explicit acceptance probe: compile once, run bulk/stream in independent
// processes with identical Go/GC settings and production parameter-table input.
func TestMemoryAcceptance(t *testing.T) {
	mode := os.Getenv("TAA_MEMORY_MODE")
	if mode == "" {
		t.Skip("set TAA_MEMORY_MODE=bulk or stream")
	}
	if mode != "bulk" && mode != "stream" {
		t.Fatal("invalid mode")
	}
	var table struct {
		CKKS map[string]struct {
			Q, P     []uint64
			LogScale int `json:"log_default_scale"`
		}
	}
	data, err := os.ReadFile(os.Getenv("TAA_PARAMETER_JSON"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &table); err != nil {
		t.Fatal(err)
	}
	entry := table.CKKS["15"]
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 15, RingType: ring.ConjugateInvariant, Q: entry.Q, P: entry.P, LogDefaultScale: entry.LogScale})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	// Keep phase samples distinct from the process-wide VmHWM. These are
	// observed maxima; allocations between samples may be higher.
	var sampleMutex sync.Mutex
	var heapPeak, rssPeak uint64
	sample := func() {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		status, _ := os.ReadFile("/proc/self/status")
		var rss uint64
		fields := strings.Fields(string(status))
		for index, field := range fields {
			if field == "VmRSS:" && index+1 < len(fields) {
				rss, _ = strconv.ParseUint(fields[index+1], 10, 64)
				break
			}
		}
		heapPeak = max(heapPeak, stats.HeapAlloc)
		rssPeak = max(rssPeak, rss)
	}
	stopSamples, samplesStopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(samplesStopped)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sampleMutex.Lock()
				sample()
				sampleMutex.Unlock()
			case <-stopSamples:
				return
			}
		}
	}()
	defer func() { close(stopSamples); <-samplesStopped }()
	record := func(phase string, extra map[string]any) {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		status, _ := os.ReadFile("/proc/self/status")
		if extra == nil {
			extra = map[string]any{}
		}
		extra["mode"], extra["phase"], extra["elapsedMs"] = mode, phase, time.Since(started).Milliseconds()
		extra["heapAlloc"], extra["heapSys"], extra["procStatus"] = stats.HeapAlloc, stats.HeapSys, string(status)
		sampleMutex.Lock()
		sample()
		extra["observedHeapPeakBytes"], extra["observedRSSPeakKiB"], extra["sampleIntervalMs"] = heapPeak, rssPeak, 10
		heapPeak, rssPeak = 0, 0
		sampleMutex.Unlock()
		encoded, _ := json.Marshal(extra)
		t.Log(string(encoded))
	}
	c, err := New(params, KeyPlan{DefaultRotations: true, Bootstrapping: true})
	if err != nil {
		t.Fatal(err)
	}
	record("client-pair", nil)
	var residual *rlwe.MemEvaluationKeySet
	var boot *bootstrapping.EvaluationKeys
	if mode == "bulk" {
		kgen := rlwe.NewKeyGenerator(params)
		residual = rlwe.NewMemEvaluationKeySet(kgen.GenRelinearizationKeyNew(c.SecretKey), kgen.GenGaloisKeysNew(c.galEls, c.SecretKey)...)
		boot, _, err = c.btp.GenEvaluationKeys(c.SecretKey)
		if err != nil {
			t.Fatal(err)
		}
		record("bulk-keygen", nil)
	}
	file, err := os.CreateTemp(os.Getenv("TAA_MEMORY_DIRECTORY"), "taa-eval-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	sink := FileSink{Writer: file, WriterAt: file}
	var bytes uint64
	if mode == "stream" {
		bytes, err = c.WriteEval(sink)
	} else {
		w := &streamWriter{dst: sink}
		_, err = w.Write([]byte(contextMagic))
		write := func(callback func(io.Writer) error) {
			if err == nil {
				err = w.blob(callback)
			}
		}
		parameter, e := params.MarshalBinary()
		if e != nil {
			t.Fatal(e)
		}
		write(func(dst io.Writer) error { _, e := dst.Write(parameter); return e })
		for range 3 {
			if err == nil {
				err = w.flag(true)
			}
		}
		write(func(dst io.Writer) error { return writeObject(dst, c.PublicKey) })
		if err == nil {
			err = w.flag(true)
		}
		write(func(dst io.Writer) error { return writeObject(dst, residual) })
		if err == nil {
			err = w.flag(true)
		}
		write(func(dst io.Writer) error { return writeObject(dst, boot) })
		bytes = w.pos
	}
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	record("eval-closed", map[string]any{"bytes": bytes})
	runtime.KeepAlive(residual)
	runtime.KeepAlive(boot)
	residual = nil
	boot = nil
	runtime.GC()
	record("evaluation-keys-released", nil)
	full, err := os.CreateTemp(os.Getenv("TAA_MEMORY_DIRECTORY"), "taa-full-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(full.Name())
	fullBytes, err := c.WriteFull(FileSink{Writer: full, WriterAt: full})
	if err != nil {
		t.Fatal(err)
	}
	if err = full.Close(); err != nil {
		t.Fatal(err)
	}
	record("full-closed", map[string]any{"bytes": fullBytes})
	reader, err := os.Open(full.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	restored, err := RestoreFrom(reader, fullBytes, params, c.plan)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.SecretKey.Equal(c.SecretKey) || !restored.PublicKey.Equal(c.PublicKey) {
		t.Fatal("restored identity differs")
	}
	record("restored", nil)
}
