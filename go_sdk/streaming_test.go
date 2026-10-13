package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/cmplx"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/ckks/bootstrapping"
	"github.com/cipherflow-fhe/lattigo/rlwe"
	"github.com/stretchr/testify/require"
)

func testStreamingContext(t *testing.T) *CkksContext {
	params, err := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	require.NoError(t, err)
	return newStreamingCkksContext(&params, false)
}

func readStreamingCkks(t *testing.T, data []byte) (*ckks.Parameters, RlweContext) {
	// The existing bit decoder reads one byte ahead, then UnreadByte. Supply a
	// sentinel so its EOF behavior cannot leave the final payload byte unread.
	reader := bytes.NewReader(append(append([]byte(nil), data...), 0xa5))
	var length uint32
	require.NoError(t, binary.Read(reader, binary.BigEndian, &length))
	parameters := make([]byte, length)
	_, err := io.ReadFull(reader, parameters)
	require.NoError(t, err)
	params := new(ckks.Parameters)
	require.NoError(t, params.UnmarshalBinary(parameters))
	// Use the original advanced decoder and require that it consumed the whole file.
	context := bytes_to_rlwe_context(reader)
	require.Equal(t, 1, reader.Len())
	sentinel, err := reader.ReadByte()
	require.NoError(t, err)
	require.Equal(t, byte(0xa5), sentinel)
	require.Nil(t, context.sk)
	require.Nil(t, context.pk)
	decompress_rlwe_context(&context, &params.Parameters)
	return params, context
}

func compareEvaluationKeys(t *testing.T, context *CkksContext, imported rlwe.EvaluationKey, extra []int) rlwe.EvaluationKey {
	params := *context.parameter
	rotations := make([]int, 0)
	for i := 0; i < params.LogN()-1; i++ {
		rotations = append(rotations, 1<<i)
	}
	for i := 0; i < params.LogN()-2; i++ {
		rotations = append(rotations, -(1 << i))
	}
	rotations = append(rotations, extra...)
	legacy := rlwe.EvaluationKey{
		Rlk:  context.kgen.GenRelinearizationKey(context.sk, 1),
		Rtks: context.kgen.GenRotationKeysForRotations(rotations, true, context.sk),
	}
	require.Len(t, imported.Rtks.Keys, len(legacy.Rtks.Keys))
	for element := range legacy.Rtks.Keys {
		require.Contains(t, imported.Rtks.Keys, element)
	}
	values := make([]complex128, params.Slots())
	for i := range values {
		values[i] = complex(float64(i%17)/100, float64(i%11)/100)
	}
	plaintext := context.encoder.EncodeNew(values, params.MaxLevel(), params.DefaultScale(), params.LogSlots())
	ciphertext := context.encryptor_sk.EncryptNew(plaintext)
	oldEvaluator := ckks.NewEvaluator(params, legacy)
	newEvaluator := ckks.NewEvaluator(params, imported)
	operations := []func(ckks.Evaluator) *ckks.Ciphertext{
		func(e ckks.Evaluator) *ckks.Ciphertext { return e.RotateNew(ciphertext, 1) },
		func(e ckks.Evaluator) *ckks.Ciphertext { return e.RotateNew(ciphertext, -1) },
		func(e ckks.Evaluator) *ckks.Ciphertext { return e.ConjugateNew(ciphertext) },
		func(e ckks.Evaluator) *ckks.Ciphertext { return e.MulRelinNew(ciphertext, ciphertext) },
	}
	for _, operation := range operations {
		oldValues := context.encoder.Decode(context.decryptor.DecryptNew(operation(oldEvaluator)), params.LogSlots())
		newValues := context.encoder.Decode(context.decryptor.DecryptNew(operation(newEvaluator)), params.LogSlots())
		for i := range oldValues {
			require.Less(t, cmplx.Abs(oldValues[i]-newValues[i]), 0.001)
		}
	}
	return legacy
}

func TestStreamingCkksProtocolAndFunction(t *testing.T) {
	context := testStreamingContext(t)
	destination := filepath.Join(t.TempDir(), "eval.bin")
	require.NoError(t, streamCkksEvalContext(context, destination))
	data, err := os.ReadFile(destination)
	require.NoError(t, err)
	params, imported := readStreamingCkks(t, data)
	require.Equal(t, *context.parameter, *params)
	require.Nil(t, context.rlk)
	require.Nil(t, context.gk)
	compareEvaluationKeys(t, context, rlwe.EvaluationKey{Rlk: imported.rlk, Rtks: imported.gk}, nil)
	// A second export must neither append bytes nor retain evaluation keys.
	require.NoError(t, streamCkksEvalContext(context, destination))
	second, err := os.ReadFile(destination)
	require.NoError(t, err)
	require.Len(t, second, len(data))
}

type faultEvalFile struct {
	bytes.Buffer
	path     string
	writeErr error
	closeErr error
	short    bool
	closed   bool
}

func (file *faultEvalFile) Name() string { return file.path }
func (file *faultEvalFile) Close() error {
	file.closed = true
	return file.closeErr
}
func (file *faultEvalFile) Write(data []byte) (int, error) {
	if file.writeErr != nil {
		return 0, file.writeErr
	}
	if file.short {
		return len(data) - 1, nil
	}
	return file.Buffer.Write(data)
}

func TestStreamingFileFailures(t *testing.T) {
	for _, failure := range []string{"write", "short", "close", "rename", "cleanup", "panic"} {
		t.Run(failure, func(t *testing.T) {
			file := &faultEvalFile{path: "temporary-key-file"}
			injected := errors.New("injected " + failure)
			removed, renamed := false, false
			if failure == "write" || failure == "cleanup" {
				file.writeErr = injected
			}
			file.short = failure == "short"
			if failure == "close" {
				file.closeErr = injected
			}
			err := publishEvalContextFile(file, "destination", func(writer io.Writer) error {
				if failure == "panic" {
					panic(injected)
				}
				buffer := bytes.NewBufferString("payload")
				_, err := buffer.WriteTo(writer)
				return err
			}, func(_, _ string) error {
				renamed = true
				return injected
			}, func(_ string) error {
				removed = true
				if failure == "cleanup" {
					return errors.New("cleanup failed")
				}
				return nil
			})
			require.Error(t, err)
			require.True(t, file.closed)
			require.True(t, removed)
			require.Equal(t, failure == "rename", renamed)
			if failure == "short" {
				require.ErrorIs(t, err, io.ErrShortWrite)
			}
			if failure == "cleanup" {
				require.True(t, strings.Contains(err.Error(), file.path))
			}
		})
	}
	// Exercise a real kernel write error (ENOSPC) as well as atomic replacement.
	if full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0); err == nil {
		defer full.Close()
		buffer := bytes.NewBufferString("payload")
		_, err = buffer.WriteTo(full)
		require.Error(t, err)
	}
	destination := filepath.Join(t.TempDir(), "eval.bin")
	require.NoError(t, os.WriteFile(destination, []byte("old"), 0600))
	err := writeEvalContextFile(destination, func(w io.Writer) error {
		_, err := w.Write([]byte("partial"))
		require.NoError(t, err)
		return errors.New("generation failed")
	})
	require.Error(t, err)
	data, err := os.ReadFile(destination)
	require.NoError(t, err)
	require.Equal(t, "old", string(data))
	temporary, err := filepath.Glob(filepath.Join(filepath.Dir(destination), ".eval-context-*"))
	require.NoError(t, err)
	require.Empty(t, temporary)
}

func TestStreamingValidationAndCgoBoundary(t *testing.T) {
	require.Error(t, streamCkksEvalContext(&CkksContext{}, "unused"))
	require.Error(t, validateEvalContextLengths(nil, make([]uint64, 65536)))
	require.Error(t, writeEvalContextFile("", func(io.Writer) error { return nil }))
	require.NotZero(t, evalContextStatus(func() error { panic("invalid handle") }))
	require.Contains(t, error_message, "invalid handle")
	require.NotZero(t, StreamSetupCkksContextToFile(0, nil, false, nil))
	require.Contains(t, error_message, "output context handle")
	require.NotZero(t, StreamExportCkksEvalContextToFile(0, nil))
}

func TestStreamingBtpProtocolAndBootstrap(t *testing.T) {
	for _, weight := range []int{32, 0} {
		t.Run(fmt.Sprintf("ephemeral-%d", weight), func(t *testing.T) {
			literal := bootstrapping.N16QP1546H192H32
			literal.SchemeParams.LogN, literal.SchemeParams.LogSlots = 13, 12
			if weight == 0 {
				literal.SchemeParams.H = 32
			}
			params, err := ckks.NewParametersFromLiteral(literal.SchemeParams)
			require.NoError(t, err)
			btpParams := literal.BootstrappingParams
			btpParams.EphemeralSecretWeight = weight
			context := &CkksBtpContext{CkksContext: *newStreamingCkksContext(&params, false), btp_parameter: &btpParams}
			destination := filepath.Join(t.TempDir(), "eval.bin")
			require.NoError(t, streamCkksBtpEvalContext(context, destination))
			require.Nil(t, context.evk)
			require.Nil(t, context.rlk)
			require.Nil(t, context.gk)
			require.Nil(t, context.bootstrapper)
			data, err := os.ReadFile(destination)
			require.NoError(t, err)
			reader := bytes.NewReader(append(append([]byte(nil), data...), 0xa5))
			var size uint32
			require.NoError(t, binary.Read(reader, binary.LittleEndian, &size))
			reader.Seek(int64(size), io.SeekCurrent)
			skFlag, _ := reader.ReadByte()
			require.Zero(t, skFlag)
			pkFlag, _ := reader.ReadByte()
			require.Equal(t, byte(1), pkFlag)
			rlwe.BytesToCiphertextQP(reader)
			btpSize, _ := reader.ReadByte()
			btpData := make([]byte, btpSize)
			_, err = io.ReadFull(reader, btpData)
			require.NoError(t, err)
			decodedParams := new(bootstrapping.Parameters)
			require.NoError(t, decodedParams.UnmarshalBinary(btpData))
			expectedParams, err := btpParams.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, expectedParams, btpData)
			flag, _ := reader.ReadByte()
			require.Equal(t, byte(1), flag)
			rlwe.BytesToRelinearizationKey(reader)
			flag, _ = reader.ReadByte()
			require.Equal(t, byte(1), flag)
			keys := rlwe.BytesToRotationKeySet(reader)
			require.Len(t, keys.Keys, len(evalGaloisElements(&params, btpParams.RotationsForBootstrapping(params))))
			for _, sparseKey := range []bool{true, false} {
				flag, _ = reader.ReadByte()
				if weight == 0 {
					require.Zero(t, flag)
				} else {
					require.Equal(t, byte(1), flag)
					key := rlwe.BytesToGadgetCiphertext(reader)
					expectedLevel := params.MaxLevel()
					if sparseKey {
						expectedLevel = 0
					}
					require.Equal(t, expectedLevel, key.Value[0][0].LevelQ())
					require.Equal(t, params.PCount()-1, key.Value[0][0].LevelP())
				}
			}
			require.Equal(t, 1, reader.Len())
			sentinel, _ := reader.ReadByte()
			require.Equal(t, byte(0xa5), sentinel)
			handle := DeserializeCkksBtpContextAdvanced(&data[0], uint64(len(data)))
			defer delete_object(handle)
			imported := get_object[CkksBtpContext](handle)
			require.Nil(t, imported.sk)
			require.NotNil(t, imported.bootstrapper)
			legacyKeys := compareEvaluationKeys(t, &context.CkksContext, imported.evk.EvaluationKey, btpParams.RotationsForBootstrapping(params))
			dts, std := btpParams.GenEncapsulationSwitchingKeys(params, context.sk)
			legacyBootstrapper, err := bootstrapping.NewBootstrapper(params, btpParams, bootstrapping.EvaluationKeys{
				EvaluationKey: legacyKeys, SwkDtS: dts, SwkStD: std,
			})
			require.NoError(t, err)
			values := make([]complex128, params.Slots())
			for i := range values {
				values[i] = complex(float64(i%13)/100, 0)
			}
			pt := context.encoder.EncodeNew(values, 0, params.DefaultScale(), params.LogSlots())
			ct := context.encryptor_sk.EncryptNew(pt)
			actual := context.encoder.Decode(context.decryptor.DecryptNew(imported.bootstrapper.Bootstrapp(ct.CopyNew())), params.LogSlots())
			legacy := context.encoder.Decode(context.decryptor.DecryptNew(legacyBootstrapper.Bootstrapp(ct.CopyNew())), params.LogSlots())
			for i := range values {
				require.Less(t, cmplx.Abs(actual[i]-values[i]), 0.001)
				require.Less(t, cmplx.Abs(actual[i]-legacy[i]), 0.001)
			}
		})
	}
}

func TestStreamingBtpRestoredClientShallowCopy(t *testing.T) {
	// Deserializing a streaming full context creates an empty evk, with no bootstrapper.
	context := &CkksBtpContext{
		CkksContext: *testStreamingContext(t),
		evk:         new(bootstrapping.EvaluationKeys),
	}
	handle := insert_object(context)
	defer delete_object(handle)
	copyHandle := ShallowCopyCkksBtpContext(handle)
	defer delete_object(copyHandle)
	copy := get_object[CkksBtpContext](copyHandle)
	require.Nil(t, copy.bootstrapper)
	params := *context.parameter
	values := make([]complex128, params.Slots())
	values[0] = 0.125
	pt := copy.encoder.EncodeNew(values, 0, params.DefaultScale(), params.LogSlots())
	ct := copy.encryptor_sk.EncryptNew(pt)
	decoded := context.encoder.Decode(context.decryptor.DecryptNew(ct), params.LogSlots())
	require.Less(t, cmplx.Abs(decoded[0]-values[0]), 0.001)
}
