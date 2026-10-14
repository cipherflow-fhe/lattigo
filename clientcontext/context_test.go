package clientcontext

import (
	"bytes"
	"math"
	"testing"

	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/ckks/bootstrapping"
	"github.com/cipherflow-fhe/lattigo/rlwe"
	"github.com/stretchr/testify/require"
)

func TestFullContextRestoresOriginalKeyPair(t *testing.T) {
	for _, useBTP := range []bool{false, true} {
		params, err := ckks.NewParametersFromLiteral(ckks.PN12QP109)
		require.NoError(t, err)
		var btp *bootstrapping.Parameters
		if useBTP {
			literal := bootstrapping.N16QP1546H192H32
			literal.SchemeParams.LogN, literal.SchemeParams.LogSlots = 12, 11
			params, err = ckks.NewParametersFromLiteral(literal.SchemeParams)
			require.NoError(t, err)
			btp = &literal.BootstrappingParams
			btp.RotationsForBootstrapping(params)
		}
		kgen := ckks.NewKeyGenerator(params)
		sk, pk := kgen.GenKeyPair()
		keys := Keys{Params: params, BTP: btp, SK: sk, PK: pk}
		raw, err := MarshalFull(keys)
		require.NoError(t, err)
		loaded, err := UnmarshalFull(raw, params, btp)
		require.NoError(t, err)
		require.True(t, sk.Value.Equals(loaded.SK.Value))
		enc := ckks.NewEncoder(params)
		pt := enc.EncodeNew([]float64{1.25, -2.5, 0.125}, params.MaxLevel(), params.DefaultScale(), params.LogSlots())
		ct := ckks.NewEncryptor(params, loaded.PK).EncryptNew(pt)
		got := enc.Decode(ckks.NewDecryptor(params, sk).DecryptNew(ct), params.LogSlots())
		for i, want := range []float64{1.25, -2.5, 0.125} {
			require.Less(t, math.Abs(real(got[i])-want), 0.001)
		}
		ct = ckks.NewEncryptor(params, pk).EncryptNew(pt)
		got = enc.Decode(ckks.NewDecryptor(params, loaded.SK).DecryptNew(ct), params.LogSlots())
		require.InDelta(t, 1.25, real(got[0]), 0.001)
		bad, err := ckks.NewParameters(params.Parameters, params.LogSlots()-1, params.DefaultScale())
		require.NoError(t, err)
		_, err = UnmarshalFull(raw, bad, btp)
		require.Error(t, err)
		_, err = UnmarshalFull(raw[:len(raw)-1], params, btp)
		require.Error(t, err)
		_, err = UnmarshalFull(append(raw, 1), params, btp)
		require.Error(t, err)
	}
}

func TestEvaluationPayloadsContainPublicKeysOnly(t *testing.T) {
	params, err := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	require.NoError(t, err)
	sk, pk := ckks.NewKeyGenerator(params).GenKeyPair()
	stream, err := NewEvaluationStream(Keys{Params: params, SK: sk, PK: pk})
	require.NoError(t, err)
	var output bytes.Buffer
	for {
		payload, err := stream.Next()
		require.NoError(t, err)
		if payload == nil {
			break
		}
		output.Write(payload)
	}
	r := bytes.NewReader(output.Bytes())
	var length [4]byte
	_, err = r.Read(length[:])
	require.NoError(t, err)
	paramBytes, err := params.MarshalBinary()
	require.NoError(t, err)
	r.Seek(int64(len(paramBytes)), 1)
	flag, err := r.ReadByte()
	require.NoError(t, err)
	require.Equal(t, byte(0), flag)
	flag, err = r.ReadByte()
	require.NoError(t, err)
	require.Equal(t, byte(0), flag)
	flag, _ = r.ReadByte()
	require.Equal(t, byte(1), flag)
	rlk := rlwe.BytesToRelinearizationKey(r)
	require.Len(t, rlk.Keys, 1)
	flag, _ = r.ReadByte()
	require.Equal(t, byte(1), flag)
	// Sentinel handles the existing bit decoder's byte lookahead at EOF.
	remaining := make([]byte, r.Len())
	r.Read(remaining)
	r = bytes.NewReader(append(remaining, 0xa5))
	rtks := rlwe.BytesToRotationKeySet(r)
	require.Len(t, rtks.Keys, 22)
	require.Contains(t, rtks.Keys, params.GaloisElementForRowRotation())
	require.Equal(t, 1, r.Len())
}
