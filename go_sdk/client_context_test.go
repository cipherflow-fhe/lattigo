package main

import (
	"bytes"
	"math/cmplx"
	"testing"

	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/ckks/bootstrapping"
	"github.com/cipherflow-fhe/lattigo/clientcontext"
	"github.com/stretchr/testify/require"
)

func TestClientExportFiltersResidentEvaluationKeys(t *testing.T) {
	context := testStreamingContext(t)
	context.rlk = context.kgen.GenRelinearizationKey(context.sk, 1)
	context.gk = context.kgen.GenRotationKeysForRotations([]int{1}, true, context.sk)
	rlk, gk := context.rlk, context.gk
	for _, useBTP := range []bool{false, true} {
		var btp *bootstrapping.Parameters
		if useBTP {
			params := bootstrapping.N16QP1546H192H32.BootstrappingParams
			params.RotationsForBootstrapping(*context.parameter)
			btp = &params
		}
		raw, err := marshalClientContext(context, btp)
		require.NoError(t, err)
		loaded, err := clientcontext.UnmarshalFull(raw, *context.parameter, btp)
		require.NoError(t, err)
		require.True(t, context.sk.Value.Equals(loaded.SK.Value))
		require.Same(t, rlk, context.rlk)
		require.Same(t, gk, context.gk)
		require.NotNil(t, context.pk)
	}
}

func TestSharedBtpStreamImportsIntoNativeSDK(t *testing.T) {
	literal := bootstrapping.N16QP1546H192H32
	literal.SchemeParams.LogN, literal.SchemeParams.LogSlots = 13, 12
	params, err := ckks.NewParametersFromLiteral(literal.SchemeParams)
	require.NoError(t, err)
	context := newStreamingCkksContext(&params, false)
	stream, err := clientcontext.NewEvaluationStream(clientcontext.Keys{
		Params: params, BTP: &literal.BootstrappingParams, SK: context.sk, PK: context.pk,
	})
	require.NoError(t, err)
	var out bytes.Buffer
	for {
		payload, err := stream.Next()
		require.NoError(t, err)
		if payload == nil {
			break
		}
		out.Write(payload)
	}
	raw := out.Bytes()
	handle := DeserializeCkksBtpContextAdvanced(&raw[0], uint64(len(raw)))
	defer delete_object(handle)
	server := get_object[CkksBtpContext](handle)
	require.Nil(t, server.sk)
	values := make([]complex128, params.Slots())
	for i := range values {
		values[i] = complex(float64(i%13)/100, 0)
	}
	pt := context.encoder.EncodeNew(values, 0, params.DefaultScale(), params.LogSlots())
	ct := context.encryptor_pk.EncryptNew(pt)
	got := context.encoder.Decode(context.decryptor.DecryptNew(server.bootstrapper.Bootstrapp(ct)), params.LogSlots())
	for i := range values {
		require.Less(t, cmplx.Abs(got[i]-values[i]), 0.001)
	}
}
