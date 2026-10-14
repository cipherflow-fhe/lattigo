package main

/*
#include <stdint.h>
*/
import "C"

import (
	"errors"
	"unsafe"

	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/ckks/bootstrapping"
	"github.com/cipherflow-fhe/lattigo/clientcontext"
)

func marshalClientContext(context *CkksContext, btp *bootstrapping.Parameters) ([]byte, error) {
	return clientcontext.MarshalFull(clientcontext.Keys{Params: *context.parameter, BTP: btp, SK: context.sk, PK: context.pk})
}

//export SerializeCkksClientContext
func SerializeCkksClientContext(context_handle uint64, use_btp bool, raw_data **byte, length *C.uint64_t, buffer_handle *C.uint64_t) uint64 {
	return evalContextStatus(func() error {
		if raw_data == nil || length == nil || buffer_handle == nil {
			return errors.New("missing client context output")
		}
		var btp *bootstrapping.Parameters
		if use_btp {
			btp = get_object[CkksBtpContext](context_handle).btp_parameter
		}
		raw, err := marshalClientContext(get_ckks_context(context_handle), btp)
		if err != nil {
			return err
		}
		*raw_data = &raw[0]
		*length = C.uint64_t(len(raw))
		*buffer_handle = C.uint64_t(insert_object(&raw))
		return nil
	})
}

//export DeserializeCkksClientContext
func DeserializeCkksClientContext(raw_data *byte, length uint64, parameter_handle uint64, use_btp bool, context_handle *C.uint64_t) uint64 {
	return evalContextStatus(func() error {
		if raw_data == nil || length == 0 || context_handle == nil {
			return errors.New("missing client context input")
		}
		*context_handle = 0
		var params *ckks.Parameters
		var btp *bootstrapping.Parameters
		if use_btp {
			parameters := get_object[BtpParameterSet](parameter_handle)
			params, btp = &parameters.SchemeParam, &parameters.BtpParam
		} else {
			params = get_object[ckks.Parameters](parameter_handle)
		}
		keys, err := clientcontext.UnmarshalFull(unsafe.Slice(raw_data, length), *params, btp)
		if err != nil {
			return err
		}
		context := CkksContext{parameter: &keys.Params, RlweContext: RlweContext{sk: keys.SK, pk: keys.PK}}
		init_ckks_context(&context)
		if use_btp {
			*context_handle = C.uint64_t(insert_object(&CkksBtpContext{CkksContext: context, btp_parameter: keys.BTP}))
		} else {
			*context_handle = C.uint64_t(insert_object(&context))
		}
		return nil
	})
}
