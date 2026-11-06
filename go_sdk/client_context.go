package main

/*
#include <stdint.h>
#include <stdlib.h>
#ifndef GO_SDK_ERROR_STATUS_DEFINED
#define GO_SDK_ERROR_STATUS_DEFINED
typedef struct ErrorStatus {
    int code;
    char* message;
} ErrorStatus;
#endif
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cipherflow-fhe/lattigo/clientcontext"
	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
)

//export RestoreCkksClientKeys
func RestoreCkksClientKeys(parameterHandle uint64, enableBootstrapping bool, data *byte, length C.uint64_t, secretKeyHandle, publicKeyHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)
	*secretKeyHandle, *publicKeyHandle = 0, 0
	if data == nil || uint64(length) > uint64(^uint(0)>>1) {
		return errorStatus(fmt.Errorf("invalid full context buffer"))
	}
	c, err := clientcontext.Restore(unsafe.Slice(data, int(length)), clientcontext.KeyPlan{DefaultRotations: true, Bootstrapping: enableBootstrapping})
	if err != nil {
		return errorStatus(err)
	}
	if !c.Parameters.Equal(getObject[ckks.Parameters](parameterHandle)) {
		return errorStatus(fmt.Errorf("full context parameters do not match task"))
	}
	*secretKeyHandle = C.uint64_t(insertObject(c.SecretKey))
	*publicKeyHandle = C.uint64_t(insertObject(c.PublicKey))
	return status
}

//export GenCkksClientKeys
func GenCkksClientKeys(parameterHandle uint64, enableBootstrapping bool, secretKeyHandle, publicKeyHandle *C.uint64_t) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)
	*secretKeyHandle, *publicKeyHandle = 0, 0
	params := getObject[ckks.Parameters](parameterHandle)
	c, err := clientcontext.New(*params, clientcontext.KeyPlan{DefaultRotations: true, Bootstrapping: enableBootstrapping})
	if err != nil {
		return errorStatus(err)
	}
	*secretKeyHandle = C.uint64_t(insertObject(c.SecretKey))
	*publicKeyHandle = C.uint64_t(insertObject(c.PublicKey))
	return status
}

//export WriteCkksEvaluationContextFile
func WriteCkksEvaluationContextFile(parameterHandle, secretKeyHandle, publicKeyHandle uint64, defaultRotations, enableBootstrapping bool, path *C.char) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)
	return writeCkksClientFile(parameterHandle, secretKeyHandle, publicKeyHandle, defaultRotations, enableBootstrapping, C.GoString(path), false)
}

//export WriteCkksFullContextFile
func WriteCkksFullContextFile(parameterHandle, secretKeyHandle, publicKeyHandle uint64, defaultRotations, enableBootstrapping bool, path *C.char) (status C.ErrorStatus) {
	status = okStatus()
	defer recoverStatus(&status)
	return writeCkksClientFile(parameterHandle, secretKeyHandle, publicKeyHandle, defaultRotations, enableBootstrapping, C.GoString(path), true)
}

func writeCkksClientFile(parameterHandle, secretKeyHandle, publicKeyHandle uint64, rotations, boot bool, path string, full bool) C.ErrorStatus {
	c, err := clientcontext.FromKeys(*getObject[ckks.Parameters](parameterHandle),
		getObject[rlwe.SecretKey](secretKeyHandle), getObject[rlwe.PublicKey](publicKeyHandle),
		clientcontext.KeyPlan{DefaultRotations: rotations, Bootstrapping: boot})
	if err != nil {
		return errorStatus(err)
	}
	// Only create a new file. Application-level publication owns the two-file
	// transaction; neither this bridge nor a retry may overwrite existing keys.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errorStatus(err)
	}
	complete := false
	defer func() {
		if !complete {
			f.Close()
			os.Remove(path)
		}
	}()
	sink := clientcontext.FileSink{Writer: f, WriterAt: f}
	if full {
		_, err = c.WriteFull(sink)
	} else {
		_, err = c.WriteEval(sink)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return errorStatus(err)
	}
	complete = true
	return okStatus()
}
