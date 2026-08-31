package main

/*
#include <stdint.h>
*/
import "C"

import "runtime/cgo"

func insertObject(item any) uint64 {
	return uint64(cgo.NewHandle(item))
}

func getObject[T any](handleID uint64) *T {
	return cgo.Handle(handleID).Value().(*T)
}

func getObjectAs[T any](handleID uint64) T {
	return cgo.Handle(handleID).Value().(T)
}

//export ReleaseHandle
func ReleaseHandle(handleID uint64) {
	cgo.Handle(handleID).Delete()
}

