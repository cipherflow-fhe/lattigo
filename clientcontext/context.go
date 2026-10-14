// Package clientcontext shares client-only persistence and evaluation-key
// streaming between the native SDK and browser WebAssembly entry points.
package clientcontext

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"

	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/ckks/bootstrapping"
	"github.com/cipherflow-fhe/lattigo/rlwe"
)

type Keys struct {
	Params ckks.Parameters
	BTP    *bootstrapping.Parameters
	SK     *rlwe.SecretKey
	PK     *rlwe.PublicKey
}

// MarshalFull retains just the parameters and key pair, with the existing wire
// layout. Evaluation-key fields are always absent, independent of source state.
func MarshalFull(keys Keys) ([]byte, error) {
	if keys.SK == nil || keys.PK == nil {
		return nil, errors.New("client context requires SK and PK")
	}
	params, err := keys.Params.MarshalBinary()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	order := parameterOrder(keys.BTP)
	binary.Write(&out, order, uint32(len(params)))
	out.Write(params)
	out.WriteByte(1)
	rlwe.SecretKeyToBytes(keys.SK, &keys.Params.Parameters, &out)
	out.WriteByte(1)
	rlwe.CiphertextQPToBytes(keys.PK, &keys.Params.Parameters, &out)
	if keys.BTP != nil {
		btp, err := keys.BTP.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if len(btp) > 255 {
			return nil, errors.New("BTP parameters exceed uint8 length")
		}
		out.WriteByte(byte(len(btp)))
		out.Write(btp)
	}
	out.Write([]byte{0, 0})
	if keys.BTP != nil {
		out.Write([]byte{0, 0})
	}
	return out.Bytes(), nil
}

func parameterOrder(btp *bootstrapping.Parameters) binary.ByteOrder {
	if btp != nil {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// UnmarshalFull validates the client-only layout against effective task
// parameters before creating encryptors or decryptors.
func UnmarshalFull(raw []byte, expected ckks.Parameters, btp *bootstrapping.Parameters) (keys Keys, err error) {
	defer func() {
		if value := recover(); value != nil {
			keys = Keys{}
			err = fmt.Errorf("invalid client context: %v", value)
		}
	}()
	r := bytes.NewReader(raw)
	var length uint32
	if err = binary.Read(r, parameterOrder(btp), &length); err != nil {
		return keys, err
	}
	if length == 0 || uint64(length) > uint64(r.Len()) {
		return keys, errors.New("invalid parameter length")
	}
	parameters := make([]byte, length)
	if _, err = io.ReadFull(r, parameters); err != nil {
		return keys, err
	}
	if err = keys.Params.UnmarshalBinary(parameters); err != nil {
		return keys, err
	}
	if !keys.Params.Equals(expected) {
		return Keys{}, errors.New("client context parameters do not match task")
	}
	if flag, e := r.ReadByte(); e != nil || flag != 1 {
		return Keys{}, errors.New("client context requires SK")
	}
	encoded, err := readQP(r, expected, false)
	if err != nil {
		return Keys{}, err
	}
	sk := rlwe.BytesToSecretKey(bytes.NewReader(append(encoded, 0)))
	keys.SK = &sk
	if flag, e := r.ReadByte(); e != nil || flag != 1 {
		return Keys{}, errors.New("client context requires PK")
	}
	encoded, err = readQP(r, expected, true)
	if err != nil {
		return Keys{}, err
	}
	pk := rlwe.BytesToCiphertextQP(bytes.NewReader(append(encoded, 0)))
	pk.Decompress(&expected.Parameters)
	keys.PK = &pk
	if btp != nil {
		length, e := r.ReadByte()
		if e != nil {
			return Keys{}, e
		}
		encoded := make([]byte, int(length))
		if _, err = io.ReadFull(r, encoded); err != nil {
			return Keys{}, err
		}
		var loaded bootstrapping.Parameters
		if err = loaded.UnmarshalBinary(encoded); err != nil {
			return Keys{}, err
		}
		want := *btp
		want.RotationsForBootstrapping(expected)
		wantBytes, e := want.MarshalBinary()
		if e != nil {
			return Keys{}, e
		}
		if !bytes.Equal(encoded, wantBytes) {
			return Keys{}, errors.New("BTP parameters do not match task")
		}
		keys.BTP = &loaded
	}
	flags := 2
	if btp != nil {
		flags = 4
	}
	for i := 0; i < flags; i++ {
		if flag, e := r.ReadByte(); e != nil || flag != 0 {
			return Keys{}, errors.New("client context must contain only SK/PK")
		}
	}
	if r.Len() != 0 {
		return Keys{}, errors.New("trailing client context bytes")
	}
	return keys, nil
}

// Validate the QP payload dimensions and length before the legacy decoder,
// which otherwise silently ignores several read errors.
func readQP(r *bytes.Reader, params ckks.Parameters, public bool) ([]byte, error) {
	var head [6]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	if int(binary.LittleEndian.Uint32(head[:4])) != params.N() || int(head[4])+1 != params.QCount() || int(head[5])+1 != params.PCount() {
		return nil, errors.New("key dimensions do not match parameters")
	}
	moduli := append(params.Q(), params.P()...)
	lengths := make([]byte, len(moduli))
	if _, err := io.ReadFull(r, lengths); err != nil {
		return nil, err
	}
	size := 6 // two polynomial metadata blocks
	for i, q := range moduli {
		if lengths[i] != byte(bits.Len64(q)) {
			return nil, errors.New("key modulus widths do not match parameters")
		}
		size += params.N() * int(lengths[i]) / 8
	}
	if public {
		size += 64
	}
	if size > r.Len() {
		return nil, io.ErrUnexpectedEOF
	}
	data := make([]byte, 6+len(lengths)+size, 7+len(lengths)+size)
	copy(data, head[:])
	copy(data[6:], lengths)
	_, err := io.ReadFull(r, data[6+len(lengths):])
	return data, err
}

func GaloisElements(params ckks.Parameters, extraRotations []int) []uint64 {
	seen := make(map[uint64]bool)
	var elements []uint64
	add := func(element uint64) {
		if !seen[element] {
			seen[element] = true
			elements = append(elements, element)
		}
	}
	for i := 0; i < params.LogN()-1; i++ {
		add(params.GaloisElementForColumnRotationBy(1 << i))
	}
	for i := 0; i < params.LogN()-2; i++ {
		add(params.GaloisElementForColumnRotationBy(-(1 << i)))
	}
	for _, rotation := range extraRotations {
		add(params.GaloisElementForColumnRotationBy(rotation))
	}
	add(params.GaloisElementForRowRotation())
	return elements
}
