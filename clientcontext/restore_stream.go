package clientcontext

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
)

// RestoreFrom reads a full container against a trusted profile. All allocation
// lengths come from that profile, and only one serialized client key is held
// at a time. It does not accept evaluation-key containers.
func RestoreFrom(source io.Reader, size uint64, params ckks.Parameters, plan KeyPlan) (*Context, error) {
	parameter, err := params.MarshalBinary()
	if err != nil {
		return nil, err
	}
	n := uint64(params.N())
	polySize := func(count int) uint64 { return 8 + uint64(count)*(8+n*8) }
	secretBytes := polySize(params.QCount()) + polySize(params.PCount())
	publicBytes := 8 + 2*secretBytes
	publicContextBytes := uint64(len(contextMagic)) + 8 + uint64(len(parameter)) + 3 + 8 + publicBytes + 2
	if size != 8+publicContextBytes+8+secretBytes {
		return nil, fmt.Errorf("full context length does not match profile")
	}
	readSize := func(expected uint64) error {
		var actual uint64
		if err := binary.Read(source, binary.LittleEndian, &actual); err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("context blob length %d does not match profile length %d", actual, expected)
		}
		return nil
	}
	readBytes := func(expected []byte) error {
		data := make([]byte, len(expected))
		if _, err := io.ReadFull(source, data); err != nil {
			return err
		}
		if !bytes.Equal(data, expected) {
			return fmt.Errorf("client context does not match profile")
		}
		return nil
	}
	if err = readSize(publicContextBytes); err != nil {
		return nil, err
	}
	if err = readBytes([]byte(contextMagic)); err != nil {
		return nil, err
	}
	if err = readSize(uint64(len(parameter))); err != nil {
		return nil, err
	}
	if err = readBytes(parameter); err != nil {
		return nil, err
	}
	flags := []byte{0, 0, 1}
	if plan.DefaultRotations {
		flags[0] = 1
	}
	if plan.Bootstrapping {
		flags[1] = 1
	}
	if err = readBytes(flags); err != nil {
		return nil, err
	}
	readKey := func(length uint64, public bool, key io.ReaderFrom) error {
		if err := readSize(length); err != nil {
			return err
		}
		// Conversion is bounded by the trusted native key size and host int.
		if length > uint64(^uint(0)>>1) {
			return fmt.Errorf("client key exceeds addressable workspace")
		}
		data := make([]byte, int(length))
		if _, err := io.ReadFull(source, data); err != nil {
			return err
		}
		if err := validateKey(data, params, public); err != nil {
			return err
		}
		return decodeKey(data, key)
	}
	pk, sk := rlwe.NewPublicKey(params), rlwe.NewSecretKey(params)
	if err = readKey(publicBytes, true, pk); err != nil {
		return nil, err
	}
	if err = readBytes([]byte{0, 0}); err != nil {
		return nil, err
	}
	if err = readKey(secretBytes, false, sk); err != nil {
		return nil, err
	}
	var extra [1]byte
	if n, err := source.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, fmt.Errorf("full context has trailing bytes or failed EOF")
	}
	return FromKeys(params, sk, pk, plan)
}
