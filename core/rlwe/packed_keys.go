package rlwe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
)

// PackedKeySetMagic identifies lossless, seeded evaluation-key persistence.
// Native v6 encodings are intentionally unchanged; their readers remain valid.
const PackedKeySetMagic = "RLWEPK01"

// PackedReader supplies the remaining encoded length before key allocation.
// bytes.Reader and bounded streaming readers can both implement it.
type PackedReader interface {
	io.Reader
	io.ByteReader
	Len() int
}

// WritePackedParameters embeds the exact expansion parameters in a versioned
// key blob. In particular CI ring-swap keys must use the standard boot ring.
func WritePackedParameters(w io.Writer, magic string, params Parameters) error {
	data, err := params.MarshalJSON()
	if err != nil {
		return err
	}
	if _, err = io.WriteString(w, magic); err != nil {
		return err
	}
	if err = binary.Write(w, binary.LittleEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func ReadPackedParameters(r PackedReader, magic string) (params Parameters, err error) {
	var header [8]byte
	if _, err = io.ReadFull(r, header[:]); err != nil {
		return
	}
	if string(header[:]) != magic {
		return params, fmt.Errorf("invalid packed key version")
	}
	var size uint32
	if err = binary.Read(r, binary.LittleEndian, &size); err != nil {
		return
	}
	if size > 64*1024 || uint64(size) > uint64(r.Len()) {
		return params, fmt.Errorf("invalid packed parameter length")
	}
	data := make([]byte, size)
	if _, err = io.ReadFull(r, data); err != nil {
		return
	}
	err = params.UnmarshalJSON(data)
	return
}

// WritePackedEvaluationKey writes c0 at each modulus' full bit width and the
// original uniform-sampling seed. No precision bits are dropped. Expanded keys
// retaining their seed can also be persisted without their random component.
// Their original parameters and levels must be preserved: truncation changes
// the uniform sampler sequence and invalidates the retained seed.
func WritePackedEvaluationKey(w io.Writer, params Parameters, key *EvaluationKey) error {
	if key == nil || key.Seed == nil || len(key.Value) == 0 || len(key.Value[0]) == 0 || len(key.Value[0][0]) == 0 {
		return fmt.Errorf("packed evaluation key requires its generation seed")
	}
	levelQ, levelP, base := key.LevelQ(), key.LevelP(), key.BaseTwoDecomposition
	if levelQ < 0 || levelQ > params.MaxLevelQ() || levelP < -1 || levelP > params.MaxLevelP() || base < 0 || base > 63 {
		return fmt.Errorf("invalid packed key levels or decomposition")
	}
	if len(key.Value) != params.BaseRNSDecompositionVectorSize(levelQ, levelP) {
		return fmt.Errorf("invalid packed RNS decomposition")
	}
	if err := binary.Write(w, binary.LittleEndian, [2]uint16{uint16(levelQ), uint16(levelP + 1)}); err != nil {
		return err
	}
	if _, err := w.Write([]byte{byte(base)}); err != nil {
		return err
	}
	if _, err := w.Write(key.Seed[:]); err != nil {
		return err
	}
	decomposition := params.BaseTwoDecompositionVectorSize(levelQ, levelP, base)
	scratch := make([]byte, params.N()*8+8)
	for i, row := range key.Value {
		if len(row) != decomposition[i] {
			return fmt.Errorf("invalid packed base-two decomposition")
		}
		for _, entry := range row {
			if len(entry) < 1 {
				return fmt.Errorf("empty packed key component")
			}
			poly := entry[0]
			for _, part := range []struct {
				coefficients [][]uint64
				moduli       []uint64
			}{
				{poly.Q.Coeffs, params.Q()[:levelQ+1]}, {poly.P.Coeffs, params.P()[:levelP+1]},
			} {
				if len(part.coefficients) != len(part.moduli) {
					return fmt.Errorf("packed key modulus count mismatch")
				}
				for j, modulus := range part.moduli {
					if len(part.coefficients[j]) != params.N() {
						return fmt.Errorf("packed key degree mismatch")
					}
					data, err := packCoefficients(scratch, part.coefficients[j], modulus)
					if err != nil {
						return err
					}
					if n, err := w.Write(data); err != nil {
						return err
					} else if n != len(data) {
						return io.ErrShortWrite
					}
				}
			}
		}
	}
	return nil
}

// ReadPackedEvaluationKey checks the complete encoded length before allocation,
// then restores full keys for existing CPU evaluators and GPU metadata exports.
func ReadPackedEvaluationKey(r PackedReader, params Parameters) (*EvaluationKey, error) {
	var levels [2]uint16
	if err := binary.Read(r, binary.LittleEndian, &levels); err != nil {
		return nil, err
	}
	base, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	levelQ, levelP := int(levels[0]), int(levels[1])-1
	if levelQ > params.MaxLevelQ() || levelP > params.MaxLevelP() || base > 63 {
		return nil, fmt.Errorf("invalid packed key levels or decomposition")
	}
	decomposition := params.BaseTwoDecompositionVectorSize(levelQ, levelP, int(base))
	blocks := 0
	for _, count := range decomposition[:params.BaseRNSDecompositionVectorSize(levelQ, levelP)] {
		blocks += count
	}
	rowBytes := 0
	for _, moduli := range [][]uint64{params.Q()[:levelQ+1], params.P()[:levelP+1]} {
		for _, modulus := range moduli {
			rowBytes += params.N() * bits.Len64(modulus) / 8
		}
	}
	if int64(rowBytes)*int64(blocks)+32 > int64(r.Len()) {
		return nil, io.ErrUnexpectedEOF
	}
	baseTwo := int(base)
	key := NewEvaluationKey(params, EvaluationKeyParameters{LevelQ: &levelQ, LevelP: &levelP, BaseTwoDecomposition: &baseTwo, Compressed: true})
	var seed [32]byte
	if _, err = io.ReadFull(r, seed[:]); err != nil {
		return nil, err
	}
	key.Seed = &seed
	scratch := make([]byte, params.N()*8+8)
	for _, row := range key.Value {
		for _, entry := range row {
			for _, part := range []struct {
				coefficients [][]uint64
				moduli       []uint64
			}{
				{entry[0].Q.Coeffs, params.Q()[:levelQ+1]}, {entry[0].P.Coeffs, params.P()[:levelP+1]},
			} {
				for j, modulus := range part.moduli {
					size := params.N() * bits.Len64(modulus) / 8
					if _, err = io.ReadFull(r, scratch[:size]); err != nil {
						return nil, err
					}
					clear(scratch[size : size+8])
					if err = unpackCoefficients(scratch, part.coefficients[j], modulus); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	if err = key.Expand(params, nil); err != nil {
		return nil, err
	}
	return key, nil
}

func WritePackedGaloisKey(w io.Writer, params Parameters, key *GaloisKey) error {
	if key == nil || key.NthRoot != params.RingQ().NthRoot() {
		return fmt.Errorf("packed Galois ring mismatch")
	}
	if err := binary.Write(w, binary.LittleEndian, key.GaloisElement); err != nil {
		return err
	}
	return WritePackedEvaluationKey(w, params, &key.EvaluationKey)
}

func ReadPackedGaloisKey(r PackedReader, params Parameters) (*GaloisKey, error) {
	var gal uint64
	if err := binary.Read(r, binary.LittleEndian, &gal); err != nil {
		return nil, err
	}
	if gal&1 == 0 || gal >= params.RingQ().NthRoot() {
		return nil, fmt.Errorf("invalid packed Galois element")
	}
	key, err := ReadPackedEvaluationKey(r, params)
	if err != nil {
		return nil, err
	}
	return &GaloisKey{EvaluationKey: *key, GaloisElement: gal, NthRoot: params.RingQ().NthRoot()}, nil
}

// ReadPackedKeySetBody reads an RLK followed by a counted map of GLKs.
func ReadPackedKeySetBody(r PackedReader, params Parameters) (*MemEvaluationKeySet, error) {
	key, err := ReadPackedEvaluationKey(r, params)
	if err != nil {
		return nil, err
	}
	keys := NewMemEvaluationKeySet(&RelinearizationKey{EvaluationKey: *key})
	var count uint32
	if err = binary.Read(r, binary.LittleEndian, &count); err != nil {
		return nil, err
	}
	if uint64(count) > uint64(r.Len()/45) {
		return nil, fmt.Errorf("invalid packed Galois key count")
	}
	for range count {
		gk, err := ReadPackedGaloisKey(r, params)
		if err != nil {
			return nil, err
		}
		if _, exists := keys.GaloisKeys[gk.GaloisElement]; exists {
			return nil, fmt.Errorf("duplicate packed Galois element")
		}
		keys.GaloisKeys[gk.GaloisElement] = gk
	}
	return keys, nil
}

func UnmarshalPackedEvaluationKeySet(data []byte) (*MemEvaluationKeySet, error) {
	r := bytes.NewReader(data)
	params, err := ReadPackedParameters(r, PackedKeySetMagic)
	if err != nil {
		return nil, err
	}
	keys, err := ReadPackedKeySetBody(r, params)
	if err == nil && r.Len() != 0 {
		return nil, fmt.Errorf("packed key set has trailing bytes")
	}
	return keys, err
}

func packCoefficients(scratch []byte, coefficients []uint64, modulus uint64) ([]byte, error) {
	width := bits.Len64(modulus)
	size := len(coefficients) * width / 8
	clear(scratch[:size+8])
	for i, x := range coefficients {
		if x >= modulus {
			return nil, fmt.Errorf("non-canonical packed key coefficient")
		}
		offset := i * width
		index, shift := offset/8, uint(offset%8)
		word := binary.LittleEndian.Uint64(scratch[index:index+8]) | x<<shift
		binary.LittleEndian.PutUint64(scratch[index:index+8], word)
		if int(shift)+width > 64 {
			scratch[index+8] |= byte(x >> (64 - shift))
		}
	}
	return scratch[:size], nil
}

func unpackCoefficients(data []byte, coefficients []uint64, modulus uint64) error {
	width := bits.Len64(modulus)
	mask := uint64(1)<<width - 1
	for i := range coefficients {
		offset := i * width
		index, shift := offset/8, uint(offset%8)
		x := binary.LittleEndian.Uint64(data[index:index+8]) >> shift
		if int(shift)+width > 64 {
			x |= uint64(data[index+8]) << (64 - shift)
		}
		x &= mask
		if x >= modulus {
			return fmt.Errorf("invalid packed key coefficient")
		}
		coefficients[i] = x
	}
	return nil
}
