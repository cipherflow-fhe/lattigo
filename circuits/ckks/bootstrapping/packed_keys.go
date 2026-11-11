package bootstrapping

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cipherflow-fhe/lattigo/core/rlwe"
)

const PackedKeysMagic = "BTPPK001"

// GenPackedEvaluationKeysTo retains one compressed key at a time and writes
// full-width residues using a seed plus lossless modulus-width packing.
func (p Parameters) GenPackedEvaluationKeysTo(sk *rlwe.SecretKey, dst io.Writer) error {
	w := bufio.NewWriterSize(dst, 64*1024)
	params := p.BootstrappingParameters.Parameters
	if err := rlwe.WritePackedParameters(w, PackedKeysMagic, params); err != nil {
		return err
	}
	_, err := p.genEvaluationKeysSequential(sk, func(slot int, object io.WriterTo) error {
		if slot < 6 {
			if object == nil {
				return w.WriteByte(0)
			}
			if err := w.WriteByte(1); err != nil {
				return err
			}
			return rlwe.WritePackedEvaluationKey(w, params, object.(*rlwe.EvaluationKey))
		}
		if slot == 6 {
			if err := rlwe.WritePackedEvaluationKey(w, params, &object.(*rlwe.RelinearizationKey).EvaluationKey); err != nil {
				return err
			}
			return binary.Write(w, binary.LittleEndian, uint32(len(p.evaluationGaloisElements())))
		}
		if err := rlwe.WritePackedGaloisKey(w, params, object.(*rlwe.GaloisKey)); err != nil {
			return err
		}
		return w.Flush()
	}, rlwe.EvaluationKeyParameters{Compressed: true})
	if err != nil {
		return err
	}
	return w.Flush()
}

func UnmarshalPackedEvaluationKeys(data []byte) (*EvaluationKeys, error) {
	r := bytes.NewReader(data)
	params, err := rlwe.ReadPackedParameters(r, PackedKeysMagic)
	if err != nil {
		return nil, err
	}
	keys := new(EvaluationKeys)
	for _, target := range []**rlwe.EvaluationKey{&keys.EvkN1ToN2, &keys.EvkN2ToN1, &keys.EvkRealToCmplx, &keys.EvkCmplxToReal, &keys.EvkDenseToSparse, &keys.EvkSparseToDense} {
		flag, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if flag > 1 {
			return nil, fmt.Errorf("invalid packed bootstrap key flag")
		}
		if flag == 1 {
			if *target, err = rlwe.ReadPackedEvaluationKey(r, params); err != nil {
				return nil, err
			}
		}
	}
	keys.MemEvaluationKeySet, err = rlwe.ReadPackedKeySetBody(r, params)
	if err == nil && r.Len() != 0 {
		return nil, fmt.Errorf("packed bootstrap keys have trailing bytes")
	}
	return keys, err
}
