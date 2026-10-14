package clientcontext

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/rlwe"
)

// EvaluationStream holds one serialized payload at a time. The caller consumes
// each returned slice before calling Next again. DtS/StD share one sparse SK.
type EvaluationStream struct {
	keys     Keys
	kgen     ckks.KeyGenerator
	elements []uint64
	index    int
	stage    int
	buffer   bytes.Buffer
	std      *rlwe.SwitchingKey
}

func NewEvaluationStream(keys Keys) (*EvaluationStream, error) {
	if keys.SK == nil || keys.PK == nil || keys.Params.PCount() == 0 {
		return nil, errors.New("streaming requires parameters and SK/PK")
	}
	var extra []int
	if keys.BTP != nil {
		extra = keys.BTP.RotationsForBootstrapping(keys.Params)
	}
	elements := GaloisElements(keys.Params, extra)
	if len(elements) > 65535 {
		return nil, errors.New("too many Galois keys")
	}
	return &EvaluationStream{keys: keys, kgen: ckks.NewKeyGenerator(keys.Params), elements: elements}, nil
}

func (s *EvaluationStream) Next() ([]byte, error) {
	s.buffer.Reset()
	p := &s.keys.Params.Parameters
	switch s.stage {
	case 0:
		params, err := s.keys.Params.MarshalBinary()
		if err != nil {
			return nil, err
		}
		binary.Write(&s.buffer, parameterOrder(s.keys.BTP), uint32(len(params)))
		s.buffer.Write(params)
		s.buffer.WriteByte(0)
		if s.keys.BTP == nil {
			s.buffer.WriteByte(0)
		} else {
			s.buffer.WriteByte(1)
			rlwe.CiphertextQPToBytes(s.keys.PK, p, &s.buffer)
			btp, err := s.keys.BTP.MarshalBinary()
			if err != nil {
				return nil, err
			}
			if len(btp) > 255 {
				return nil, errors.New("BTP parameters exceed uint8 length")
			}
			s.buffer.WriteByte(byte(len(btp)))
			s.buffer.Write(btp)
		}
		s.stage++
	case 1:
		s.buffer.WriteByte(1)
		rlwe.RelinearizationKeyToByte(s.kgen.GenRelinearizationKey(s.keys.SK, 1), p, &s.buffer)
		s.stage++
	case 2:
		s.buffer.WriteByte(1)
		binary.Write(&s.buffer, binary.LittleEndian, uint16(len(s.elements)))
		s.stage++
	case 3:
		if s.index < len(s.elements) {
			element := s.elements[s.index]
			binary.Write(&s.buffer, binary.LittleEndian, element)
			rlwe.SwitchingKeyToBytes(s.kgen.GenSwitchingKeyForGalois(element, s.keys.SK), p, &s.buffer)
			s.index++
		} else {
			s.stage++
			return s.Next()
		}
	case 4:
		if s.keys.BTP == nil {
			s.stage = 6
			return s.Next()
		}
		dts, std := s.keys.BTP.GenEncapsulationSwitchingKeys(s.keys.Params, s.keys.SK)
		s.std = std
		if dts == nil {
			s.buffer.WriteByte(0)
		} else {
			sparse, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{LogN: p.LogN(), Q: p.Q()[:1], P: p.P()})
			if err != nil {
				return nil, err
			}
			s.buffer.WriteByte(1)
			rlwe.GadgetCiphertextToBytes(&dts.GadgetCiphertext, &sparse, &s.buffer)
		}
		s.stage++
	case 5:
		if s.std == nil {
			s.buffer.WriteByte(0)
		} else {
			s.buffer.WriteByte(1)
			rlwe.GadgetCiphertextToBytes(&s.std.GadgetCiphertext, p, &s.buffer)
		}
		s.std = nil
		s.stage++
	default:
		s.kgen = nil
		s.buffer = bytes.Buffer{}
		return nil, nil
	}
	return s.buffer.Bytes(), nil
}
