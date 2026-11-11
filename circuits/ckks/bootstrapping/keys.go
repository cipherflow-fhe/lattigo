package bootstrapping

import (
	"bufio"
	"fmt"
	"io"
	"slices"

	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/utils/buffer"
)

// EvaluationKeys is a struct storing the different
// evaluation keys required by the bootstrapper.
type EvaluationKeys struct {

	// EvkN1ToN2 is the evaluation key to switch from the residual parameters'
	// ring degree (N1) to the bootstrapping parameters' ring degree (N2)
	EvkN1ToN2 *rlwe.EvaluationKey

	// EvkN2ToN1 is the evaluation key to switch from the bootstrapping parameters'
	// ring degree (N2) to the residual parameters' ring degree (N1)
	EvkN2ToN1 *rlwe.EvaluationKey

	// EvkRealToCmplx is the evaluation key to switch from the standard ring to the
	// conjugate invariant ring.
	EvkRealToCmplx *rlwe.EvaluationKey

	// EvkCmplxToReal is the evaluation key to switch from the conjugate invariant
	// ring to the standard ring.
	EvkCmplxToReal *rlwe.EvaluationKey

	// EvkDenseToSparse is the evaluation key to switch
	// from the dense secret to the sparse secret.
	// https://eprint.iacr.org/2022/024
	EvkDenseToSparse *rlwe.EvaluationKey

	// EvkSparseToDense is the evaluation key to switch
	// from the sparse secret to the dense secret.
	// https://eprint.iacr.org/2022/024
	EvkSparseToDense *rlwe.EvaluationKey

	// MemEvaluationKeySet is the evaluation key set storing the relinearization
	// key and the Galois keys necessary for the bootstrapping circuit.
	*rlwe.MemEvaluationKeySet
}

// GenEvaluationKeys generates the bootstrapping evaluation keys, which include:
//
// If the bootstrapping parameters' ring degree > residual parameters' ring degree:
//   - An evaluation key to switch from the residual parameters' ring to the bootstrapping parameters' ring
//   - An evaluation key to switch from the bootstrapping parameters' ring to the residual parameters' ring
//
// If the residual parameters use the Conjugate Invariant ring:
//   - An evaluation key to switch from the conjugate invariant ring to the standard ring
//   - An evaluation key to switch from the standard ring to the conjugate invariant ring
//
// The core bootstrapping circuit evaluation keys:
//   - Relinearization key
//   - Galois keys
//   - The encapsulation evaluation keys (https://eprint.iacr.org/2022/024)
//
// Note:
//   - These evaluation keys are generated under an ephemeral secret key skN2 using the distribution
//     specified in the bootstrapping parameters.
//   - The ephemeral key used to generate the bootstrapping keys is returned by this method for debugging purposes.
//   - !WARNING! The bootstrapping parameters use their own and independent cryptographic parameters (i.e. float.Parameters)
//     and it is the user's responsibility to ensure that these parameters meet the target security and tweak them if necessary.
func (p Parameters) GenEvaluationKeys(skN1 *rlwe.SecretKey) (btpkeys *EvaluationKeys, skN2 *rlwe.SecretKey, err error) {
	btpkeys = &EvaluationKeys{MemEvaluationKeySet: rlwe.NewMemEvaluationKeySet(nil)}
	skN2, err = p.genEvaluationKeysSequential(skN1, func(slot int, key io.WriterTo) error {
		if key == nil {
			return nil
		}
		switch slot {
		case 0:
			btpkeys.EvkN1ToN2 = key.(*rlwe.EvaluationKey)
		case 1:
			btpkeys.EvkN2ToN1 = key.(*rlwe.EvaluationKey)
		case 2:
			btpkeys.EvkRealToCmplx = key.(*rlwe.EvaluationKey)
		case 3:
			btpkeys.EvkCmplxToReal = key.(*rlwe.EvaluationKey)
		case 4:
			btpkeys.EvkDenseToSparse = key.(*rlwe.EvaluationKey)
		case 5:
			btpkeys.EvkSparseToDense = key.(*rlwe.EvaluationKey)
		case 6:
			btpkeys.RelinearizationKey = key.(*rlwe.RelinearizationKey)
		case 7:
			gk := key.(*rlwe.GaloisKey)
			btpkeys.GaloisKeys[gk.GaloisElement] = gk
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return
}

// GenEvaluationKeysTo generates and writes the native v6 EvaluationKeys encoding
// without retaining the complete key set. Each key is flushed before generating
// the next; a write failure stops generation. The existing ring-swap primitive
// is the only step that temporarily returns a pair of keys.
func (p Parameters) GenEvaluationKeysTo(skN1 *rlwe.SecretKey, dst io.Writer) (n int64, err error) {
	w := bufio.NewWriterSize(dst, 64*1024)
	writeFlag := func(v uint8) error {
		inc, e := buffer.WriteUint8(w, v)
		n += inc
		return e
	}
	_, err = p.genEvaluationKeysSequential(skN1, func(slot int, key io.WriterTo) error {
		if slot < 6 {
			if key == nil {
				return writeFlag(0)
			}
			if e := writeFlag(1); e != nil {
				return e
			}
		} else if slot == 6 {
			// Boot MemEvaluationKeySet presence, followed by RLK presence.
			if e := writeFlag(1); e != nil {
				return e
			}
			if e := writeFlag(1); e != nil {
				return e
			}
		} else {
			inc, e := buffer.WriteUint64(w, key.(*rlwe.GaloisKey).GaloisElement)
			n += inc
			if e != nil {
				return e
			}
		}
		inc, e := key.WriteTo(w)
		n += inc
		if e != nil {
			return e
		}
		if slot == 6 {
			if e = writeFlag(1); e != nil {
				return e
			}
			inc, e = buffer.WriteUint32(w, uint32(len(p.evaluationGaloisElements())))
			n += inc
			if e != nil {
				return e
			}
		}
		return w.Flush()
	})
	if err != nil {
		return n, err
	}
	return n, w.Flush()
}

func (p Parameters) evaluationGaloisElements() []uint64 {
	params := p.BootstrappingParameters
	galEls := append(p.GaloisElements(params), params.GaloisElementForComplexConjugation())
	slices.Sort(galEls)
	return slices.Compact(galEls)
}

// slot follows EvaluationKeys.WriteTo: six optional switching keys, RLK, GLKs.
// The visitor borrows the key only for the duration of the call unless it is the
// bulk collector above. Temporary secrets remain alive for all linked keys.
func (p Parameters) genEvaluationKeysSequential(skN1 *rlwe.SecretKey, visit func(int, io.WriterTo) error, evkParams ...rlwe.EvaluationKeyParameters) (skN2 *rlwe.SecretKey, err error) {
	paramsN2 := p.BootstrappingParameters
	kgen := rlwe.NewKeyGenerator(paramsN2)
	if p.ResidualParameters.N() != paramsN2.N() {
		skN2 = kgen.GenSecretKeyNew()
	} else {
		ringQ, ringP := paramsN2.RingQ(), paramsN2.RingP()
		skN2 = rlwe.NewSecretKey(paramsN2)
		buff := ringQ.NewPoly()
		rlwe.ExtendBasisSmallNormAndCenterNTTMontgomery(ringQ, ringQ, skN1.Value.Q, buff, skN2.Value.Q)
		rlwe.ExtendBasisSmallNormAndCenterNTTMontgomery(ringQ, ringP, skN1.Value.Q, buff, skN2.Value.P)
	}

	switchKey := func(slot int, key *rlwe.EvaluationKey) error {
		if key == nil {
			return visit(slot, nil)
		}
		return visit(slot, key)
	}
	crossN := p.ResidualParameters.N() != paramsN2.N()
	ci := p.ResidualParameters.RingType() == ring.ConjugateInvariant
	for slot := 0; slot < 2; slot++ {
		var key *rlwe.EvaluationKey
		if crossN && !ci {
			if slot == 0 {
				key = kgen.GenEvaluationKeyNew(skN1, skN2, evkParams...)
			} else {
				key = kgen.GenEvaluationKeyNew(skN2, skN1, evkParams...)
			}
		}
		if err = switchKey(slot, key); err != nil {
			return nil, err
		}
	}
	var realToCmplx, cmplxToReal *rlwe.EvaluationKey
	if crossN && ci {
		cmplxToReal, realToCmplx = kgen.GenEvaluationKeysForRingSwapNew(skN2, skN1, evkParams...)
	}
	if err = switchKey(2, realToCmplx); err != nil {
		return nil, err
	}
	realToCmplx = nil
	if err = switchKey(3, cmplxToReal); err != nil {
		return nil, err
	}
	cmplxToReal = nil

	if p.EphemeralSecretWeight == 0 {
		for slot := 4; slot < 6; slot++ {
			if err = switchKey(slot, nil); err != nil {
				return nil, err
			}
		}
	} else {
		paramsSparse, e := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN: paramsN2.LogN(), Q: paramsN2.Q()[:1], P: paramsN2.P(),
		})
		if e != nil {
			return nil, e
		}
		kgenSparse := rlwe.NewKeyGenerator(paramsSparse)
		skSparse := kgenSparse.GenSecretKeyWithHammingWeightNew(p.EphemeralSecretWeight)
		if err = switchKey(4, kgenSparse.GenEvaluationKeyNew(skN2, skSparse, evkParams...)); err != nil {
			return nil, err
		}
		if err = switchKey(5, kgen.GenEvaluationKeyNew(skSparse, skN2, evkParams...)); err != nil {
			return nil, err
		}
	}
	if err = visit(6, kgen.GenRelinearizationKeyNew(skN2, evkParams...)); err != nil {
		return nil, err
	}
	for _, galEl := range p.evaluationGaloisElements() {
		if err = visit(7, kgen.GenGaloisKeyNew(galEl, skN2, evkParams...)); err != nil {
			return nil, err
		}
	}
	return skN2, nil
}

// BinarySize returns the total binary size of the bootstrapper's keys.
func (b EvaluationKeys) BinarySize() (dLen int) {
	if b.EvkN1ToN2 != nil {
		dLen += b.EvkN1ToN2.BinarySize()
	}
	dLen++

	if b.EvkN2ToN1 != nil {
		dLen += b.EvkN2ToN1.BinarySize()
	}
	dLen++

	if b.EvkRealToCmplx != nil {
		dLen += b.EvkRealToCmplx.BinarySize()
	}
	dLen++

	if b.EvkCmplxToReal != nil {
		dLen += b.EvkCmplxToReal.BinarySize()
	}
	dLen++

	if b.EvkDenseToSparse != nil {
		dLen += b.EvkDenseToSparse.BinarySize()
	}
	dLen++

	if b.EvkSparseToDense != nil {
		dLen += b.EvkSparseToDense.BinarySize()
	}
	dLen++

	if b.MemEvaluationKeySet != nil {
		dLen += b.MemEvaluationKeySet.BinarySize()
	}
	dLen++

	return
}

// MarshalBinary encodes the object into a binary form on a newly allocated slices of bytes.
func (b EvaluationKeys) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(b.BinarySize())
	_, err = b.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary encodes a slices of bytes generated by MarshalBinary or WriteTo on the object.
func (b *EvaluationKeys) UnmarshalBinary(p []byte) (err error) {
	_, err = b.ReadFrom(buffer.NewBuffer(p))
	return
}

// WriteTo writes the object on an io.Writer. It implements the io.WriterTo
// interface, and will write exactly object.BinarySize() bytes on w.
//
// Unless w implements the buffer.Writer interface (see lattigo/utils/buffer/writer.go),
// it will be wrapped into a bufio.Writer. Since this requires allocations, it
// is preferable to pass a buffer.Writer directly:
//
//   - When writing multiple times to a io.Writer, it is preferable to first wrap the
//     io.Writer in a pre-allocated bufio.Writer.
//   - When writing to a pre-allocated var b []byte, it is preferable to pass
//     buffer.NewBuffer(b) as w (see lattigo/utils/buffer/buffer.go).
func (b EvaluationKeys) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		inc, err = writeEvkKey(b.EvkN1ToN2, w)
		if err != nil {
			return inc, fmt.Errorf("cannot write EvkN1ToN2 evaluation key: %w", err)
		}
		n += inc

		inc, err = writeEvkKey(b.EvkN2ToN1, w)
		if err != nil {
			return inc, fmt.Errorf("cannot write EvkN2ToN1 evaluation key: %w", err)
		}
		n += inc

		inc, err = writeEvkKey(b.EvkRealToCmplx, w)
		if err != nil {
			return inc, fmt.Errorf("cannot write EvkRealToCmplx evaluation key: %w", err)
		}
		n += inc

		inc, err = writeEvkKey(b.EvkCmplxToReal, w)
		if err != nil {
			return inc, fmt.Errorf("cannot write EvkCmplxToReal evaluation key: %w", err)
		}
		n += inc

		inc, err = writeEvkKey(b.EvkDenseToSparse, w)
		if err != nil {
			return inc, fmt.Errorf("cannot write EvkDenseToSparse evaluation key: %w", err)
		}
		n += inc

		inc, err = writeEvkKey(b.EvkSparseToDense, w)
		if err != nil {
			return inc, fmt.Errorf("cannot write EvkSparseToDense evaluation key: %w", err)
		}
		n += inc

		if b.MemEvaluationKeySet != nil {
			if inc, err = buffer.WriteUint8(w, 1); err != nil {
				return inc, err
			}
			n += inc

			if inc, err = b.MemEvaluationKeySet.WriteTo(w); err != nil {
				return n + inc, err
			}
			n += inc

		} else {
			if inc, err = buffer.WriteUint8(w, 0); err != nil {
				return inc, err
			}
			n += inc
		}

		return n, w.Flush()
	default:
		return b.WriteTo(bufio.NewWriter(w))
	}
}

// ReadFrom reads on the object from an io.Writer. It implements the
// io.ReaderFrom interface.
//
// Unless r implements the buffer.Reader interface (see see lattigo/utils/buffer/reader.go),
// it will be wrapped into a bufio.Reader. Since this requires allocation, it
// is preferable to pass a buffer.Reader directly:
//
//   - When reading multiple values from a io.Reader, it is preferable to first
//     first wrap io.Reader in a pre-allocated bufio.Reader.
//   - When reading from a var b []byte, it is preferable to pass a buffer.NewBuffer(b)
//     as w (see lattigo/utils/buffer/buffer.go).
func (b *EvaluationKeys) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		var inc int64

		b.EvkN1ToN2, inc, err = readEvkKey(r)
		if err != nil {
			return inc, fmt.Errorf("unable to read EvkN1ToN2 evaluation key: %w", err)
		}
		n += inc

		b.EvkN2ToN1, inc, err = readEvkKey(r)
		if err != nil {
			return inc, fmt.Errorf("unable to read EvkN2ToN1 evaluation key: %w", err)
		}
		n += inc

		b.EvkRealToCmplx, inc, err = readEvkKey(r)
		if err != nil {
			return inc, fmt.Errorf("unable to read EvkRealToCmplx evaluation key: %w", err)
		}
		n += inc

		b.EvkCmplxToReal, inc, err = readEvkKey(r)
		if err != nil {
			return inc, fmt.Errorf("unable to read EvkCmplxToReal evaluation key: %w", err)
		}
		n += inc

		b.EvkDenseToSparse, inc, err = readEvkKey(r)
		if err != nil {
			return inc, fmt.Errorf("unable to read EvkDenseToSparse evaluation key: %w", err)
		}
		n += inc

		b.EvkSparseToDense, inc, err = readEvkKey(r)
		if err != nil {
			return inc, fmt.Errorf("unable to read EvkSparseToDense evaluation key: %w", err)
		}
		n += inc

		var hasKey uint8

		if inc, err = buffer.ReadUint8(r, &hasKey); err != nil {
			return inc, err
		}
		n += inc

		if hasKey == 1 {

			b.MemEvaluationKeySet = new(rlwe.MemEvaluationKeySet)

			if inc, err = b.MemEvaluationKeySet.ReadFrom(r); err != nil {
				return inc, err
			}

			n += inc
		}

		return n, nil

	default:
		return b.ReadFrom(bufio.NewReader(r))
	}
}

// writeEvkKey is a helper function for marshalling a bootstrapping evaluation key.
func writeEvkKey(key *rlwe.EvaluationKey, w buffer.Writer) (n int64, err error) {
	var inc int64

	if key != nil {
		if inc, err = buffer.WriteUint8(w, 1); err != nil {
			return inc, err
		}
		n += inc

		if inc, err = key.WriteTo(w); err != nil {
			return inc, err
		}
		n += inc
	} else {
		if inc, err = buffer.WriteUint8(w, 0); err != nil {
			return inc, err
		}
		n += inc
	}
	return
}

// readEvkKey is a helper function for unmarshalling a bootstrapping evaluation key.
func readEvkKey(r buffer.Reader) (key *rlwe.EvaluationKey, n int64, err error) {
	var (
		inc    int64
		hasKey uint8
	)

	if inc, err = buffer.ReadUint8(r, &hasKey); err != nil {
		return nil, inc, err
	}
	n += inc

	if hasKey == 1 {

		key = new(rlwe.EvaluationKey)

		if inc, err = key.ReadFrom(r); err != nil {
			return nil, n + inc, err
		}

		n += inc
	}
	return
}
