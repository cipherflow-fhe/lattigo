package clientcontext

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"slices"

	"github.com/cipherflow-fhe/lattigo/circuits/ckks/bootstrapping"
	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/schemes/ckks"
)

const contextMagic = "CKKSCTX1"

// KeyPlan specifies the v6 keys to generate. It is persisted separately from
// the existing CKKSCTX1 wire; GaloisElements contains explicit additional keys.
type KeyPlan struct {
	DefaultRotations bool
	Bootstrapping    bool
	GaloisElements   []uint64
}

// Context holds only client keys. It never retains evaluation keys. Callers
// must not mutate Parameters, SecretKey, or PublicKey while an export is active.
type Context struct {
	Parameters ckks.Parameters
	SecretKey  *rlwe.SecretKey
	PublicKey  *rlwe.PublicKey
	plan       KeyPlan
	galEls     []uint64
	btp        *bootstrapping.Parameters
}

// New validates the generation plan before sampling the one client SK/PK pair.
func New(params ckks.Parameters, plan KeyPlan) (*Context, error) {
	c, err := prepare(params, plan)
	if err != nil {
		return nil, err
	}
	kgen := rlwe.NewKeyGenerator(params)
	c.SecretKey = kgen.GenSecretKeyNew()
	c.PublicKey = kgen.GenPublicKeyNew(c.SecretKey)
	return c, nil
}

// FromKeys borrows existing v6 keys, avoiding a second pair in native bridges.
func FromKeys(params ckks.Parameters, sk *rlwe.SecretKey, pk *rlwe.PublicKey, plan KeyPlan) (*Context, error) {
	c, err := prepare(params, plan)
	if err != nil {
		return nil, err
	}
	if sk == nil || pk == nil || sk.Value.Q.N() != params.N() ||
		sk.LevelQ() != params.MaxLevelQ() || sk.LevelP() != params.MaxLevelP() {
		return nil, fmt.Errorf("secret key dimensions or levels do not match parameters")
	}
	for _, poly := range pk.Value {
		if poly.Q.N() != params.N() || poly.Q.Level() != params.MaxLevelQ() || poly.P.Level() != params.MaxLevelP() ||
			(params.PCount() != 0 && poly.P.N() != params.N()) {
			return nil, fmt.Errorf("public key dimensions or levels do not match parameters")
		}
	}
	if params.PCount() != 0 && sk.Value.P.N() != params.N() {
		return nil, fmt.Errorf("secret key P dimension does not match parameters")
	}
	c.SecretKey, c.PublicKey = sk, pk
	return c, nil
}

func prepare(params ckks.Parameters, plan KeyPlan) (*Context, error) {
	if params.N() == 0 || params.PCount() == 0 {
		return nil, fmt.Errorf("client evaluation keys require valid Q/P parameters")
	}
	plan.GaloisElements = slices.Clone(plan.GaloisElements)
	c := &Context{Parameters: params, plan: plan, galEls: slices.Clone(plan.GaloisElements)}
	if plan.DefaultRotations {
		l := params.LogMaxSlots()
		for i := 0; i < l; i++ {
			c.galEls = append(c.galEls, params.GaloisElement(1<<i))
		}
		for i := 0; i < l-1; i++ {
			c.galEls = append(c.galEls, params.GaloisElement(-(1 << i)))
		}
		if params.RingType() == ring.Standard {
			c.galEls = append(c.galEls, params.GaloisElementForComplexConjugation())
		}
	}
	slices.Sort(c.galEls)
	c.galEls = slices.Compact(c.galEls)
	for _, galEl := range c.galEls {
		if galEl&1 == 0 || galEl >= params.RingQ().NthRoot() {
			return nil, fmt.Errorf("invalid GaloisElement %d", galEl)
		}
		if params.RingType() == ring.ConjugateInvariant && galEl%4 != 1 {
			return nil, fmt.Errorf("GaloisElement %d is not a CI rotation", galEl)
		}
	}
	if plan.Bootstrapping {
		p, err := BootstrappingParameters(params)
		if err != nil {
			return nil, err
		}
		c.btp = &p
	}
	return c, nil
}

// WriteEval writes the existing SDK CKKSCTX1 encoding, generating one key at a
// time. dst must be empty and unpublished; any failure leaves it incomplete.
func (c *Context) WriteEval(dst Sink) (uint64, error) {
	w := &streamWriter{dst: dst}
	err := c.writeContext(w, true)
	return w.pos, err
}

// WriteFull writes the existing native two-u64-blob container, retaining the
// original PK but excluding residual and boot evaluation keys.
func (c *Context) WriteFull(dst Sink) (uint64, error) {
	w := &streamWriter{dst: dst}
	if err := w.blob(func(io.Writer) error { return c.writeContext(w, false) }); err != nil {
		return w.pos, err
	}
	err := w.blob(func(dst io.Writer) error { return writeObject(dst, c.SecretKey) })
	return w.pos, err
}

func (c *Context) writeContext(w *streamWriter, eval bool) error {
	if c.SecretKey == nil || c.PublicKey == nil {
		return fmt.Errorf("client keys are not initialized")
	}
	if _, err := w.Write([]byte(contextMagic)); err != nil {
		return err
	}
	parameter, err := c.Parameters.MarshalBinary()
	if err != nil {
		return err
	}
	if err = w.blob(func(dst io.Writer) error { _, e := dst.Write(parameter); return e }); err != nil {
		return err
	}
	for _, flag := range []bool{c.plan.DefaultRotations, c.plan.Bootstrapping, true} {
		if err = w.flag(flag); err != nil {
			return err
		}
	}
	if err = w.blob(func(dst io.Writer) error { return writeObject(dst, c.PublicKey) }); err != nil {
		return err
	}
	if err = w.flag(eval); err != nil {
		return err
	}
	if eval {
		if err = w.blob(c.writeResidualKeys); err != nil {
			return err
		}
	}
	if err = w.flag(eval && c.btp != nil); err != nil {
		return err
	}
	if eval && c.btp != nil {
		return w.blob(func(dst io.Writer) error { _, e := c.btp.GenEvaluationKeysTo(c.SecretKey, dst); return e })
	}
	return nil
}

func (c *Context) writeResidualKeys(dst io.Writer) error {
	kgen := rlwe.NewKeyGenerator(c.Parameters)
	if _, err := dst.Write([]byte{1}); err != nil { // RLK present
		return err
	}
	if err := writeObject(dst, kgen.GenRelinearizationKeyNew(c.SecretKey)); err != nil {
		return err
	}
	if _, err := dst.Write([]byte{1}); err != nil { // Galois map present
		return err
	}
	var count [4]byte
	binary.LittleEndian.PutUint32(count[:], uint32(len(c.galEls)))
	if _, err := dst.Write(count[:]); err != nil {
		return err
	}
	for _, galEl := range c.galEls {
		var key [8]byte
		binary.LittleEndian.PutUint64(key[:], galEl)
		if _, err := dst.Write(key[:]); err != nil {
			return err
		}
		if err := writeObject(dst, kgen.GenGaloisKeyNew(galEl, c.SecretKey)); err != nil {
			return err
		}
	}
	return nil
}

// Restore accepts only the client-only full container, with strict blob and EOF
// checks before native key decoding. The trusted plan comes from the profile.
func Restore(full []byte, plan KeyPlan) (*Context, error) {
	r := bytes.NewReader(full)
	public, err := readBlob(r)
	if err != nil {
		return nil, err
	}
	secret, err := readBlob(r)
	if err != nil || r.Len() != 0 {
		return nil, fmt.Errorf("invalid full context length or trailing bytes")
	}
	p := bytes.NewReader(public)
	var magic [8]byte
	if _, err = io.ReadFull(p, magic[:]); err != nil || string(magic[:]) != contextMagic {
		return nil, fmt.Errorf("invalid client context magic")
	}
	parameter, err := readBlob(p)
	if err != nil {
		return nil, err
	}
	var params ckks.Parameters
	if err = params.UnmarshalBinary(parameter); err != nil {
		return nil, err
	}
	for _, expected := range []bool{plan.DefaultRotations, plan.Bootstrapping, true} {
		flag, e := p.ReadByte()
		if e != nil || flag > 1 || (flag == 1) != expected {
			return nil, fmt.Errorf("client context flags do not match key plan")
		}
	}
	pkData, err := readBlob(p)
	if err != nil {
		return nil, err
	}
	for range 2 {
		flag, e := p.ReadByte()
		if e != nil || flag != 0 {
			return nil, fmt.Errorf("full context must not contain evaluation keys")
		}
	}
	if p.Len() != 0 {
		return nil, fmt.Errorf("client context has trailing bytes")
	}
	// Check dimensions before ReadFrom can allocate attacker-chosen slices.
	if err = validateKey(secret, params, false); err != nil {
		return nil, err
	}
	if err = validateKey(pkData, params, true); err != nil {
		return nil, err
	}
	sk, pk := rlwe.NewSecretKey(params), rlwe.NewPublicKey(params)
	if err = decodeKey(secret, sk); err != nil {
		return nil, err
	}
	if err = decodeKey(pkData, pk); err != nil {
		return nil, err
	}
	return FromKeys(params, sk, pk, plan)
}

func readBlob(r *bytes.Reader) ([]byte, error) {
	var length uint64
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}
	if length > uint64(r.Len()) {
		return nil, fmt.Errorf("truncated context blob")
	}
	data := make([]byte, int(length)) // bounded by the existing in-memory container
	_, err := io.ReadFull(r, data)
	return data, err
}

func decodeKey(data []byte, key io.ReaderFrom) error {
	n, err := key.ReadFrom(bytes.NewReader(data))
	if err != nil {
		return err
	}
	if n != int64(len(data)) {
		return fmt.Errorf("key has trailing bytes")
	}
	return nil
}

func validateKey(data []byte, params ckks.Parameters, public bool) error {
	r := bytes.NewReader(data)
	readCount := func(expected uint64) error {
		var actual uint64
		if err := binary.Read(r, binary.LittleEndian, &actual); err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("key dimension %d does not match %d", actual, expected)
		}
		return nil
	}
	polys := 1
	if public {
		if err := readCount(2); err != nil {
			return err
		}
		polys = 2
	}
	for range polys {
		for _, count := range []int{params.QCount(), params.PCount()} {
			if err := readCount(uint64(count)); err != nil {
				return err
			}
			for range count {
				if err := readCount(uint64(params.N())); err != nil {
					return err
				}
				length := uint64(params.N()) * 8
				if length > uint64(r.Len()) {
					return fmt.Errorf("truncated key coefficients")
				}
				if _, err := r.Seek(int64(length), io.SeekCurrent); err != nil {
					return err
				}
			}
		}
	}
	if r.Len() != 0 {
		return fmt.Errorf("key has trailing bytes")
	}
	return nil
}
