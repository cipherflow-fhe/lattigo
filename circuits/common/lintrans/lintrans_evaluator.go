package lintrans

import (
	"fmt"

	"github.com/cipherflow-fhe/lattigo/core/rlwe"
	"github.com/cipherflow-fhe/lattigo/ring"
	"github.com/cipherflow-fhe/lattigo/ring/ringqp"
	"github.com/cipherflow-fhe/lattigo/schemes"
	"github.com/cipherflow-fhe/lattigo/utils"
)

type Evaluator struct {
	schemes.Evaluator
	pool *rlwe.BufferPool
}

func NewEvaluator(eval schemes.Evaluator) *Evaluator {

	return &Evaluator{
		Evaluator: eval,
		pool:      rlwe.NewPool(eval.GetRLWEParameters().RingQP()),
	}
}

// EvaluateMany takes as input a ciphertext ctIn, a list of linear transformations [M0, M1, M2, ...] and a list of pre-allocated receiver opOut
// and evaluates opOut: [M0(ctIn), M1(ctIn), M2(ctIn), ...]
func (eval Evaluator) EvaluateMany(ctIn *rlwe.Ciphertext, linearTransformations []LinearTransformation, opOut []*rlwe.Ciphertext) (err error) {

	if len(opOut) < len(linearTransformations) {
		return fmt.Errorf("output *rlwe.Ciphertext slice is too small")
	}
	for i := range linearTransformations {
		if opOut[i] == nil {
			return fmt.Errorf("output slice contains unallocated ciphertext")
		}
	}

	var levelQ int
	levelP := linearTransformations[0].LevelP
	for _, lt := range linearTransformations {
		levelQ = utils.Max(levelQ, lt.LevelQ)

		if levelP != lt.LevelP {
			return fmt.Errorf("all linearTransformations must have the same levelP")
		}
	}

	levelQ = utils.Min(levelQ, ctIn.Level())

	poolQP := eval.pool.AtLevel(levelQ, levelP)
	buffDecompQP := poolQP.GetBuffDecompQP(*eval.GetRLWEParameters(), levelQ, levelP)
	defer eval.pool.RecycleBuffDecompQP(buffDecompQP)

	eval.DecomposeNTT(levelQ, levelP, levelP+1, ctIn.Value[1], ctIn.IsNTT, buffDecompQP)

	ctPreRot := map[int]*rlwe.Element[ringqp.Poly]{}

	for i, lt := range linearTransformations {

		if lt.N1 == 0 {
			if err = eval.MultiplyByDiagMatrix(ctIn, lt, buffDecompQP, opOut[i]); err != nil {
				return
			}
		} else {

			_, _, rotN2 := lt.BSGSIndex()

			if err = eval.PreRotatedCiphertextForDiagonalMatrixMultiplication(levelQ, levelP, ctIn, buffDecompQP, rotN2, ctPreRot, lt.UseDefaultRotationKeys, 1<<lt.LogDimensions.Cols); err != nil { // @company CipherFlow
				return
			}

			if err = eval.MultiplyByDiagMatrixBSGS(ctIn, lt, ctPreRot, opOut[i]); err != nil {
				return
			}
		}
	}

	return
}

// PreRotatedCiphertextForDiagonalMatrixMultiplication populates ctPreRot with the pre-rotated ciphertext for the rotations rots and deletes rotated ciphertexts that are not in rots.
// @company CipherFlow. If useDefaultRotationKeys is true, each rotation is evaluated as a chain of the default rotations ±2^i (see
// [NAFRotationSubsteps]) with `slots` the number of plaintext slots. In this case BuffDecompQP (the RNS
// decomposition of ctIn) is reused for the first substep of every chain.
func (eval Evaluator) PreRotatedCiphertextForDiagonalMatrixMultiplication(
	levelQ, levelP int,
	ctIn *rlwe.Ciphertext,
	BuffDecompQP []ringqp.Poly,
	rots []int,
	ctPreRot map[int]*rlwe.Element[ringqp.Poly],
	useDefaultRotationKeys bool, slots int, // @company CipherFlow
) (err error) {

	params := eval.GetRLWEParameters()

	rotsMap := map[int]bool{}

	for _, i := range rots {
		rotsMap[i] = true
	}

	// Cleans the map of non-required ciphertexts
	for i := range ctPreRot {
		if _, ok := rotsMap[i]; !ok {
			delete(ctPreRot, i)
		}
	}

	// Computes the rotation only for the ones that are not already present.
	for _, i := range rots {
		if _, ok := ctPreRot[i]; i != 0 && !ok {
			ctPreRot[i] = rlwe.NewElementExtended(params, 1, levelQ, levelP)
			if useDefaultRotationKeys { // @company CipherFlow
				if err = eval.rotateBySubstepsQP(levelQ, levelP, ctIn, BuffDecompQP, NAFRotationSubsteps(i, slots), ctPreRot[i]); err != nil {
					return fmt.Errorf("eval.rotateBySubstepsQP: %w", err)
				}
			} else if err = eval.AutomorphismHoistedLazy(levelQ, ctIn, BuffDecompQP, params.GaloisElement(i), ctPreRot[i]); err != nil {
				return fmt.Errorf("eval.AutomorphismHoistedLazy: %w", err)
			}
		}
	}

	return
}

// rotateBySubsteps evaluates the rotation by the given chain of substeps on ctIn and returns the
// result as a normalized ciphertext modulo Q. Each substep must be a signed power of two for which a
// Galois key exists. If ctInDecompQP is not nil, it must be the RNS decomposition of ctIn and is reused
// for the first substep (it is never modified).
// @company CipherFlow. 
func (eval Evaluator) rotateBySubsteps(levelQ, levelP int, ctIn *rlwe.Ciphertext, ctInDecompQP []ringqp.Poly, substeps []int, opOut *rlwe.Ciphertext) (err error) {

	poolQP := eval.pool.AtLevel(levelQ, levelP)

	buffQP0 := poolQP.GetBuffPolyQP()
	defer poolQP.RecycleBuffPolyQP(buffQP0)
	buffQP1 := poolQP.GetBuffPolyQP()
	defer poolQP.RecycleBuffPolyQP(buffQP1)

	ctQP := &rlwe.Element[ringqp.Poly]{}
	ctQP.Value = []ringqp.Poly{*buffQP0, *buffQP1}
	ctQP.MetaData = &rlwe.MetaData{}
	ctQP.IsNTT = true

	if err = eval.rotateBySubstepsQP(levelQ, levelP, ctIn, ctInDecompQP, substeps, ctQP); err != nil {
		return
	}

	eval.ModDownQPtoQNTT(levelQ, levelP, ctQP.Value[0].Q, ctQP.Value[0].P, opOut.Value[0])
	eval.ModDownQPtoQNTT(levelQ, levelP, ctQP.Value[1].Q, ctQP.Value[1].P, opOut.Value[1])
	opOut.IsNTT = ctIn.IsNTT

	return
}

// rotateBySubstepsQP evaluates the rotation by the given chain of substeps on ctIn and returns the
// result in the QP basis, scaled by P (i.e. as an un-normalized lazy automorphism would).
// If ctInDecompQP is not nil, it must be the RNS decomposition of ctIn: it is used for the first substep
// and is not modified (an internal buffer is used for the decompositions of the intermediate results).
// @company CipherFlow
func (eval Evaluator) rotateBySubstepsQP(levelQ, levelP int, ctIn *rlwe.Ciphertext, ctInDecompQP []ringqp.Poly, substeps []int, opOutQP *rlwe.Element[ringqp.Poly]) (err error) {

	params := eval.GetRLWEParameters()

	ringQP := params.RingQP().AtLevel(levelQ, levelP)
	ringQ := ringQP.RingQ
	ringP := ringQP.RingP
	poolQP := eval.pool.AtLevel(levelQ, levelP)

	if len(substeps) == 0 {
		// Identity rotation: returns P*ctIn in the Q basis, with zero P residues.
		ringQ.MulScalarBigint(ctIn.Value[0], ringP.ModulusAtLevel[levelP], opOutQP.Value[0].Q)
		ringQ.MulScalarBigint(ctIn.Value[1], ringP.ModulusAtLevel[levelP], opOutQP.Value[1].Q)
		opOutQP.Value[0].P.Zero()
		opOutQP.Value[1].P.Zero()
		return
	}

	// Decomposition used by the current substep. If it was provided by the caller, it must not be
	// overwritten, so the decompositions of the intermediate results use a separate buffer.
	compCur := ctInDecompQP

	if compCur == nil {
		compCur = poolQP.GetBuffDecompQP(*params, levelQ, levelP)
		defer eval.pool.RecycleBuffDecompQP(compCur)
		eval.DecomposeNTT(levelQ, levelP, levelP+1, ctIn.Value[1], ctIn.IsNTT, compCur)
	}

	// Fast path: a single substep writes the lazy automorphism result directly to the output,
	// without allocating the intermediate buffers.
	if len(substeps) == 1 {
		return eval.AutomorphismHoistedLazy(levelQ, ctIn, compCur, params.GaloisElement(substeps[0]), opOutQP)
	}

	var decompNext []ringqp.Poly
	if ctInDecompQP == nil {
		// No other owner: the intermediate decompositions can overwrite the same buffer.
		decompNext = compCur
	} else {
		decompNext = poolQP.GetBuffDecompQP(*params, levelQ, levelP)
		defer eval.pool.RecycleBuffDecompQP(decompNext)
	}

	// Buffer holding the normalized intermediate ciphertext when chaining substeps.
	buffCt := eval.pool.GetBuffCt(1, levelQ)
	defer eval.pool.RecycleBuffCt(buffCt)
	buffCt.MetaData = &rlwe.MetaData{}
	buffCt.IsNTT = true

	buffQP0 := poolQP.GetBuffPolyQP()
	defer poolQP.RecycleBuffPolyQP(buffQP0)
	buffQP1 := poolQP.GetBuffPolyQP()
	defer poolQP.RecycleBuffPolyQP(buffQP1)

	tmpQP := &rlwe.Element[ringqp.Poly]{}
	tmpQP.Value = []ringqp.Poly{*buffQP0, *buffQP1}
	tmpQP.MetaData = &rlwe.MetaData{}
	tmpQP.IsNTT = true

	ctCur := ctIn

	for i, substep := range substeps {

		// The last substep can write its result directly to the output.
		if i == len(substeps)-1 {
			return eval.AutomorphismHoistedLazy(levelQ, ctCur, compCur, params.GaloisElement(substep), opOutQP)
		}

		if err = eval.AutomorphismHoistedLazy(levelQ, ctCur, compCur, params.GaloisElement(substep), tmpQP); err != nil {
			return fmt.Errorf("eval.AutomorphismHoistedLazy: %w", err)
		}

		// Normalizes the intermediate result modulo Q to be able to chain the next automorphism.
		eval.ModDownQPtoQNTT(levelQ, levelP, tmpQP.Value[0].Q, tmpQP.Value[0].P, buffCt.Value[0])
		eval.ModDownQPtoQNTT(levelQ, levelP, tmpQP.Value[1].Q, tmpQP.Value[1].P, buffCt.Value[1])

		ctCur = buffCt
		eval.DecomposeNTT(levelQ, levelP, levelP+1, ctCur.Value[1], true, decompNext)
		compCur = decompNext
	}

	return
}

// EvaluateSequential takes as input a ciphertext ctIn and a list of linear transformations [M0, M1, M2, ...] and evaluates opOut:...M2(M1(M0(ctIn))
func (eval Evaluator) EvaluateSequential(ctIn *rlwe.Ciphertext, linearTransformations []LinearTransformation, opOut *rlwe.Ciphertext) (err error) {

	if err = eval.EvaluateMany(ctIn, linearTransformations[:1], []*rlwe.Ciphertext{opOut}); err != nil {
		return
	}

	if err = eval.Rescale(opOut, opOut); err != nil {
		return
	}

	for i := 1; i < len(linearTransformations); i++ {

		if err = eval.EvaluateMany(opOut, linearTransformations[i:i+1], []*rlwe.Ciphertext{opOut}); err != nil {
			return
		}

		if err = eval.Rescale(opOut, opOut); err != nil {
			return
		}
	}

	return
}

// MultiplyByDiagMatrix multiplies the Ciphertext ctIn by the plaintext matrix and returns the result on the Ciphertext
// opOut. Memory buffers for the decomposed ciphertext BuffDecompQP, BuffDecompQP must be provided, those are list of poly of ringQ and ringP
// respectively, each of size params.Beta().
// The naive approach is used (single hoisting and no baby-step giant-step), which is faster than MultiplyByDiagMatrixBSGS
// for matrix of only a few non-zero diagonals but uses more keys.
func (eval Evaluator) MultiplyByDiagMatrix(ctIn *rlwe.Ciphertext, matrix LinearTransformation, BuffDecompQP []ringqp.Poly, opOut *rlwe.Ciphertext) (err error) {

	*opOut.MetaData = *ctIn.MetaData
	opOut.Scale = opOut.Scale.Mul(matrix.Scale)

	params := eval.GetRLWEParameters()

	levelQ := utils.Min(opOut.Level(), utils.Min(ctIn.Level(), matrix.LevelQ))
	levelP := matrix.LevelP

	ringQP := params.RingQP().AtLevel(levelQ, levelP)
	poolQP := eval.pool.AtLevel(levelQ, levelP)
	ringQ := ringQP.RingQ
	ringP := ringQP.RingP

	buffQP0 := poolQP.GetBuffPolyQP()
	defer poolQP.RecycleBuffPolyQP(buffQP0)
	buffQP1 := poolQP.GetBuffPolyQP()
	defer poolQP.RecycleBuffPolyQP(buffQP1)
	buffQP2 := poolQP.GetBuffPolyQP()
	defer poolQP.RecycleBuffPolyQP(buffQP2)
	buffQP3 := poolQP.GetBuffPolyQP()
	defer poolQP.RecycleBuffPolyQP(buffQP3)
	buffQP4 := poolQP.GetBuffPolyQP()
	defer poolQP.RecycleBuffPolyQP(buffQP4)
	buffQP5 := poolQP.GetBuffPolyQP()
	defer poolQP.RecycleBuffPolyQP(buffQP5)
	buffCt := eval.pool.GetBuffCt(1, ringQ.Level())
	defer eval.pool.RecycleBuffCt(buffCt)

	opOut.Resize(opOut.Degree(), levelQ)

	if matrix.UseDefaultRotationKeys { // @company CipherFlow
		return eval.multiplyByDiagMatrixSubsteps(levelQ, levelP, ctIn, matrix, BuffDecompQP, opOut)
	}

	QiOverF := params.QiOverflowMargin(levelQ)
	PiOverF := params.PiOverflowMargin(levelP)

	c0OutQP := ringqp.Poly{Q: opOut.Value[0], P: (*buffQP5).Q}
	c1OutQP := ringqp.Poly{Q: opOut.Value[1], P: (*buffQP5).P}

	ct0TimesP := (*buffQP0).Q // ct0 * P mod Q
	tmp0QP := *buffQP1
	tmp1QP := *buffQP2

	cQP := &rlwe.Element[ringqp.Poly]{}
	cQP.Value = []ringqp.Poly{*buffQP3, *buffQP4}
	cQP.MetaData = &rlwe.MetaData{}
	cQP.MetaData.IsNTT = true

	buffCt.Value[0].CopyLvl(levelQ, ctIn.Value[0])
	buffCt.Value[1].CopyLvl(levelQ, ctIn.Value[1])

	ctInTmp0, ctInTmp1 := buffCt.Value[0], buffCt.Value[1]

	ringQ.MulScalarBigint(ctInTmp0, ringP.ModulusAtLevel[levelP], ct0TimesP) // P*c0

	slots := 1 << matrix.LogDimensions.Cols

	keys := utils.GetSortedKeys(matrix.Vec)

	var state bool
	if keys[0] == 0 {
		state = true
		keys = keys[1:]
	}

	for i, k := range keys {

		k &= (slots - 1)

		galEl := params.GaloisElement(k)

		var evk *rlwe.GaloisKey
		var err error
		if evk, err = eval.CheckAndGetGaloisKey(galEl); err != nil {
			return fmt.Errorf("cannot MultiplyByDiagMatrix: Automorphism: CheckAndGetGaloisKey: %w", err)
		}

		if evk.LevelP() != levelP {
			return fmt.Errorf("LinearTransformation.LevelP = %d != GaloiKey[%d].LevelP() = %d: ensure that the levelP of the linear transformation is the same as the levelP of the GaloisKeys", levelP, galEl, evk.LevelP())
		}

		index := eval.AutomorphismIndex(galEl)

		if err = eval.GadgetProductHoistedLazy(levelQ, BuffDecompQP, &evk.GadgetCiphertext, cQP); err != nil {
			return fmt.Errorf("eval.GadgetProductHoistedLazy: %w", err)
		}

		ringQ.Add(cQP.Value[0].Q, ct0TimesP, cQP.Value[0].Q)
		ringQP.AutomorphismNTTWithIndex(cQP.Value[0], index, tmp0QP)
		ringQP.AutomorphismNTTWithIndex(cQP.Value[1], index, tmp1QP)

		pt := matrix.Vec[k]

		if i == 0 {
			// keyswitch(c1_Q) = (d0_QP, d1_QP)
			ringQP.MulCoeffsMontgomery(pt, tmp0QP, c0OutQP)
			ringQP.MulCoeffsMontgomery(pt, tmp1QP, c1OutQP)
		} else {
			// keyswitch(c1_Q) = (d0_QP, d1_QP)
			ringQP.MulCoeffsMontgomeryThenAdd(pt, tmp0QP, c0OutQP)
			ringQP.MulCoeffsMontgomeryThenAdd(pt, tmp1QP, c1OutQP)
		}

		if i%QiOverF == QiOverF-1 {
			ringQ.Reduce(c0OutQP.Q, c0OutQP.Q)
			ringQ.Reduce(c1OutQP.Q, c1OutQP.Q)
		}

		if i%PiOverF == PiOverF-1 {
			ringP.Reduce(c0OutQP.P, c0OutQP.P)
			ringP.Reduce(c1OutQP.P, c1OutQP.P)
		}
	}

	if len(keys)%QiOverF == 0 {
		ringQ.Reduce(c0OutQP.Q, c0OutQP.Q)
		ringQ.Reduce(c1OutQP.Q, c1OutQP.Q)
	}

	if len(keys)%PiOverF == 0 {
		ringP.Reduce(c0OutQP.P, c0OutQP.P)
		ringP.Reduce(c1OutQP.P, c1OutQP.P)
	}

	eval.ModDownQPtoQNTT(levelQ, levelP, c0OutQP.Q, c0OutQP.P, c0OutQP.Q) // sum(phi(c0 * P + d0_QP))/P
	eval.ModDownQPtoQNTT(levelQ, levelP, c1OutQP.Q, c1OutQP.P, c1OutQP.Q) // sum(phi(d1_QP))/P

	if state { // Rotation by zero
		ringQ.MulCoeffsMontgomeryThenAdd(matrix.Vec[0].Q, ctInTmp0, c0OutQP.Q) // opOut += c0_Q * plaintext
		ringQ.MulCoeffsMontgomeryThenAdd(matrix.Vec[0].Q, ctInTmp1, c1OutQP.Q) // opOut += c1_Q * plaintext
	}

	return
}

// multiplyByDiagMatrixSubsteps is the multiplication by a diagonal matrix where each non-zero diagonal is
// reached by a chain of ±2^i rotations (i.e. using only the default rotation keys) before being multiplied
// by its plaintext diagonal.
// BuffDecompQP must be the RNS decomposition of ctIn; it is reused for the first substep of every rotation chain.
// @company CipherFlow
func (eval Evaluator) multiplyByDiagMatrixSubsteps(levelQ, levelP int, ctIn *rlwe.Ciphertext, matrix LinearTransformation, BuffDecompQP []ringqp.Poly, opOut *rlwe.Ciphertext) (err error) {

	params := eval.GetRLWEParameters()
	ringQ := params.RingQ().AtLevel(levelQ)

	slots := 1 << matrix.LogDimensions.Cols

	buffCt := eval.pool.GetBuffCt(1, ringQ.Level())
	defer eval.pool.RecycleBuffCt(buffCt)
	buffCt.MetaData = &rlwe.MetaData{}
	buffCt.IsNTT = true

	// Accumulator kept separate from opOut, as opOut may alias ctIn (which is read by the rotations).
	accCt := eval.pool.GetBuffCt(1, ringQ.Level())
	defer eval.pool.RecycleBuffCt(accCt)
	accCt.Value[0].Zero()
	accCt.Value[1].Zero()

	keys := utils.GetSortedKeys(matrix.Vec)

	QiOverF := params.QiOverflowMargin(levelQ)

	for i, k := range keys {

		k &= (slots - 1)

		pt := matrix.Vec[k]

		c0, c1 := ctIn.Value[0], ctIn.Value[1]

		// Rotation by zero: multiply the input directly instead of running an empty substep chain.
		if k != 0 {
			if err = eval.rotateBySubsteps(levelQ, levelP, ctIn, BuffDecompQP, NAFRotationSubsteps(k, slots), buffCt); err != nil {
				return fmt.Errorf("cannot MultiplyByDiagMatrix: %w", err)
			}
			c0, c1 = buffCt.Value[0], buffCt.Value[1]
		}

		if i == 0 {
			ringQ.MulCoeffsMontgomery(pt.Q, c0, accCt.Value[0])
			ringQ.MulCoeffsMontgomery(pt.Q, c1, accCt.Value[1])
		} else {
			ringQ.MulCoeffsMontgomeryThenAdd(pt.Q, c0, accCt.Value[0])
			ringQ.MulCoeffsMontgomeryThenAdd(pt.Q, c1, accCt.Value[1])
		}

		if i%QiOverF == QiOverF-1 {
			ringQ.Reduce(accCt.Value[0], accCt.Value[0])
			ringQ.Reduce(accCt.Value[1], accCt.Value[1])
		}
	}

	ringQ.Reduce(accCt.Value[0], accCt.Value[0])
	ringQ.Reduce(accCt.Value[1], accCt.Value[1])

	opOut.Value[0].CopyLvl(levelQ, accCt.Value[0])
	opOut.Value[1].CopyLvl(levelQ, accCt.Value[1])

	return
}

// MultiplyByDiagMatrixBSGS multiplies the Ciphertext "ctIn" by the plaintext matrix "matrix" and returns the result on the Ciphertext "opOut".
// ctInPreRotated can be obtained with [PreRotatedCiphertextForDiagonalMatrixMultiplication].
// The BSGS approach is used (double hoisting with baby-step giant-step), which is faster than MultiplyByDiagMatrix
// for matrix with more than a few non-zero diagonals and uses significantly less keys.
func (eval Evaluator) MultiplyByDiagMatrixBSGS(ctIn *rlwe.Ciphertext, matrix LinearTransformation, ctInPreRot map[int]*rlwe.Element[ringqp.Poly], opOut *rlwe.Ciphertext) (err error) {

	params := eval.GetRLWEParameters()

	*opOut.MetaData = *ctIn.MetaData
	opOut.Scale = opOut.Scale.Mul(matrix.Scale)

	levelQ := utils.Min(opOut.Level(), utils.Min(ctIn.Level(), matrix.LevelQ))
	levelP := matrix.LevelP

	ringQP := params.RingQP().AtLevel(levelQ, levelP)
	poolQP := eval.pool.AtLevel(levelQ, levelP)
	ringQ := ringQP.RingQ
	ringP := ringQP.RingP

	buffQP1 := poolQP.GetBuffPolyQP()
	defer poolQP.RecycleBuffPolyQP(buffQP1)
	buffQP2 := poolQP.GetBuffPolyQP()
	defer poolQP.RecycleBuffPolyQP(buffQP2)
	buffQP3 := poolQP.GetBuffPolyQP()
	defer poolQP.RecycleBuffPolyQP(buffQP3)
	buffQP4 := poolQP.GetBuffPolyQP()
	defer poolQP.RecycleBuffPolyQP(buffQP4)
	buffP1 := poolQP.PoolP.GetBuffPoly()
	defer poolQP.PoolP.RecycleBuffPoly(buffP1)
	buffP2 := poolQP.PoolP.GetBuffPoly()
	defer poolQP.PoolP.RecycleBuffPoly(buffP2)
	buffCt := eval.pool.GetBuffCt(1, ringQ.Level())
	defer eval.pool.RecycleBuffCt(buffCt)

	opOut.Resize(opOut.Degree(), levelQ)

	QiOverF := params.QiOverflowMargin(levelQ) >> 1
	PiOverF := params.PiOverflowMargin(levelP) >> 1

	// Computes the N2 rotations indexes of the non-zero rows of the diagonalized DFT matrix for the baby-step giant-step algorithm
	index, _, _ := matrix.BSGSIndex()

	slots := 1 << matrix.LogDimensions.Cols // @company CipherFlow

	buffCt.Value[0].CopyLvl(levelQ, ctIn.Value[0])
	buffCt.Value[1].CopyLvl(levelQ, ctIn.Value[1])

	ctInTmp0, ctInTmp1 := buffCt.Value[0], buffCt.Value[1]

	// Accumulator inner loop
	tmp0QP := (*buffQP1)
	tmp1QP := (*buffQP2)

	// Accumulator outer loop
	cQP := &rlwe.Element[ringqp.Poly]{}
	cQP.Value = []ringqp.Poly{*buffQP3, *buffQP4}
	cQP.MetaData = &rlwe.MetaData{}
	cQP.IsNTT = true

	// Result in QP
	c0OutQP := ringqp.Poly{Q: opOut.Value[0], P: *buffP1}
	c1OutQP := ringqp.Poly{Q: opOut.Value[1], P: *buffP2}

	ringQ.MulScalarBigint(ctInTmp0, ringP.ModulusAtLevel[levelP], ctInTmp0) // P*c0
	ringQ.MulScalarBigint(ctInTmp1, ringP.ModulusAtLevel[levelP], ctInTmp1) // P*c1

	keys := utils.GetSortedKeys(index)

	// OUTER LOOP
	var cnt0 int
	for _, j := range keys {

		// INNER LOOP
		var cnt1 int
		for _, i := range index[j] {

			pt := matrix.Vec[j+i]
			ct := ctInPreRot[i]

			if i == 0 {
				if cnt1 == 0 {
					ringQ.MulCoeffsMontgomeryLazy(pt.Q, ctInTmp0, tmp0QP.Q)
					ringQ.MulCoeffsMontgomeryLazy(pt.Q, ctInTmp1, tmp1QP.Q)
					tmp0QP.P.Zero()
					tmp1QP.P.Zero()
				} else {
					ringQ.MulCoeffsMontgomeryLazyThenAddLazy(pt.Q, ctInTmp0, tmp0QP.Q)
					ringQ.MulCoeffsMontgomeryLazyThenAddLazy(pt.Q, ctInTmp1, tmp1QP.Q)
				}
			} else {
				if cnt1 == 0 {
					ringQP.MulCoeffsMontgomeryLazy(pt, ct.Value[0], tmp0QP)
					ringQP.MulCoeffsMontgomeryLazy(pt, ct.Value[1], tmp1QP)
				} else {
					ringQP.MulCoeffsMontgomeryLazyThenAddLazy(pt, ct.Value[0], tmp0QP)
					ringQP.MulCoeffsMontgomeryLazyThenAddLazy(pt, ct.Value[1], tmp1QP)
				}
			}

			if cnt1%QiOverF == QiOverF-1 {
				ringQ.Reduce(tmp0QP.Q, tmp0QP.Q)
				ringQ.Reduce(tmp1QP.Q, tmp1QP.Q)
			}

			if cnt1%PiOverF == PiOverF-1 {
				ringP.Reduce(tmp0QP.P, tmp0QP.P)
				ringP.Reduce(tmp1QP.P, tmp1QP.P)
			}

			cnt1++
		}

		if cnt1%QiOverF != 0 {
			ringQ.Reduce(tmp0QP.Q, tmp0QP.Q)
			ringQ.Reduce(tmp1QP.Q, tmp1QP.Q)
		}

		if cnt1%PiOverF != 0 {
			ringP.Reduce(tmp0QP.P, tmp0QP.P)
			ringP.Reduce(tmp1QP.P, tmp1QP.P)
		}

		// If j != 0, then rotates ((tmp0QP.Q, tmp0QP.P), (tmp1QP.Q, tmp1QP.P)) by N1*j and adds the result on ((cQP.Value[0].Q, cQP.Value[0].P), (cQP.Value[1].Q, cQP.Value[1].P))
		if j != 0 {

			if matrix.UseDefaultRotationKeys { // @company CipherFlow

				// Normalizes the giant-step accumulator modulo Q.
				eval.ModDownQPtoQNTT(levelQ, levelP, tmp1QP.Q, tmp1QP.P, tmp1QP.Q)
				eval.ModDownQPtoQNTT(levelQ, levelP, tmp0QP.Q, tmp0QP.P, tmp0QP.Q)

				ctTmp := &rlwe.Ciphertext{Element: rlwe.Element[ring.Poly]{
					MetaData: &rlwe.MetaData{CiphertextMetaData: rlwe.CiphertextMetaData{IsNTT: true}},
					Value:    []ring.Poly{tmp0QP.Q, tmp1QP.Q},
				}}

				if err = eval.rotateBySubstepsQP(levelQ, levelP, ctTmp, nil, NAFRotationSubsteps(j, slots), cQP); err != nil {
					return fmt.Errorf("eval.rotateBySubstepsQP: %w", err)
				}

				if cnt0 == 0 {
					c0OutQP.CopyLvl(levelQ, levelP, cQP.Value[0])
					c1OutQP.CopyLvl(levelQ, levelP, cQP.Value[1])
				} else {
					ringQP.AddLazy(c0OutQP, cQP.Value[0], c0OutQP)
					ringQP.AddLazy(c1OutQP, cQP.Value[1], c1OutQP)
				}

			} else {

				// Hoisting of the ModDown of sum(sum(phi(d1) * plaintext))
				eval.ModDownQPtoQNTT(levelQ, levelP, tmp1QP.Q, tmp1QP.P, tmp1QP.Q) // c1 * plaintext + sum(phi(d1) * plaintext) + phi(c1) * plaintext mod Q

				galEl := params.GaloisElement(j)

				var evk *rlwe.GaloisKey
				var err error
				if evk, err = eval.CheckAndGetGaloisKey(galEl); err != nil {
					return fmt.Errorf("eval.CheckAndGetGaloisKey(%d): CheckAndGetGaloisKey: %w", galEl, err)
				}

				if evk.LevelP() != levelP {
					return fmt.Errorf("LinearTransformation.LevelP = %d != GaloiKey[%d].LevelP() = %d: ensure that the levelP of the linear transformation is the same as the levelP of the GaloisKeys", levelP, galEl, evk.LevelP())
				}

				rotIndex := eval.AutomorphismIndex(galEl)

				// EvaluationKey(P*phi(tmpRes_1)) = (d0, d1) in base QP
				if err = eval.GadgetProductLazy(levelQ, tmp1QP.Q, &evk.GadgetCiphertext, cQP); err != nil {
					return fmt.Errorf("eval.GadgetProductLazy: %w", err)
				}

				ringQP.Add(cQP.Value[0], tmp0QP, cQP.Value[0])

				// Outer loop rotations
				if cnt0 == 0 {
					ringQP.AutomorphismNTTWithIndex(cQP.Value[0], rotIndex, c0OutQP)
					ringQP.AutomorphismNTTWithIndex(cQP.Value[1], rotIndex, c1OutQP)
				} else {
					ringQP.AutomorphismNTTWithIndexThenAddLazy(cQP.Value[0], rotIndex, c0OutQP)
					ringQP.AutomorphismNTTWithIndexThenAddLazy(cQP.Value[1], rotIndex, c1OutQP)
				}

			}

			// Else directly adds on ((cQP.Value[0].Q, cQP.Value[0].P), (cQP.Value[1].Q, cQP.Value[1].P))
		} else {
			if cnt0 == 0 {
				c0OutQP.CopyLvl(levelQ, levelP, tmp0QP)
				c1OutQP.CopyLvl(levelQ, levelP, tmp1QP)
			} else {
				ringQP.AddLazy(c0OutQP, tmp0QP, c0OutQP)
				ringQP.AddLazy(c1OutQP, tmp1QP, c1OutQP)
			}
		}

		if cnt0%QiOverF == QiOverF-1 {
			ringQ.Reduce(opOut.Value[0], opOut.Value[0])
			ringQ.Reduce(opOut.Value[1], opOut.Value[1])
		}

		if cnt0%PiOverF == PiOverF-1 {
			ringP.Reduce(c0OutQP.P, c0OutQP.P)
			ringP.Reduce(c1OutQP.P, c1OutQP.P)
		}

		cnt0++
	}

	if cnt0%QiOverF != 0 {
		ringQ.Reduce(opOut.Value[0], opOut.Value[0])
		ringQ.Reduce(opOut.Value[1], opOut.Value[1])
	}

	if cnt0%PiOverF != 0 {
		ringP.Reduce(c0OutQP.P, c0OutQP.P)
		ringP.Reduce(c1OutQP.P, c1OutQP.P)
	}

	eval.ModDownQPtoQNTT(levelQ, levelP, opOut.Value[0], c0OutQP.P, opOut.Value[0]) // sum(phi(c0 * P + d0_QP))/P
	eval.ModDownQPtoQNTT(levelQ, levelP, opOut.Value[1], c1OutQP.P, opOut.Value[1]) // sum(phi(d1_QP))/P

	return
}
