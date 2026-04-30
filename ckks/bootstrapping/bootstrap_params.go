package bootstrapping

import (
	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/cipherflow-fhe/lattigo/ckks/advanced"
	"github.com/cipherflow-fhe/lattigo/utils"
)

// Parameters is a struct for the default bootstrapping parameters
type Parameters struct {
	SlotsToCoeffsParameters advanced.EncodingMatrixLiteral
	EvalModParameters       advanced.EvalModLiteral
	CoeffsToSlotsParameters advanced.EncodingMatrixLiteral
	EphemeralSecretWeight   int  // Hamming weight of the ephemeral secret. If 0, no ephemeral secret is used during the bootstrapping.
	LogSlots                *int // nil if logSlots is not set and original logSlots (logN-1 in ckks) is used.
}

// MarshalBinary encode the target Parameters on a slice of bytes.
func (p *Parameters) MarshalBinary() (data []byte, err error) {
	data = []byte{}

	var tmp []byte
	if tmp, err = p.SlotsToCoeffsParameters.MarshalBinary(); err != nil {
		return nil, err
	}

	data = append(data, uint8(len(tmp)))
	data = append(data, tmp...)

	if tmp, err = p.EvalModParameters.MarshalBinary(); err != nil {
		return nil, err
	}

	data = append(data, uint8(len(tmp)))
	data = append(data, tmp...)

	if tmp, err = p.CoeffsToSlotsParameters.MarshalBinary(); err != nil {
		return nil, err
	}

	data = append(data, uint8(len(tmp)))
	data = append(data, tmp...)

	tmp = make([]byte, 5)
	tmp[0] = uint8(p.EphemeralSecretWeight >> 24)
	tmp[1] = uint8(p.EphemeralSecretWeight >> 16)
	tmp[2] = uint8(p.EphemeralSecretWeight >> 8)
	tmp[3] = uint8(p.EphemeralSecretWeight >> 0)
	if p.LogSlots != nil {
		tmp[4] = uint8(*p.LogSlots + 1)
		// LogSlots >= 0, so LogSlots+1 fits in a uint8 and LogSlots+1 == 0 is not possible.
	} else {
		tmp[4] = 0
	}
	data = append(data, tmp...)
	return
}

// UnmarshalBinary decodes a slice of bytes on the target Parameters.
func (p *Parameters) UnmarshalBinary(data []byte) (err error) {

	pt := 0
	dLen := int(data[pt])

	if err := p.SlotsToCoeffsParameters.UnmarshalBinary(data[pt+1 : pt+dLen+1]); err != nil {
		return err
	}

	pt += dLen
	pt++
	dLen = int(data[pt])

	if err := p.EvalModParameters.UnmarshalBinary(data[pt+1 : pt+dLen+1]); err != nil {
		return err
	}

	pt += dLen
	pt++
	dLen = int(data[pt])

	if err := p.CoeffsToSlotsParameters.UnmarshalBinary(data[pt+1 : pt+dLen+1]); err != nil {
		return err
	}

	pt += dLen
	pt++

	p.EphemeralSecretWeight = int(data[pt])<<24 | int(data[pt+1])<<16 | int(data[pt+2])<<8 | int(data[pt+3])

	if len(data) > pt+4 { // logSlots is enabled
		logSlotsVal := int(data[pt+4])
		if logSlotsVal > 0 {
			logSlotsVal-- // logSlots is stored as logSlots+1 to fit in a uint8 and to distinguish between logSlots=0 and logSlots not set.
			p.LogSlots = &logSlotsVal
		}
	}
	return
}

// RotationsForBootstrapping returns the list of rotations performed during the Bootstrapping operation.
func (p *Parameters) RotationsForBootstrapping(params ckks.Parameters) (rotations []int) {

	logN := params.LogN()
	logSlots := params.LogSlots()

	if p.LogSlots != nil {
		logSlots = *p.LogSlots
	}

	// List of the rotation key values to needed for the bootstrapp
	rotations = []int{}

	//SubSum rotation needed X -> Y^slots rotations
	for i := logSlots; i < logN-1; i++ {
		if !utils.IsInSliceInt(1<<i, rotations) {
			rotations = append(rotations, 1<<i)
		}
	}

	p.CoeffsToSlotsParameters.LogN = logN
	p.SlotsToCoeffsParameters.LogN = logN

	p.CoeffsToSlotsParameters.LogSlots = logSlots
	p.SlotsToCoeffsParameters.LogSlots = logSlots

	rotations = append(rotations, p.CoeffsToSlotsParameters.Rotations()...)
	rotations = append(rotations, p.SlotsToCoeffsParameters.Rotations()...)

	return
}
