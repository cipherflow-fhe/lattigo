package bootstrapping

import (
	"testing"

	"github.com/cipherflow-fhe/lattigo/ckks"
	"github.com/stretchr/testify/require"
)

func TestPresetParameters(t *testing.T) {
	presets := []struct {
		name     string
		preset   int
		expected struct {
			logN      int
			hamming   int
			ephemeral int
		}
	}{
		{"Sparse0", 0, struct{ logN, hamming, ephemeral int }{16, 192, 32}},
		{"Sparse1", 1, struct{ logN, hamming, ephemeral int }{16, 192, 32}},
		{"Sparse2", 2, struct{ logN, hamming, ephemeral int }{16, 192, 32}},
		{"Sparse3", 3, struct{ logN, hamming, ephemeral int }{15, 192, 32}},
		{"Dense0", 4, struct{ logN, hamming, ephemeral int }{16, 32768, 32}},
		{"Dense1", 5, struct{ logN, hamming, ephemeral int }{16, 32768, 32}},
		{"Dense2", 6, struct{ logN, hamming, ephemeral int }{16, 32768, 32}},
		{"Dense3", 7, struct{ logN, hamming, ephemeral int }{15, 16384, 32}},
	}

	for _, tc := range presets {
		t.Run(tc.name, func(t *testing.T) {
			var literal defaultParametersLiteral
			switch tc.preset {
			case 0:
				literal = N16QP1546H192H32
			case 1:
				literal = N16QP1547H192H32
			case 2:
				literal = N16QP1553H192H32
			case 3:
				literal = N15QP768H192H32
			case 4:
				literal = N16QP1767H32768H32
			case 5:
				literal = N16QP1788H32768H32
			case 6:
				literal = N16QP1793H32768H32
			case 7:
				literal = N15QP880H16384H32
			}

			params, err := ckks.NewParametersFromLiteral(literal.SchemeParams)
			require.NoError(t, err)
			require.Equal(t, tc.expected.logN, params.LogN())
			require.Equal(t, tc.expected.hamming, params.HammingWeight())
			require.Equal(t, tc.expected.ephemeral, literal.BootstrappingParams.EphemeralSecretWeight)
		})
	}
}
