package central

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_containsControlChar(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"no control char", "abcDEF123", false},
		{"has null", "abc\x00def", true},
		{"has bell", "abc\x07def", true},
		{"has escape", "abc\x1bdef", true},
		{"has DEL", "abc\x7Fdef", true},
		{"all control", "\x00\x01\x02", true},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsControlChar(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}
