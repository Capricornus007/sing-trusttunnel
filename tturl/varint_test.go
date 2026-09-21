package tturl

import (
	"bytes"
	"io"
	"testing"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	F "github.com/sagernet/sing/common/format"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVarint_BoundaryValues(t *testing.T) {
	t.Parallel()
	tests := []uint64{
		0,
		maxVarInt1,
		maxVarInt1 + 1,
		maxVarInt2,
		maxVarInt2 + 1,
		maxVarInt4,
		maxVarInt4 + 1,
		maxVarInt8,
	}
	for _, tt := range tests {
		t.Run(F.ToString(tt), func(t *testing.T) {
			t.Parallel()
			var buffer bytes.Buffer
			err := writeVarint(&buffer, tt)
			require.NoError(t, err)
			got, err := readVarint(buf.As(buffer.Bytes()))
			require.NoError(t, err)
			assert.Equal(t, tt, got)
		})
	}
}

func TestReadVarint_Truncated(t *testing.T) {
	t.Parallel()
	_, err := readVarint(buf.As([]byte{0x40}))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

var benchmarkVarintValues = []uint64{
	5, maxVarInt1,
	maxVarInt1 + 1, maxVarInt2,
	maxVarInt2 + 1, maxVarInt4,
	maxVarInt4 + 1, maxVarInt8,
}

func BenchmarkReadVarint(b *testing.B) {
	var buffer bytes.Buffer
	for _, value := range benchmarkVarintValues {
		common.Must(writeVarint(&buffer, value))
	}
	data := buffer.Bytes()
	b.ReportAllocs()
	for b.Loop() {
		reader := buf.As(data)
		for !reader.IsEmpty() {
			_, err := readVarint(reader)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkWriteVarint(b *testing.B) {
	var buffer bytes.Buffer
	b.ReportAllocs()
	for b.Loop() {
		buffer.Reset()
		for _, value := range benchmarkVarintValues {
			err := writeVarint(&buffer, value)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}
