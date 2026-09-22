// QUIC varint implementation. I don't want to import github.com/quic-go/quic-go/quicvarint

package tturl

import (
	"bytes"
	"io"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

func varintSizeCode(value uint64) (byte, error) {
	switch {
	case value <= maxVarInt1:
		return 0, nil
	case value <= maxVarInt2:
		return 1, nil
	case value <= maxVarInt4:
		return 2, nil
	case value <= maxVarInt8:
		return 3, nil
	default:
		return 0, E.New("varint too large: ", value)
	}
}

func varintLength(value uint64) (int, error) {
	sizeCode, err := varintSizeCode(value)
	if err != nil {
		return 0, err
	}
	return 1 << sizeCode, nil
}

func writeVarint(buffer *bytes.Buffer, value uint64) error {
	sizeCode, err := varintSizeCode(value)
	if err != nil {
		return err
	}
	byteLength := 1 << sizeCode
	value |= uint64(sizeCode) << (byteLength*8 - 2)
	buffer.Grow(byteLength)
	for shift := (byteLength - 1) * 8; shift >= 0; shift -= 8 {
		buffer.WriteByte(byte(value >> shift))
	}
	return nil
}

func readVarint(buffer *buf.Buffer) (uint64, error) {
	first, err := buffer.ReadByte()
	if err != nil {
		return 0, err
	}
	byteLength := 1 << (first >> 6)
	value := uint64(first & 0x3f)
	for range byteLength - 1 {
		next, err := buffer.ReadByte()
		if err != nil {
			// Truncated varint must not be mistaken for the end of input.
			return 0, io.ErrUnexpectedEOF
		}
		value = value<<8 | uint64(next)
	}
	return value, nil
}
