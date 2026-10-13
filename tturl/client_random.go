package tturl

import (
	"encoding/hex"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

type ClientRandomPrefix struct {
	Prefix []byte
	Mask   []byte
}

func ParseClientRandomPrefix(raw string) (ClientRandomPrefix, error) {
	prefixHex, maskHex, hasMask := strings.Cut(raw, "/")
	prefix, err := decodeRandomPrefixHex(prefixHex)
	if err != nil {
		return ClientRandomPrefix{}, E.Cause(err, "parse client random prefix")
	}
	if !hasMask {
		return ClientRandomPrefix{Prefix: prefix}, nil
	}
	if maskHex == "" {
		return ClientRandomPrefix{}, E.New("client random prefix mask can't be empty")
	}
	mask, err := decodeRandomPrefixHex(maskHex)
	if err != nil {
		return ClientRandomPrefix{}, E.Cause(err, "parse client random prefix mask")
	}
	return ClientRandomPrefix{Prefix: prefix, Mask: mask}, nil
}

func (c ClientRandomPrefix) IsEmpty() bool {
	return len(c.Prefix) == 0 && len(c.Mask) == 0
}

func (c ClientRandomPrefix) String() string {
	builder := hex.EncodeToString(c.Prefix)
	if len(c.Mask) != 0 {
		builder += "/" + hex.EncodeToString(c.Mask)
	}
	return builder
}

// TLS client random length
const maxRandomPrefixLen = 32

func decodeRandomPrefixHex(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	value, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(value) > maxRandomPrefixLen {
		return nil, E.New("invalid length")
	}
	return value, nil
}
