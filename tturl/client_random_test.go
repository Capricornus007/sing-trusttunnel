package tturl

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseClientRandomPrefix(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name   string
		raw    string
		prefix []byte
		mask   []byte
	}{
		{name: "prefix", raw: "aabbcc", prefix: []byte{0xaa, 0xbb, 0xcc}},
		{name: "uppercase", raw: "AABBCC", prefix: []byte{0xaa, 0xbb, 0xcc}},
		{name: "mask", raw: "a0b0/f0f0", prefix: []byte{0xa0, 0xb0}, mask: []byte{0xf0, 0xf0}},
		{name: "mask longer example", raw: "aabbcc/ff00ff", prefix: []byte{0xaa, 0xbb, 0xcc}, mask: []byte{0xff, 0x00, 0xff}},
		{name: "decode fixture", raw: "5841/7a43", prefix: []byte{0x58, 0x41}, mask: []byte{0x7a, 0x43}},
		{name: "partial byte mask", raw: "12345678/ffff0000", prefix: []byte{0x12, 0x34, 0x56, 0x78}, mask: []byte{0xff, 0xff, 0x00, 0x00}},
		{name: "unequal lengths", raw: "aabb/ff", prefix: []byte{0xaa, 0xbb}, mask: []byte{0xff}},
		{name: "empty", raw: ""},
		{name: "empty prefix with mask", raw: "/f0f0", mask: []byte{0xf0, 0xf0}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			parsed, err := ParseClientRandomPrefix(testCase.raw)
			require.NoError(t, err)
			require.Equal(t, testCase.prefix, parsed.Prefix)
			require.Equal(t, testCase.mask, parsed.Mask)
			require.Equal(t, testCase.prefix == nil && testCase.mask == nil, parsed.IsEmpty())
			require.Equal(t, strings.ToLower(testCase.raw), parsed.String())
		})
	}
}

func TestParseClientRandomPrefix_Lengths(t *testing.T) {
	t.Parallel()
	for length := 1; length <= maxRandomPrefixLen; length++ {
		prefix := bytes.Repeat([]byte{0xab}, length)
		mask := bytes.Repeat([]byte{0x0f}, length)
		raw := hex.EncodeToString(prefix) + "/" + hex.EncodeToString(mask)
		parsed, err := ParseClientRandomPrefix(raw)
		require.NoError(t, err)
		require.Equal(t, prefix, parsed.Prefix)
		require.Equal(t, mask, parsed.Mask)
		require.Equal(t, raw, parsed.String())
	}
}

func TestParseClientRandomPrefix_Invalid(t *testing.T) {
	t.Parallel()
	tooLong := strings.Repeat("aa", maxRandomPrefixLen+1)
	testCases := []struct {
		name    string
		raw     string
		message string
	}{
		{name: "not hex", raw: "notvalidhex", message: "parse client random prefix"},
		{name: "odd length", raw: "abc", message: "parse client random prefix"},
		{name: "not hex short", raw: "nothex", message: "parse client random prefix"},
		{name: "empty mask", raw: "aabbcc/", message: "mask can't be empty"},
		{name: "invalid mask", raw: "aabbcc/zz", message: "parse client random prefix mask"},
		{name: "extra slash", raw: "aabbcc/ff00ff/00", message: "parse client random prefix mask"},
		{name: "prefix too long", raw: tooLong, message: "invalid length"},
		{name: "mask too long", raw: "aa/" + tooLong, message: "invalid length"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseClientRandomPrefix(testCase.raw)
			require.Error(t, err)
			assert.Contains(t, err.Error(), testCase.message)
		})
	}
}

func TestRoundTrip_ClientRandomPrefix(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name   string
		prefix ClientRandomPrefix
		raw    string
	}{
		{
			name:   "prefix",
			prefix: ClientRandomPrefix{Prefix: []byte{0xaa, 0xbb, 0xcc}},
			raw:    "aabbcc",
		},
		{
			name: "mask",
			prefix: ClientRandomPrefix{
				Prefix: []byte{0xa0, 0xb0},
				Mask:   []byte{0xf0, 0xf0},
			},
			raw: "a0b0/f0f0",
		},
		{
			name: "subscription example",
			prefix: ClientRandomPrefix{
				Prefix: []byte{0xaa, 0xbb, 0xcc},
				Mask:   []byte{0xff, 0x00, 0xff},
			},
			raw: "aabbcc/ff00ff",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			original := clientRandomURL(testCase.prefix)
			link, err := original.Build()
			require.NoError(t, err)

			require.Equal(t, [][]byte{[]byte(testCase.raw)}, decodeTLVValues(t, decodeTLVPayload(t, link), TagClientRandomPrefix))

			parsed, err := Parse(link)
			require.NoError(t, err)
			require.Equal(t, original.ClientRandomPrefix, parsed.ClientRandomPrefix)
			require.Equal(t, testCase.raw, parsed.ClientRandomPrefix.String())
		})
	}
}

func TestRoundTrip_ClientRandomPrefixOmittedWhenEmpty(t *testing.T) {
	t.Parallel()
	link, err := clientRandomURL(ClientRandomPrefix{}).Build()
	require.NoError(t, err)
	assert.NotContains(t, decodeTLVTags(t, link), TagClientRandomPrefix)

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Empty(t, parsed.ClientRandomPrefix)
}

func TestParse_ClientRandomPrefixInvalid(t *testing.T) {
	t.Parallel()
	testCases := []string{"notvalidhex", "nothex", "aabbcc/", "aabbcc/zz"}
	for _, raw := range testCases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(clientRandomLink(t, raw))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "client random prefix")
		})
	}
}

func TestParse_ClientRandomPrefixNormalizesCase(t *testing.T) {
	t.Parallel()
	parsed, err := Parse(clientRandomLink(t, "A0B0/F0F0"))
	require.NoError(t, err)
	require.Equal(t, []byte{0xa0, 0xb0}, parsed.ClientRandomPrefix.Prefix)
	require.Equal(t, []byte{0xf0, 0xf0}, parsed.ClientRandomPrefix.Mask)
	require.Equal(t, "a0b0/f0f0", parsed.ClientRandomPrefix.String())
}

func clientRandomURL(prefix ClientRandomPrefix) URL {
	return URL{
		Hostname:           "crp.example.com",
		Addresses:          []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:           "testuser",
		Password:           "testpass",
		ClientRandomPrefix: prefix,
	}
}

func clientRandomLink(t *testing.T, raw string) string {
	t.Helper()
	builder := bytes.NewBuffer(nil)
	common.Must(writeTLV(builder, TagVersion, Version1))
	common.Must(writeTLV(builder, TagHostname, "crp.example.com"))
	common.Must(writeTLV(builder, TagAddresses, "1.2.3.4:443"))
	common.Must(writeTLV(builder, TagUsername, "testuser"))
	common.Must(writeTLV(builder, TagPassword, "testpass"))
	common.Must(writeTLV(builder, TagClientRandomPrefix, raw))
	return Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
}
