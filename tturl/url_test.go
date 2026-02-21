package tturl

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundTrip_MinimalConfig(t *testing.T) {
	original := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "alice",
		Password:  "secret123",
	}

	link, err := original.Build()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(link, "tt://"))

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, original.Hostname, parsed.Hostname)
	assertAddressesEqual(t, parsed.Addresses, original.Addresses)
	require.Equal(t, original.Username, parsed.Username)
	require.Equal(t, original.Password, parsed.Password)
	require.EqualValues(t, UpstreamProtocolHTTP2, parsed.UpstreamProtocol)
	require.False(t, parsed.AntiDPI)
}

func TestRoundTrip_MaximalConfig(t *testing.T) {
	original := URL{
		Hostname: "secure.vpn.example.com",
		Addresses: []M.Socksaddr{
			{Addr: netip.MustParseAddr("192.168.1.1"), Port: 8443},
			{Addr: netip.MustParseAddr("10.0.0.0"), Port: 8443},
		},
		CustomSNI:          "cdn.example.org",
		Username:           "premium_user",
		Password:           "very_secret_password_123",
		ClientRandomPrefix: "aabbcc",
		SkipVerification:   true,
		Certificate:        []byte{0x30, 0x82, 0x01, 0x23},
		UpstreamProtocol:   UpstreamProtocolHTTP3,
		AntiDPI:            true,
	}

	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)

	require.Equal(t, original.Hostname, parsed.Hostname)
	assertAddressesEqual(t, parsed.Addresses, original.Addresses)
	require.Equal(t, original.CustomSNI, parsed.CustomSNI)
	require.Equal(t, original.Username, parsed.Username)
	require.Equal(t, original.Password, parsed.Password)
	require.Equal(t, original.ClientRandomPrefix, parsed.ClientRandomPrefix)
	require.Equal(t, original.SkipVerification, parsed.SkipVerification)
	require.Equal(t, original.Certificate, parsed.Certificate)
	require.Equal(t, original.UpstreamProtocol, parsed.UpstreamProtocol)
	require.Equal(t, original.AntiDPI, parsed.AntiDPI)
}

func TestRoundTrip_MultipleAddresses(t *testing.T) {
	original := URL{
		Hostname: "multi.vpn.com",
		Addresses: []M.Socksaddr{
			{Addr: netip.MustParseAddr("1.1.1.1"), Port: 443},
			{Addr: netip.MustParseAddr("8.8.8.8"), Port: 8443},
			{Addr: netip.MustParseAddr("9.9.9.9"), Port: 9443},
		},
		Username: "multiaddr",
		Password: "test123",
	}
	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)

	assertAddressesEqual(t, parsed.Addresses, original.Addresses)
}

func TestRoundTrip_LongValues(t *testing.T) {
	longPassword := strings.Repeat("a", 200)
	longHostname := strings.Repeat("sub", 50) + ".vpn.example.com"
	original := URL{
		Hostname:  longHostname,
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "user",
		Password:  longPassword,
	}

	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)

	require.Equal(t, longHostname, parsed.Hostname)
	require.Equal(t, longPassword, parsed.Password)
}

func TestRoundTrip_SpecialCharacters(t *testing.T) {
	original := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		CustomSNI: "cdn-123.example.org",
		Username:  "user@example.com",
		Password:  "p@ss!w0rd#123",
	}
	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)

	require.Equal(t, original.Username, parsed.Username)
	require.Equal(t, original.Password, parsed.Password)
	require.Equal(t, original.CustomSNI, parsed.CustomSNI)
}

func TestRoundTrip_IPv6Addresses(t *testing.T) {
	original := URL{
		Hostname: "vpn6.example.com",
		Addresses: []M.Socksaddr{
			{Addr: netip.MustParseAddr("2001:db8::1"), Port: 443},
			{Addr: netip.MustParseAddr("::1"), Port: 8443},
		},
		Username: "ipv6user",
		Password: "ipv6pass",
	}
	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)

	assertAddressesEqual(t, parsed.Addresses, original.Addresses)
}

func TestParse_DefaultUpstreamProtocolHTTP2(t *testing.T) {
	builder := bytes.NewBuffer(nil)
	common.Must(writeTLV(builder, TagVersion, Version))
	common.Must(writeTLV(builder, TagHostname, "example.com"))
	common.Must(writeTLV(builder, TagAddresses, "1.2.3.4:443"))
	common.Must(writeTLV(builder, TagUsername, "user"))
	common.Must(writeTLV(builder, TagPassword, "pass"))

	link := Schema + "://" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
	parsed, err := Parse(link)
	require.NoError(t, err)
	require.EqualValues(t, UpstreamProtocolHTTP2, parsed.UpstreamProtocol)
}

func TestParse_IgnoreUnknownTag(t *testing.T) {
	builder := bytes.NewBuffer(nil)
	common.Must(writeTLV(builder, TagVersion, Version))
	common.Must(writeTLV(builder, TagHostname, "example.com"))
	common.Must(writeTLV(builder, TagAddresses, "1.2.3.4:443"))
	common.Must(writeTLV(builder, TagUsername, "user"))
	common.Must(writeTLV(builder, TagPassword, "pass"))
	common.Must(writeTLV(builder, 0x0c, []byte{0x01, 0x02, 0x03}))

	link := Schema + "://" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, "user", parsed.Username)
}

func TestParse_InvalidScheme(t *testing.T) {
	_, err := Parse("http://example.com")
	require.Error(t, err)
}

func TestParse_RejectLengthExceedingRemainingBuffer(t *testing.T) {
	builder := bytes.NewBuffer(nil)
	common.Must(writeVarint(builder, TagHostname))
	common.Must(writeVarint(builder, 5))
	_, err := builder.WriteString("abc")
	require.NoError(t, err)

	link := Schema + "://" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
	_, err = Parse(link)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid length of tag")
}

func TestBuild_DefaultUpstreamProtocolTagOmitted(t *testing.T) {
	url := URL{
		Hostname:  "example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "user",
		Password:  "pass",
	}
	link, err := url.Build()
	require.NoError(t, err)
	tags := decodeTLVTags(t, link)
	assert.NotContains(t, tags, TagUpstreamProtocol)
}

func TestBuild_HTTP3UpstreamProtocolTagIncluded(t *testing.T) {
	url := URL{
		Hostname:         "example.com",
		Addresses:        []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:         "user",
		Password:         "pass",
		UpstreamProtocol: UpstreamProtocolHTTP3,
	}
	link, err := url.Build()
	require.NoError(t, err)
	tags := decodeTLVTags(t, link)
	assert.Contains(t, tags, TagUpstreamProtocol)
}

func TestBuild_WithCertificateRoundTrip(t *testing.T) {
	url := URL{
		Hostname:    "example.com",
		Addresses:   []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:    "user",
		Password:    "pass",
		Certificate: []byte{0x01, 0x02, 0x03, 0x04},
	}

	link, err := url.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.NotEmpty(t, parsed.Certificate)
	require.Equal(t, url.Certificate, parsed.Certificate)
	require.EqualValues(t, UpstreamProtocolHTTP2, parsed.UpstreamProtocol)
}

func assertAddressesEqual(t *testing.T, got []M.Socksaddr, want []M.Socksaddr) {
	t.Helper()
	require.Len(t, got, len(want))
	for i := range want {
		require.Equal(t, want[i].String(), got[i].String())
	}
}

func decodeTLVTags(t *testing.T, link string) []uint64 {
	t.Helper()
	encoded, found := strings.CutPrefix(link, Schema+"://")
	require.True(t, found)

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	reader := bytes.NewReader(payload)
	tags := make([]uint64, 0, 8)
	for {
		tag, err := readVarint(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
		}

		length, err := readVarint(reader)
		require.NoError(t, err)

		tags = append(tags, tag)
		_, err = reader.Seek(int64(length), io.SeekCurrent)
		require.NoError(t, err)
	}

	return tags
}
