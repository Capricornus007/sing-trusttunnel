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
	require.True(t, strings.HasPrefix(link, "tt://?"))

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
		Name:               "My VPN Server",
		DNSUpstreams: []string{
			"1.1.1.1",
			"tls://dns.example.com",
			"https://dns.example.com/dns-query",
		},
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
	require.Equal(t, original.Name, parsed.Name)
	require.Equal(t, original.DNSUpstreams, parsed.DNSUpstreams)
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

	link := Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
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

	link := Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
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

	link := Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
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

func TestRoundTrip_Name(t *testing.T) {
	original := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "user",
		Password:  "pass",
		Name:      "My VPN Server",
	}

	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, original.Name, parsed.Name)
}

func TestRoundTrip_DNSUpstreams(t *testing.T) {
	original := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "user",
		Password:  "pass",
		DNSUpstreams: []string{
			"1.1.1.1",
			"tls://dns.example.com",
			"https://dns.example.com/dns-query",
		},
	}

	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, original.DNSUpstreams, parsed.DNSUpstreams)
}

func TestBuild_DNSUpstreamsEncodedAsSingleStringArrayTLV(t *testing.T) {
	url := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "user",
		Password:  "pass",
		DNSUpstreams: []string{
			"1.1.1.1",
			"8.8.8.8",
		},
	}

	link, err := url.Build()
	require.NoError(t, err)

	payload := decodeTLVPayload(t, link)
	dnsValues := decodeTLVValues(t, payload, TagDNSUpstreams)
	require.Len(t, dnsValues, 1)

	reader := bytes.NewReader(dnsValues[0])
	firstLength, err := readVarint(reader)
	require.NoError(t, err)
	require.EqualValues(t, len("1.1.1.1"), firstLength)

	first := make([]byte, int(firstLength))
	_, err = io.ReadFull(reader, first)
	require.NoError(t, err)
	require.Equal(t, "1.1.1.1", string(first))

	secondLength, err := readVarint(reader)
	require.NoError(t, err)
	require.EqualValues(t, len("8.8.8.8"), secondLength)

	second := make([]byte, int(secondLength))
	_, err = io.ReadFull(reader, second)
	require.NoError(t, err)
	require.Equal(t, "8.8.8.8", string(second))
	require.Zero(t, reader.Len())
}

func TestParse_DNSUpstreamsFromSingleStringArrayTLV(t *testing.T) {
	builder := bytes.NewBuffer(nil)
	common.Must(writeTLV(builder, TagVersion, Version))
	common.Must(writeTLV(builder, TagHostname, "vpn.example.com"))
	common.Must(writeTLV(builder, TagAddresses, "1.2.3.4:443"))
	common.Must(writeTLV(builder, TagUsername, "user"))
	common.Must(writeTLV(builder, TagPassword, "pass"))

	dnsUpstreamsBuffer := bytes.NewBuffer(nil)
	common.Must(writeVarint(dnsUpstreamsBuffer, uint64(len("1.1.1.1"))))
	_, err := io.WriteString(dnsUpstreamsBuffer, "1.1.1.1")
	require.NoError(t, err)
	common.Must(writeVarint(dnsUpstreamsBuffer, uint64(len("tls://dns.example.com"))))
	_, err = io.WriteString(dnsUpstreamsBuffer, "tls://dns.example.com")
	require.NoError(t, err)
	common.Must(writeTLV(builder, TagDNSUpstreams, dnsUpstreamsBuffer.Bytes()))

	link := Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, []string{"1.1.1.1", "tls://dns.example.com"}, parsed.DNSUpstreams)
}

func TestRoundTrip_WithoutNewOptionalFields(t *testing.T) {
	original := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "user",
		Password:  "pass",
	}

	link, err := original.Build()
	require.NoError(t, err)

	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Empty(t, parsed.Name)
	require.Empty(t, parsed.DNSUpstreams)
}

func TestParse_UnsupportedVersionRejected(t *testing.T) {
	builder := bytes.NewBuffer(nil)
	common.Must(writeVarint(builder, TagVersion))
	common.Must(writeVarint(builder, 1))
	_, err := builder.Write([]byte{99})
	require.NoError(t, err)
	common.Must(writeTLV(builder, TagHostname, "vpn"))

	link := Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes())
	_, err = Parse(link)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected version: 99")
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

func TestParse_LegacyFormatWithoutQuestionMark(t *testing.T) {
	// Old format tt://Base64 should still be parsed successfully
	original := URL{
		Hostname:  "vpn.example.com",
		Addresses: []M.Socksaddr{{Addr: netip.MustParseAddr("1.2.3.4"), Port: 443}},
		Username:  "alice",
		Password:  "secret",
	}

	link, err := original.Build()
	require.NoError(t, err)

	// Build now produces new format with ?
	require.True(t, strings.HasPrefix(link, Schema+"://?"))

	// New format with ? should parse
	parsed, err := Parse(link)
	require.NoError(t, err)
	require.Equal(t, "vpn.example.com", parsed.Hostname)
	require.Equal(t, "alice", parsed.Username)

	// Legacy format without ? should also parse
	legacyLink := strings.Replace(link, Schema+"://?", Schema+"://", 1)
	parsed2, err := Parse(legacyLink)
	require.NoError(t, err)
	require.Equal(t, "vpn.example.com", parsed2.Hostname)
	require.Equal(t, "alice", parsed2.Username)
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
	reader := bytes.NewReader(decodeTLVPayload(t, link))
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

func decodeTLVPayload(t *testing.T, link string) []byte {
	t.Helper()
	encoded, found := strings.CutPrefix(link, Schema+"://")
	require.True(t, found)
	encoded = strings.TrimPrefix(encoded, "?")

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	return payload
}

func decodeTLVValues(t *testing.T, payload []byte, targetTag uint64) [][]byte {
	t.Helper()
	reader := bytes.NewReader(payload)
	var values [][]byte
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

		value := make([]byte, int(length))
		_, err = io.ReadFull(reader, value)
		require.NoError(t, err)

		if tag == targetTag {
			values = append(values, value)
		}
	}
	return values
}
