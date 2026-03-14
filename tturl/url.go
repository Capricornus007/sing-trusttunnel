package tturl

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strings"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/rw"
)

const (
	Schema       = "tt"
	Version byte = 0x00
)

const (
	TagVersion            uint64 = 0x00
	TagHostname           uint64 = 0x01
	TagAddresses          uint64 = 0x02
	TagCustomSNI          uint64 = 0x03
	TagHasIPv6            uint64 = 0x04 // Always true in original implementation
	TagUsername           uint64 = 0x05
	TagPassword           uint64 = 0x06
	TagClientRandomPrefix uint64 = 0x0B // Naive and ridiculous design.
	TagSkipVerification   uint64 = 0x07
	TagCertificate        uint64 = 0x08
	TagUpstreamProtocol   uint64 = 0x09
	TagAntiDPI            uint64 = 0x0A
)

type UpstreamProtocol byte

const (
	UpstreamProtocolHTTP2 = 0x01
	UpstreamProtocolHTTP3 = 0x02
)

func (u UpstreamProtocol) IsValid() bool {
	switch u {
	case UpstreamProtocolHTTP2, UpstreamProtocolHTTP3:
		return true
	default:
		return false
	}
}

type URL struct {
	Hostname           string
	Addresses          []M.Socksaddr
	CustomSNI          string
	Username           string
	Password           string
	ClientRandomPrefix string
	SkipVerification   bool
	Certificate        []byte // der
	UpstreamProtocol   UpstreamProtocol
	AntiDPI            bool
}

func Parse(link string) (*URL, error) {
	base64String, found := strings.CutPrefix(link, Schema+"://")
	if !found {
		return nil, E.New("schema is not ", Schema)
	}
	// since draft 2
	// https://github.com/TrustTunnel/TrustTunnel/blob/984817f3b92f5769aedb15e3f90782bc88839825/DEEP_LINK.md?plain=1#L8
	base64String = strings.TrimPrefix(base64String, "?")
	buffer := buf.NewSize(base64.RawURLEncoding.DecodedLen(len(base64String)))
	defer buffer.Release()
	n, err := base64.RawURLEncoding.Decode(buffer.FreeBytes(), []byte(base64String))
	if err != nil {
		return nil, err
	}
	buffer.Truncate(n)

	url := new(URL)
	err = parseTLV(buffer, url)
	if err != nil {
		return nil, err
	}
	url.applyDefaults()
	err = url.requireValid()
	if err != nil {
		return nil, err
	}
	return url, nil
}

func parseTLV(buffer *buf.Buffer, url *URL) error {
	for {
		tag, err := readVarint(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		err = parseTag(buffer, url, tag)
		if err != nil {
			return err
		}
	}
	return nil
}

func parseTag(buffer *buf.Buffer, url *URL, tag uint64) error {
	switch tag {
	case TagVersion:
		version, err := readTLVByte(buffer, tag)
		if err != nil {
			return err
		}
		if version != Version {
			return E.New("unexpected version: ", version)
		}
	case TagHostname:
		value, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		url.Hostname = value
	case TagAddresses:
		value, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		address := M.ParseSocksaddr(value)
		if !address.IsValid() || address.Port == 0 {
			return E.New("invalid address: ", value)
		}
		url.Addresses = append(url.Addresses, address)
	case TagCustomSNI:
		value, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		url.CustomSNI = value
	case TagUsername:
		value, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		url.Username = value
	case TagPassword:
		value, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		url.Password = value
	case TagClientRandomPrefix:
		value, err := readTLVString(buffer, tag)
		if err != nil {
			return err
		}
		url.ClientRandomPrefix = value
	case TagSkipVerification:
		value, err := readTLVBool(buffer, tag)
		if err != nil {
			return err
		}
		url.SkipVerification = value
	case TagCertificate:
		value, err := readTLVBytes(buffer, tag)
		if err != nil {
			return err
		}
		url.Certificate = value
	case TagUpstreamProtocol:
		value, err := readTLVByte(buffer, tag)
		if err != nil {
			return err
		}
		upstreamProtocol := UpstreamProtocol(value)
		if !upstreamProtocol.IsValid() {
			return E.New("invalid upstream protocol: ", upstreamProtocol)
		}
		url.UpstreamProtocol = upstreamProtocol
	case TagAntiDPI:
		value, err := readTLVBool(buffer, tag)
		if err != nil {
			return err
		}
		url.AntiDPI = value
	case TagHasIPv6:
		fallthrough
	default:
		return skipTLV(buffer, tag)
	}
	return nil
}

func readTLVString(buffer *buf.Buffer, tag uint64) (string, error) {
	value, err := readTLVBytes(buffer, tag)
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func readTLVBool(buffer *buf.Buffer, tag uint64) (bool, error) {
	value, err := readTLVByte(buffer, tag)
	if err != nil {
		return false, err
	}
	return value != 0, nil
}

func readTLVByte(buffer *buf.Buffer, tag uint64) (byte, error) {
	value, err := readTLVFixedBytes(buffer, tag, 1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

func readTLVFixedBytes(buffer *buf.Buffer, tag uint64, expectLength uint64) ([]byte, error) {
	length, err := readTLVLength(buffer, tag)
	if err != nil {
		return nil, err
	}
	if length != expectLength {
		if tag == TagVersion {
			return nil, E.New("invalid version length: ", length)
		}
		return nil, E.New("invalid length of tag ", tag, ": ", length)
	}
	readBuffer := make([]byte, int(length))
	_, err = io.ReadFull(buffer, readBuffer)
	if err != nil {
		return nil, err
	}
	return readBuffer, nil
}

func readTLVBytes(buffer *buf.Buffer, tag uint64) ([]byte, error) {
	length, err := readTLVLength(buffer, tag)
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	readBuffer := make([]byte, int(length))
	_, err = io.ReadFull(buffer, readBuffer)
	if err != nil {
		return nil, err
	}
	return readBuffer, nil
}

func readTLVLength(buffer *buf.Buffer, tag uint64) (uint64, error) {
	length, err := readVarint(buffer)
	if err != nil {
		return 0, err
	}
	remaining := buffer.Len()
	if length > uint64(buffer.Len()) {
		return 0, E.New("invalid length of tag ", tag, ": ", length, ", remaining: ", remaining)
	}
	return length, nil
}

func skipTLV(buffer *buf.Buffer, tag uint64) error {
	length, err := readTLVLength(buffer, tag)
	if err != nil {
		return err
	}
	return rw.SkipN(buffer, int(length))
}

func (u *URL) applyDefaults() {
	if u.UpstreamProtocol == 0 {
		u.UpstreamProtocol = UpstreamProtocolHTTP2
	}
}

func (u URL) requireValid() error {
	if u.Hostname == "" {
		return E.New("missing hostname")
	}
	if len(u.Addresses) == 0 {
		return E.New("missing addresses")
	}
	if invalidIndex := common.Index(u.Addresses, func(it M.Socksaddr) bool {
		return !it.IsValid() || it.Port == 0
	}); invalidIndex >= 0 {
		return E.New("address [", invalidIndex, "] is invalid")
	}
	if u.Username == "" {
		return E.New("missing username")
	}
	if u.Password == "" {
		return E.New("missing password")
	}
	if !u.UpstreamProtocol.IsValid() {
		return E.New("invalid upstream protocol ", u.UpstreamProtocol)
	}
	return nil
}

func (u URL) Build() (string, error) {
	u.applyDefaults()
	err := u.requireValid()
	if err != nil {
		return "", err
	}
	builder := bytes.NewBuffer(nil)
	err = writeTLV(builder, TagVersion, Version)
	if err != nil {
		return "", E.Cause(err, "write version")
	}
	err = writeTLV(builder, TagHostname, u.Hostname)
	if err != nil {
		return "", E.Cause(err, "write hostname")
	}
	for i, address := range u.Addresses {
		err = writeTLV(builder, TagAddresses, address.String())
		if err != nil {
			return "", E.Cause(err, "write address ", i)
		}
	}
	if u.CustomSNI != "" {
		err = writeTLV(builder, TagCustomSNI, u.CustomSNI)
		if err != nil {
			return "", E.Cause(err, "write custom sni")
		}
	}
	err = writeTLV(builder, TagUsername, u.Username)
	if err != nil {
		return "", E.Cause(err, "write username")
	}
	err = writeTLV(builder, TagPassword, u.Password)
	if err != nil {
		return "", E.Cause(err, "write password")
	}
	if u.ClientRandomPrefix != "" {
		err = writeTLV(builder, TagClientRandomPrefix, u.ClientRandomPrefix)
		if err != nil {
			return "", E.Cause(err, "write client random prefix")
		}
	}
	if u.SkipVerification {
		err = writeTLV(builder, TagSkipVerification, true)
		if err != nil {
			return "", E.Cause(err, "write skip verification")
		}
	}
	if cert := u.Certificate; len(cert) > 0 {
		err = writeTLV(builder, TagCertificate, cert)
		if err != nil {
			return "", E.Cause(err, "write certificate")
		}
	}
	if u.UpstreamProtocol != UpstreamProtocolHTTP2 {
		err = writeTLV(builder, TagUpstreamProtocol, byte(u.UpstreamProtocol))
		if err != nil {
			return "", E.Cause(err, "write upstream protocol")
		}
	}
	if u.AntiDPI {
		err = writeTLV(builder, TagAntiDPI, true)
		if err != nil {
			return "", E.Cause(err, "write anti-dpi")
		}
	}

	return Schema + "://?" + base64.RawURLEncoding.EncodeToString(builder.Bytes()), nil
}

func writeTLV(writer io.Writer, tag uint64, data any) (err error) {
	err = writeVarint(writer, tag)
	if err != nil {
		return
	}
	switch data.(type) {
	case byte:
		value := data.(byte)
		_, err = writer.Write([]byte{1, value})
		return
	case bool:
		value := data.(bool)
		buffer := [2]byte{1, 0}
		if value {
			buffer[1] = 0x01
		} else {
			buffer[1] = 0x00
		}
		_, err = writer.Write(buffer[:])
		return
	case string:
		value := data.(string)
		length := uint64(len(value))
		err = writeVarint(writer, length)
		if err != nil {
			return
		}
		_, err = io.WriteString(writer, value)
		return
	case []byte:
		value := data.([]byte)
		length := uint64(len(value))
		err = writeVarint(writer, length)
		if err != nil {
			return
		}
		_, err = writer.Write(value)
		return
	default:
		panic("unexpected data type")
	}
}

const (
	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

func writeVarint(writer io.Writer, value uint64) error {
	var encodedBytes []byte
	var scratch [8]byte
	switch {
	case value <= maxVarInt1:
		scratch[0] = byte(value)
		encodedBytes = scratch[:1]
	case value <= maxVarInt2:
		binary.BigEndian.PutUint16(scratch[:2], uint16(value))
		scratch[0] |= 0x40 // 01xxxxxx
		encodedBytes = scratch[:2]
	case value <= maxVarInt4:
		binary.BigEndian.PutUint32(scratch[:4], uint32(value))
		scratch[0] |= 0x80 // 10xxxxxx
		encodedBytes = scratch[:4]
	case value <= maxVarInt8:
		binary.BigEndian.PutUint64(scratch[:8], value)
		scratch[0] |= 0xc0 // 11xxxxxx
		encodedBytes = scratch[:8]
	default:
		return E.New("varint too large: ", value)
	}
	return common.Error(writer.Write(encodedBytes))
}

func readVarint(reader io.Reader) (uint64, error) {
	var scratch [8]byte
	_, err := io.ReadFull(reader, scratch[:1])
	if err != nil {
		return 0, err
	}
	sizeCode := scratch[0] >> 6
	byteLength := 1 << sizeCode
	scratch[0] &= 0x3f
	if byteLength == 1 {
		return uint64(scratch[0]), nil
	}
	_, err = io.ReadFull(reader, scratch[1:byteLength])
	if err != nil {
		return 0, err
	}
	switch byteLength {
	case 2:
		return uint64(binary.BigEndian.Uint16(scratch[:2])), nil
	case 4:
		return uint64(binary.BigEndian.Uint32(scratch[:4])), nil
	case 8:
		return binary.BigEndian.Uint64(scratch[:8]), nil
	default:
		return 0, E.New("impossible varint length: ", byteLength)
	}
}
