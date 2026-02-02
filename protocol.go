package trusttunnel

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
)

const (
	Version = "v0.1.0"

	UDPMagicAddress         = "_udp2"
	ICMPMagicAddress        = "_icmp"
	HealthCheckMagicAddress = "_check"

	DefaultQuicStreamReceiveWindow = 131072 // Chrome's default
	DefaultConnectionTimeout       = 30 * time.Second
	DefaultHealthCheckTimeout      = 7 * time.Second
	DefaultQuicMaxIdleTimeout      = 2 * (DefaultConnectionTimeout + DefaultHealthCheckTimeout)
	DefaultSessionTimeout          = 30 * time.Second
)

var (
	AppName = "sing-trusttunnel"

	// TCPUserAgent is user-agent for TCP connections.
	// Format: <platform> <app_name>
	TCPUserAgent = runtime.GOOS + " " + AppName + "/" + Version

	// UDPUserAgent is user-agent for UDP multiplexing.
	// Format: <platform> _udp2
	UDPUserAgent = runtime.GOOS + " " + UDPMagicAddress

	// ICMPUserAgent is user-agent for ICMP multiplexing.
	// Format: <platform> _icmp
	ICMPUserAgent = runtime.GOOS + " " + ICMPMagicAddress

	HealthCheckUserAgent = runtime.GOOS
)

var ErrQUICNotIncluded = E.New("QUIC is not included")

func buildAuth(user auth.User) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user.Username+":"+user.Password))
}

func parse16BytesIP(buffer [16]byte) netip.Addr {
	var zeroPrefix [12]byte
	isIPv4 := bytes.HasPrefix(buffer[:], zeroPrefix[:])
	// Special: check ::1
	isIPv4 = isIPv4 && !(buffer[12] == 0 && buffer[13] == 0 && buffer[14] == 0 && buffer[15] == 1)
	if isIPv4 {
		return netip.AddrFrom4([4]byte(buffer[12:16]))
	}
	return netip.AddrFrom16(buffer)
}

func buildPaddingIP(addr netip.Addr) (buffer [16]byte) {
	if addr.Is6() {
		return addr.As16()
	}
	ipv4 := addr.As4()
	copy(buffer[12:16], ipv4[:])
	return buffer
}

type httpConn struct {
	writer    io.Writer
	flusher   http.Flusher
	body      io.ReadCloser
	wrapError func(error) error
	created   chan struct{}
	createErr error
}

func (h *httpConn) setUp(body io.ReadCloser, err error) {
	h.body = body
	h.createErr = err
	close(h.created)
}

func (h *httpConn) waitCreated() error {
	if h.body != nil || h.createErr != nil {
		return h.createErr
	}
	<-h.created
	return h.createErr
}

func (h *httpConn) Close() error {
	return common.Close(
		h.writer,
		h.body,
	)
}

func (h *httpConn) writeFlush(p []byte) (n int, err error) {
	n, err = h.writer.Write(p)
	if h.flusher != nil {
		h.flusher.Flush()
	}
	return n, h.wrapError(err)
}

func (h *httpConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (h *httpConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (h *httpConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (h *httpConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (h *httpConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

var _ net.Conn = (*tcpConn)(nil)

type tcpConn struct {
	httpConn
}

func (t *tcpConn) Read(b []byte) (n int, err error) {
	err = t.waitCreated()
	if err != nil {
		return 0, err
	}
	n, err = t.body.Read(b)
	err = t.wrapError(err)
	return
}

func (t *tcpConn) Write(b []byte) (int, error) {
	return t.writeFlush(b)
}

var (
	_ N.NetPacketConn    = (*udpConn)(nil)
	_ N.FrontHeadroom    = (*udpConn)(nil)
	_ N.PacketReadWaiter = (*udpConn)(nil)
)

type udpConn struct {
	httpConn
	readWaitOptions N.ReadWaitOptions
	isClient        bool
}

func (u *udpConn) FrontHeadroom() int {
	if !u.isClient {
		return 4 + 16 + 2 + 16 + 2
	}
	return 4 + 16 + 2 + 16 + 2 + 1 + math.MaxUint8
}

func (u *udpConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	u.readWaitOptions = options
	return false
}

func (u *udpConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	buffer = u.readWaitOptions.NewPacketBuffer()
	destination, err = u.ReadPacket(buffer)
	if err != nil {
		buffer.Release()
		return nil, M.Socksaddr{}, err
	}
	u.readWaitOptions.PostReturn(buffer)
	return buffer, destination, nil
}

func (u *udpConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	err = u.waitCreated()
	if err != nil {
		return M.Socksaddr{}, err
	}
	if u.isClient {
		return u.readPacketFromServer(buffer)
	}
	return u.readPacketFromClient(buffer)
}

func (u *udpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := buf.With(p)
	destination, err := u.ReadPacket(buffer)
	if err != nil {
		return
	}
	n = buffer.Len()
	addr = destination.UDPAddr()
	return
}

func (u *udpConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if !u.isClient {
		return u.writePacketToClient(buffer, destination)
	}
	return u.writePacketToServer(buffer, destination)
}

func (u *udpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = u.WritePacket(buf.As(p), M.SocksaddrFromNet(addr))
	if err == nil {
		n = len(p)
	}
	return
}

func (u *udpConn) readPacketFromServer(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	header := buf.NewSize(4 + 16 + 2 + 16 + 2)
	defer header.Release()
	_, err = header.ReadFullFrom(u.body, header.Cap())
	if err != nil {
		err = u.wrapError(err)
		return
	}
	var length uint32
	common.Must(binary.Read(header, binary.BigEndian, &length))
	var sourceAddressBuffer [16]byte
	common.Must1(header.Read(sourceAddressBuffer[:]))
	destination.Addr = parse16BytesIP(sourceAddressBuffer)
	common.Must(binary.Read(header, binary.BigEndian, &destination.Port))
	common.Must(rw.SkipN(header, 16+2)) // To local address:port
	payloadLen := int(length) - (16 + 2 + 16 + 2)
	if payloadLen < 0 {
		return M.Socksaddr{}, E.New("invalid udp length: ", length)
	}
	_, err = buffer.ReadFullFrom(u.body, payloadLen)
	err = u.wrapError(err)
	return
}

func (u *udpConn) readPacketFromClient(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	header := buf.NewSize(4 + 16 + 2 + 16 + 2 + 1)
	defer header.Release()
	_, err = header.ReadFullFrom(u.body, header.Cap())
	if err != nil {
		err = u.wrapError(err)
		return
	}
	var length uint32
	common.Must(binary.Read(header, binary.BigEndian, &length))
	var sourceAddressBuffer [16]byte
	common.Must1(header.Read(sourceAddressBuffer[:]))
	var sourcePort uint16
	common.Must(binary.Read(header, binary.BigEndian, &sourcePort))
	_ = sourcePort
	var destinationAddressBuffer [16]byte
	common.Must1(header.Read(destinationAddressBuffer[:]))
	destination.Addr = parse16BytesIP(destinationAddressBuffer)
	common.Must(binary.Read(header, binary.BigEndian, &destination.Port))
	var appNameLen uint8
	common.Must(binary.Read(header, binary.BigEndian, &appNameLen))
	if appNameLen > 0 {
		err = rw.SkipN(u.body, int(appNameLen))
		if err != nil {
			err = u.wrapError(err)
			return M.Socksaddr{}, err
		}
	}
	payloadLen := int(length) - (16 + 2 + 16 + 2 + 1 + int(appNameLen))
	if payloadLen < 0 {
		return M.Socksaddr{}, E.New("invalid udp length: ", length)
	}
	_, err = buffer.ReadFullFrom(u.body, payloadLen)
	err = u.wrapError(err)
	return
}

func (u *udpConn) writePacketToClient(buffer *buf.Buffer, source M.Socksaddr) error {
	defer buffer.Release()
	if !source.IsIP() {
		return E.New("only support IP")
	}
	payloadLen := buffer.Len()
	headerLen := 4 + 16 + 2 + 16 + 2
	lengthField := uint32(16 + 2 + 16 + 2 + payloadLen)
	sourceAddress := buildPaddingIP(source.Addr)
	var destinationAddress [16]byte
	var destinationPort uint16
	var (
		header         *buf.Buffer
		headerInBuffer bool
	)
	if buffer.Start() >= headerLen {
		headerBytes := buffer.ExtendHeader(headerLen)
		header = buf.With(headerBytes)
		headerInBuffer = true
	} else {
		header = buf.NewSize(headerLen)
		defer header.Release()
	}
	common.Must(binary.Write(header, binary.BigEndian, lengthField))
	common.Must1(header.Write(sourceAddress[:]))
	common.Must(binary.Write(header, binary.BigEndian, source.Port))
	common.Must1(header.Write(destinationAddress[:]))
	common.Must(binary.Write(header, binary.BigEndian, destinationPort))
	if !headerInBuffer {
		_, err := u.writer.Write(header.Bytes())
		if err != nil {
			return u.wrapError(err)
		}
	}
	_, err := u.writer.Write(buffer.Bytes())
	if err != nil {
		return u.wrapError(err)
	}
	if u.flusher != nil {
		u.flusher.Flush()
	}
	return nil
}

func (u *udpConn) writePacketToServer(buffer *buf.Buffer, source M.Socksaddr) error {
	defer buffer.Release()
	if !source.IsIP() {
		return E.New("only support IP")
	}
	appName := AppName
	if len(appName) > math.MaxUint8 {
		appName = appName[:math.MaxUint8]
	}
	payloadLen := buffer.Len()
	headerLen := 4 + 16 + 2 + 16 + 2 + 1 + len(appName)
	lengthField := uint32(16 + 2 + 16 + 2 + 1 + len(appName) + payloadLen)
	destinationAddress := buildPaddingIP(source.Addr)

	var (
		header         *buf.Buffer
		headerInBuffer bool
	)
	if buffer.Start() >= headerLen {
		headerBytes := buffer.ExtendHeader(headerLen)
		header = buf.With(headerBytes)
		headerInBuffer = true
	} else {
		header = buf.NewSize(headerLen)
		defer header.Release()
	}
	common.Must(binary.Write(header, binary.BigEndian, lengthField))
	common.Must(header.WriteZeroN(16 + 2)) // Source address:port (unknown)
	common.Must1(header.Write(destinationAddress[:]))
	common.Must(binary.Write(header, binary.BigEndian, source.Port))
	common.Must(binary.Write(header, binary.BigEndian, uint8(len(appName))))
	common.Must1(header.WriteString(appName))
	if !headerInBuffer {
		_, err := u.writer.Write(header.Bytes())
		if err != nil {
			return u.wrapError(err)
		}
	}
	_, err := u.writer.Write(buffer.Bytes())
	if err != nil {
		return u.wrapError(err)
	}
	if u.flusher != nil {
		u.flusher.Flush()
	}
	return nil
}

type IcmpConn struct {
	httpConn
}

func (i *IcmpConn) WritePing(id uint16, destination netip.Addr, sequenceNumber uint16, ttl uint8, size uint16) error {
	request := buf.NewSize(2 + 16 + 2 + 1 + 2)
	defer request.Release()
	common.Must(binary.Write(request, binary.BigEndian, id))
	destinationAddress := buildPaddingIP(destination)
	common.Must1(request.Write(destinationAddress[:]))
	common.Must(binary.Write(request, binary.BigEndian, sequenceNumber))
	common.Must(binary.Write(request, binary.BigEndian, ttl))
	common.Must(binary.Write(request, binary.BigEndian, size))
	return common.Error(i.writeFlush(request.Bytes()))
}

func (i *IcmpConn) ReadPing() (id uint16, sourceAddress netip.Addr, icmpType uint8, code uint8, sequenceNumber uint16, err error) {
	err = i.waitCreated()
	if err != nil {
		return
	}
	response := buf.NewSize(2 + 16 + 1 + 1 + 2)
	defer response.Release()
	_, err = response.ReadFullFrom(i.body, response.Cap())
	if err != nil {
		err = i.wrapError(err)
		return
	}
	common.Must(binary.Read(response, binary.BigEndian, &id))
	var sourceAddressBuffer [16]byte
	common.Must1(response.Read(sourceAddressBuffer[:]))
	sourceAddress = parse16BytesIP(sourceAddressBuffer)
	common.Must(binary.Read(response, binary.BigEndian, &icmpType))
	common.Must(binary.Read(response, binary.BigEndian, &code))
	common.Must(binary.Read(response, binary.BigEndian, &sequenceNumber))
	return
}

func (i *IcmpConn) Close() error {
	return i.httpConn.Close()
}

func (i *IcmpConn) ReadPingRequest() (id uint16, destination netip.Addr, sequenceNumber uint16, ttl uint8, size uint16, err error) {
	err = i.waitCreated()
	if err != nil {
		return
	}
	request := buf.NewSize(2 + 16 + 2 + 1 + 2)
	defer request.Release()
	_, err = request.ReadFullFrom(i.body, request.Cap())
	if err != nil {
		err = i.wrapError(err)
		return
	}
	common.Must(binary.Read(request, binary.BigEndian, &id))
	var destinationAddressBuffer [16]byte
	common.Must1(request.Read(destinationAddressBuffer[:]))
	destination = parse16BytesIP(destinationAddressBuffer)
	common.Must(binary.Read(request, binary.BigEndian, &sequenceNumber))
	common.Must(binary.Read(request, binary.BigEndian, &ttl))
	common.Must(binary.Read(request, binary.BigEndian, &size))
	return
}

func (i *IcmpConn) WritePingResponse(id uint16, sourceAddress netip.Addr, icmpType uint8, code uint8, sequenceNumber uint16) error {
	response := buf.NewSize(2 + 16 + 1 + 1 + 2)
	defer response.Release()
	common.Must(binary.Write(response, binary.BigEndian, id))
	sourceAddressBytes := buildPaddingIP(sourceAddress)
	common.Must1(response.Write(sourceAddressBytes[:]))
	common.Must(binary.Write(response, binary.BigEndian, icmpType))
	common.Must(binary.Write(response, binary.BigEndian, code))
	common.Must(binary.Write(response, binary.BigEndian, sequenceNumber))
	return common.Error(i.writeFlush(response.Bytes()))
}
