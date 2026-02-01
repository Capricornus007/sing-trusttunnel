package trusttunnel

import (
	"context"
	stdTLS "crypto/tls"
	"encoding/binary"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
)

type RoundTripper interface {
	http.RoundTripper
	CloseIdleConnections()
}

type ClientOptions struct {
	Ctx                   context.Context
	Detour                N.Dialer
	Server                M.Socksaddr
	Auth                  auth.User
	TLSConfig             tls.Config
	QUIC                  bool
	QUICCongestionControl string
	HealthCheck           bool
}

type Client struct {
	ctx              context.Context
	detour           N.Dialer
	server           M.Socksaddr
	auth             string
	roundTripper     RoundTripper
	healthCheckTimer *time.Timer
	wrapError        func(error) error
}

func NewClient(options ClientOptions) (client *Client, err error) {
	client = &Client{
		ctx:    options.Ctx,
		detour: options.Detour,
		server: options.Server,
		auth:   buildAuth(options.Auth),
	}
	nextProtos := options.TLSConfig.NextProtos()
	if options.QUIC {
		if len(nextProtos) == 0 {
			nextProtos = []string{"h3"}
			options.TLSConfig.SetNextProtos(nextProtos)
		} else if !common.Contains(nextProtos, "h3") {
			return nil, E.New("require alpn h3")
		}
		err = client.quicRoundTripper(options.TLSConfig, options.QUICCongestionControl)
		if err != nil {
			return nil, err
		}
	} else {
		if len(nextProtos) == 0 {
			nextProtos = []string{http2.NextProtoTLS}
			options.TLSConfig.SetNextProtos(nextProtos)
		} else if !common.Contains(nextProtos, http2.NextProtoTLS) {
			return nil, E.New("require alpn h2")
		}
		client.h2RoundTripper(options.TLSConfig)
	}
	if options.HealthCheck {
		client.healthCheckTimer = new(time.Timer)
	}
	return client, nil
}

func (c *Client) h2RoundTripper(tlsConfig tls.Config) {
	c.roundTripper = &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *stdTLS.Config) (net.Conn, error) {
			conn, err := c.detour.DialContext(ctx, N.NetworkTCP, c.server)
			if err != nil {
				return nil, err
			}
			tlsConn, err := tlsConfig.Client(conn)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		AllowHTTP:       false,
		IdleConnTimeout: DefaultSessionTimeout,
	}
	c.wrapError = baderror.WrapH2
}

func (c *Client) Start() error {
	if c.healthCheckTimer != nil {
		c.healthCheckTimer = time.NewTimer(DefaultHealthCheckTimeout)
		go c.loopHealthCheck()
	}
	return nil
}

func (c *Client) loopHealthCheck() {
	for {
		select {
		case <-c.healthCheckTimer.C:
		case <-c.ctx.Done():
			c.healthCheckTimer.Stop()
			return
		}
		ctx, cancel := context.WithTimeout(c.ctx, DefaultHealthCheckTimeout)
		_ = c.HealthCheck(ctx)
		cancel()
	}
}

func (c *Client) resetHealthCheckTimer() {
	if c.healthCheckTimer == nil {
		return
	}
	c.healthCheckTimer.Reset(DefaultHealthCheckTimeout)
}

func (c *Client) Dial(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	pipeReader, pipeWriter := io.Pipe()
	host := destination.String()
	request := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   host,
		},
		Header: make(http.Header),
		Body:   pipeReader,
		Host:   host,
	}
	request.Header.Add("User-Agent", TCPUserAgent)
	request.Header.Add("Proxy-Authorization", c.auth)
	conn := &tcpConn{
		httpConn: httpConn{
			pipeWriter: pipeWriter,
			wrapError:  c.wrapError,
			created:    make(chan struct{}),
		},
	}
	go func() {
		response, err := c.roundTripper.RoundTrip(request.WithContext(ctx))
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setUp(nil, err)
		} else if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			err = E.New("unexpected status code: ", response.StatusCode)
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setUp(nil, err)
		} else {
			c.resetHealthCheckTimer()
			conn.setUp(response.Body, nil)
		}
	}()
	return conn, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	pipeReader, pipeWriter := io.Pipe()
	request := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   UDPMagicAddress,
		},
		Header: make(http.Header),
		Body:   pipeReader,
		Host:   UDPMagicAddress,
	}
	request.Header.Add("User-Agent", UDPUserAgent)
	request.Header.Add("Proxy-Authorization", c.auth)
	conn := &udpConn{
		httpConn: httpConn{
			pipeWriter: pipeWriter,
			wrapError:  c.wrapError,
			created:    make(chan struct{}),
		},
	}
	go func() {
		response, err := c.roundTripper.RoundTrip(request.WithContext(ctx))
		if err != nil {
			err = c.wrapError(err)
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setUp(nil, err)
		} else if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			err = E.New("unexpected status code: ", response.StatusCode)
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setUp(nil, err)
		} else {
			c.resetHealthCheckTimer()
			conn.setUp(response.Body, nil)
		}
	}()
	return conn, nil
}

func (c *Client) ListenICMP(ctx context.Context) (*IcmpConn, error) {
	pipeReader, pipeWriter := io.Pipe()
	request := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   ICMPMagicAddress,
		},
		Header: make(http.Header),
		Body:   pipeReader,
		Host:   ICMPMagicAddress,
	}
	request.Header.Add("User-Agent", ICMPMagicAddress)
	request.Header.Add("Proxy-Authorization", c.auth)
	conn := &IcmpConn{
		httpConn{
			pipeWriter: pipeWriter,
			wrapError:  c.wrapError,
			created:    make(chan struct{}),
		},
	}
	go func() {
		response, err := c.roundTripper.RoundTrip(request.WithContext(ctx))
		if err != nil {
			err = c.wrapError(err)
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setUp(nil, err)
		} else if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			err = E.New("unexpected status code: ", response.StatusCode)
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setUp(nil, err)
		} else {
			c.resetHealthCheckTimer()
			conn.setUp(response.Body, nil)
		}
	}()
	return conn, nil
}

func (c *Client) Close() error {
	c.roundTripper.CloseIdleConnections()
	if c.healthCheckTimer != nil {
		c.healthCheckTimer.Stop()
	}
	return nil
}

func (c *Client) ResetConnections() {
	c.roundTripper.CloseIdleConnections()
	c.resetHealthCheckTimer()
}

func (c *Client) HealthCheck(ctx context.Context) error {
	defer c.resetHealthCheckTimer()
	request := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   HealthCheckMagicAddress,
		},
		Header: make(http.Header),
		Host:   HealthCheckMagicAddress,
	}
	request.Header.Add("User-Agent", HealthCheckUserAgent)
	request.Header.Add("Proxy-Authorization", c.auth)
	response, err := c.roundTripper.RoundTrip(request.WithContext(ctx))
	if err != nil {
		return c.wrapError(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return E.New("unexpected status code: ", response.StatusCode)
	}
	return nil
}

type httpConn struct {
	pipeWriter *io.PipeWriter
	body       io.ReadCloser
	wrapError  func(error) error
	created    chan struct{}
	createErr  error
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
		common.PtrOrNil(h.pipeWriter),
		h.body,
	)
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
	if err = t.waitCreated(); err != nil {
		return 0, err
	}
	n, err = t.body.Read(b)
	err = t.wrapError(err)
	return
}

func (t *tcpConn) Write(b []byte) (n int, err error) {
	n, err = t.pipeWriter.Write(b)
	err = t.wrapError(err)
	return
}

var (
	_ N.NetPacketConn    = (*udpConn)(nil)
	_ N.FrontHeadroom    = (*udpConn)(nil)
	_ N.PacketReadWaiter = (*udpConn)(nil)
)

type udpConn struct {
	httpConn
	readWaitOptions N.ReadWaitOptions
}

func (u *udpConn) FrontHeadroom() int {
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
	_, err = buffer.ReadFullFrom(u.body, int(length)-(16+2+16+2))
	err = u.wrapError(err)
	return
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
	defer buffer.Release()
	if !destination.IsIP() {
		return E.New("only support IP")
	}
	appName := AppName
	if len(appName) > math.MaxUint8 {
		appName = appName[:math.MaxUint8]
	}
	payloadLen := buffer.Len()
	headerLen := 4 + 16 + 2 + 16 + 2 + 1 + len(appName)
	lengthField := uint32(16 + 2 + 16 + 2 + 1 + len(appName) + payloadLen)
	destinationAddress := buildPaddingIP(destination.Addr)

	var header *buf.Buffer
	if buffer.Start() >= headerLen {
		headerBytes := buffer.ExtendHeader(headerLen)
		header = buf.With(headerBytes)
	} else {
		header = buf.NewSize(headerLen)
		defer header.Release()
	}
	common.Must(binary.Write(header, binary.BigEndian, lengthField))
	common.Must(header.WriteZeroN(16 + 2)) // Source address:port (unknown)
	common.Must1(header.Write(destinationAddress[:]))
	common.Must(binary.Write(header, binary.BigEndian, destination.Port))
	common.Must(binary.Write(header, binary.BigEndian, uint8(len(appName))))
	common.Must1(header.WriteString(appName))
	_, err := u.pipeWriter.Write(header.Bytes())
	if err != nil {
		return u.wrapError(err)
	}
	_, err = u.pipeWriter.Write(buffer.Bytes())
	return u.wrapError(err)
}

func (u *udpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = u.WritePacket(buf.As(p), M.SocksaddrFromNet(addr))
	if err == nil {
		n = len(p)
	}
	return
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
	_, err := i.pipeWriter.Write(request.Bytes())
	err = i.wrapError(err)
	return err
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
