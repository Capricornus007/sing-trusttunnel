package trusttunnel

import (
	"sync"
	"unsafe"

	"github.com/sagernet/sing/common"

	"golang.org/x/net/http2"
)

func forceCloseAllConnections(roundTripper RoundTripper) {
	roundTripper.CloseIdleConnections()
	_ = common.Close(roundTripper) // Can close http3 connections
	if h2Transport, isH2Transport := roundTripper.(*http2.Transport); isH2Transport {
		connPool := transportConnPool(h2Transport)
		p := (*h2ClientConnPool)((*efaceWords)(unsafe.Pointer(&connPool)).data)
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, clientConns := range p.conns {
			for _, clientConn := range clientConns {
				_ = clientConn.Close()
			}
		}
		return
	}
}

type efaceWords struct {
	typ  unsafe.Pointer
	data unsafe.Pointer
}

//go:linkname transportConnPool golang.org/x/net/http2.(*Transport).connPool
func transportConnPool(t *http2.Transport) http2.ClientConnPool

type h2ClientConnPool struct {
	t *http2.Transport

	mu    sync.Mutex
	conns map[string][]*http2.ClientConn // key is host:port
	/*dialing      map[string]*dialCall     // currently in-flight dials
	keys         map[*ClientConn][]string
	addConnCalls map[string]*addConnCall // in-flight addConnIfNeeded calls*/
}
