//go:build !with_quic

package trusttunnel

import "github.com/sagernet/sing/common/tls"

func (c *Client) quicRoundTripper(tlsConfig tls.Config, congestionControlName string) error {
	return ErrQUICNotIncluded
}
