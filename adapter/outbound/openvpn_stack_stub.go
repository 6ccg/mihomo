//go:build !with_gvisor

package outbound

import (
	"errors"
	"net/netip"

	minitunnel "github.com/6ccg/minivpn/pkg/tunnel"
)

func newOpenVPNStackDevice(_ *minitunnel.TUN, _ []netip.Prefix, _ uint32) (openvpnDevice, error) {
	return nil, errors.New("openvpn requires build tag with_gvisor")
}
