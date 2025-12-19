package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"

	M "github.com/metacubex/sing/common/metadata"

	miniconfig "github.com/ooni/minivpn/pkg/config"
	minitunnel "github.com/ooni/minivpn/pkg/tunnel"
)

type openvpnDevice interface {
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
	Start() error
	Close() error
}

type OpenVPN struct {
	*Base
	option     OpenVPNOption
	vpnOptions *miniconfig.OpenVPNOptions

	initOk    atomic.Bool
	initMutex sync.Mutex
	initErr   error

	tun    *minitunnel.TUN
	device openvpnDevice
}

type OpenVPNOption struct {
	BasicOption
	Name     string `proxy:"name"`
	Config   string `proxy:"config"`
	Username string `proxy:"username,omitempty"`
	Password string `proxy:"password,omitempty"`
	Timeout  int    `proxy:"timeout,omitempty"`
}

type ovpnNetDialer struct {
	device openvpnDevice
}

var _ dialer.NetDialer = (*ovpnNetDialer)(nil)

func (d ovpnNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.device.DialContext(ctx, network, M.ParseSocksaddr(address).Unwrap())
}

func NewOpenVPN(option OpenVPNOption) (*OpenVPN, error) {
	if option.Config == "" {
		return nil, errors.New("missing openvpn config")
	}
	configPath, err := resolveOpenVPNConfigPath(option.Config)
	if err != nil {
		return nil, err
	}

	vpnOpts, err := miniconfig.ReadConfigFile(configPath)
	if err != nil {
		return nil, err
	}
	applyAuthOverrides(vpnOpts, option)
	if !vpnOpts.HasAuthInfo() {
		return nil, errors.New("openvpn: missing auth info")
	}

	addr := configPath
	if vpnOpts.Remote != "" && vpnOpts.Port != "" {
		addr = net.JoinHostPort(vpnOpts.Remote, vpnOpts.Port)
	}

	return &OpenVPN{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.OpenVPN,
			udp:    true,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
		},
		option:     option,
		vpnOptions: vpnOpts,
	}, nil
}

func resolveOpenVPNConfigPath(path string) (string, error) {
	path = C.Path.Resolve(path)
	if !C.Path.IsSafePath(path) {
		return "", C.Path.ErrNotSafePath(path)
	}
	return path, nil
}

func applyAuthOverrides(vpnOpts *miniconfig.OpenVPNOptions, option OpenVPNOption) {
	if option.Username != "" {
		vpnOpts.Username = option.Username
	}
	if option.Password != "" {
		vpnOpts.Password = option.Password
	}
}

func (o *OpenVPN) init(ctx context.Context) error {
	if o.initOk.Load() {
		return nil
	}
	o.initMutex.Lock()
	defer o.initMutex.Unlock()
	if o.initOk.Load() {
		return nil
	}
	if o.initErr != nil {
		return o.initErr
	}
	if !features.WithGVisor {
		o.initErr = errors.New("openvpn requires build tag with_gvisor")
		return o.initErr
	}

	baseDialer := dialer.NewDialer(o.DialOptions()...)
	var underlyingDialer C.Dialer = baseDialer
	if strings.TrimSpace(o.option.DialerProxy) != "" {
		pd, err := proxydialer.NewByName(o.option.DialerProxy, baseDialer)
		if err != nil {
			o.initErr = err
			return o.initErr
		}
		underlyingDialer = pd
	}

	vpnCfg := miniconfig.NewConfig(miniconfig.WithOpenVPNOptions(o.vpnOptions))

	timeout := time.Duration(o.option.Timeout) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tun, err := minitunnel.Start(ctx, underlyingDialer, vpnCfg)
	if err != nil {
		o.initErr = err
		return o.initErr
	}
	o.tun = tun

	localPrefixes, err := localPrefixesFromTUN(tun)
	if err != nil {
		o.initErr = err
		return o.initErr
	}

	has4, has6 := false, false
	for _, prefix := range localPrefixes {
		if prefix.Addr().Is4() {
			has4 = true
		} else if prefix.Addr().Is6() {
			has6 = true
		}
	}
	if has4 && !has6 {
		// Clamp to IPv4 when the tunnel is effectively IPv4-only, unless user explicitly
		// forces IPv6-only (in which case it's expected to be unreachable).
		if o.prefer != C.IPv6Only {
			o.prefer = C.IPv4Only
		}
	} else if has6 && !has4 {
		// Clamp to IPv6 when the tunnel is effectively IPv6-only, unless user explicitly
		// forces IPv4-only (in which case it's expected to be unreachable).
		if o.prefer != C.IPv4Only {
			o.prefer = C.IPv6Only
		}
	}
	mtu := tun.MTU()
	if mtu == 0 {
		mtu = 1500
	}
	device, err := newOpenVPNStackDevice(tun, localPrefixes, uint32(mtu))
	if err != nil {
		o.initErr = err
		return o.initErr
	}
	if err := device.Start(); err != nil {
		o.initErr = err
		return o.initErr
	}
	o.device = device

	o.initOk.Store(true)
	return nil
}

func localPrefixesFromTUN(tun *minitunnel.TUN) ([]netip.Prefix, error) {
	ipStr := tun.LocalAddr().String()
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("openvpn: invalid local ip %q", ipStr)
	}
	mask := tun.NetMask()
	if ip4 := ip.To4(); ip4 != nil {
		ones := 32
		if mask != nil {
			if o, b := mask.Size(); b == 32 {
				ones = o
			}
		}
		var b [4]byte
		copy(b[:], ip4)
		return []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4(b), ones)}, nil
	}
	ip = ip.To16()
	if ip == nil {
		return nil, fmt.Errorf("openvpn: unsupported ip %q", ipStr)
	}
	ones := 128
	if mask != nil {
		if o, b := mask.Size(); b == 128 {
			ones = o
		}
	}
	var b [16]byte
	copy(b[:], ip)
	return []netip.Prefix{netip.PrefixFrom(netip.AddrFrom16(b), ones)}, nil
}

func (o *OpenVPN) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if err = o.init(ctx); err != nil {
		return nil, err
	}
	var conn net.Conn
	if !metadata.Resolved() {
		options := o.DialOptions()
		options = append(options, dialer.WithResolver(resolver.DefaultResolver))
		options = append(options, dialer.WithNetDialer(ovpnNetDialer{device: o.device}))
		conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	} else {
		conn, err = o.device.DialContext(ctx, "tcp", M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap())
	}
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("conn is nil")
	}
	return NewConn(conn, o), nil
}

func (o *OpenVPN) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = o.init(ctx); err != nil {
		return nil, err
	}
	if err = o.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err := o.device.ListenPacket(ctx, M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap())
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return newPacketConn(pc, o), nil
}

func (o *OpenVPN) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if !metadata.Resolved() && metadata.Host != "" {
		var (
			ip  netip.Addr
			err error
		)
		switch o.prefer {
		case C.IPv4Only:
			ip, err = resolver.ResolveIPv4(ctx, metadata.Host)
		case C.IPv6Only:
			ip, err = resolver.ResolveIPv6(ctx, metadata.Host)
		case C.IPv6Prefer:
			ip, err = resolver.ResolveIPPrefer6(ctx, metadata.Host)
		default:
			ip, err = resolver.ResolveIP(ctx, metadata.Host)
		}
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

// IsL3Protocol implements C.ProxyAdapter
func (o *OpenVPN) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

func (o *OpenVPN) Close() error {
	o.initMutex.Lock()
	defer o.initMutex.Unlock()
	if o.device != nil {
		_ = o.device.Close()
	}
	if o.tun != nil {
		_ = o.tun.Close()
	}
	return nil
}
