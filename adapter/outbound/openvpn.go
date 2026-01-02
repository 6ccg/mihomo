package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	apexlog "github.com/apex/log"
	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	mihomolog "github.com/metacubex/mihomo/log"

	M "github.com/metacubex/sing/common/metadata"

	miniconfig "github.com/6ccg/minivpn/pkg/config"
	minitunnel "github.com/6ccg/minivpn/pkg/tunnel"
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
	Name string `proxy:"name"`

	// Connection settings
	Server string `proxy:"server"`
	Port   int    `proxy:"port"`
	Proto  string `proxy:"proto,omitempty"` // udp, tcp, udp4, tcp4, udp6, tcp6

	// Authentication - credentials
	Username string `proxy:"username,omitempty"`
	Password string `proxy:"password,omitempty"`

	// Authentication - certificates (PEM format, inline)
	CA   string `proxy:"ca"`
	Cert string `proxy:"cert,omitempty"`
	Key  string `proxy:"key,omitempty"`

	// TLS encryption options (PEM format, inline)
	TLSAuth    string `proxy:"tls-auth,omitempty"`
	TLSCrypt   string `proxy:"tls-crypt,omitempty"`
	TLSCryptV2 string `proxy:"tls-crypt-v2,omitempty"`

	// Encryption settings
	Cipher       string `proxy:"cipher,omitempty"`
	Auth         string `proxy:"auth,omitempty"`
	TLSMaxVer    string `proxy:"tls-max-ver,omitempty"`
	KeyDirection *int   `proxy:"key-direction,omitempty"`

	// Compression
	Compress string `proxy:"compress,omitempty"`

	// Timeout and connection management
	Timeout            int   `proxy:"timeout,omitempty"`
	RenegotiateSeconds int   `proxy:"reneg-sec,omitempty"`
	RenegotiateBytes   int64 `proxy:"reneg-bytes,omitempty"`
	RenegotiatePackets int64 `proxy:"reneg-pkts,omitempty"`

	// Keepalive/ping settings
	Ping        int `proxy:"ping,omitempty"`
	PingRestart int `proxy:"ping-restart,omitempty"`
	PingExit    int `proxy:"ping-exit,omitempty"`

	// Advanced settings
	Fragment         int `proxy:"fragment,omitempty"`
	TransitionWindow int `proxy:"transition-window,omitempty"`
	HandshakeWindow  int `proxy:"hand-window,omitempty"`

	// Certificate verification
	VerifyX509Name string `proxy:"verify-x509-name,omitempty"`
	VerifyX509Type string `proxy:"verify-x509-type,omitempty"`
	RemoteCertTLS  string `proxy:"remote-cert-tls,omitempty"`
	RemoteCertEKU  string `proxy:"remote-cert-eku,omitempty"`

	// Obfuscation
	ProxyOBFS4 string `proxy:"proxy-obfs4,omitempty"`
}

type ovpnNetDialer struct {
	device openvpnDevice
}

var _ dialer.NetDialer = (*ovpnNetDialer)(nil)

func buildVPNOptions(option OpenVPNOption) (*miniconfig.OpenVPNOptions, error) {
	// Validate required fields
	if option.Server == "" {
		return nil, errors.New("missing openvpn server")
	}
	if option.Port == 0 {
		return nil, errors.New("missing openvpn port")
	}
	if option.CA == "" {
		return nil, errors.New("missing openvpn ca certificate")
	}

	vpnOpts := &miniconfig.OpenVPNOptions{
		Remote:   option.Server,
		Port:     strconv.Itoa(option.Port),
		CA:       []byte(option.CA),
		Username: option.Username,
		Password: option.Password,
	}

	// Protocol
	switch strings.ToLower(option.Proto) {
	case "", "udp":
		vpnOpts.Proto = miniconfig.ProtoUDP
	case "udp4":
		vpnOpts.Proto = miniconfig.ProtoUDP4
	case "udp6":
		vpnOpts.Proto = miniconfig.ProtoUDP6
	case "tcp", "tcp-client":
		vpnOpts.Proto = miniconfig.ProtoTCP
	case "tcp4", "tcp4-client":
		vpnOpts.Proto = miniconfig.ProtoTCP4
	case "tcp6", "tcp6-client":
		vpnOpts.Proto = miniconfig.ProtoTCP6
	default:
		return nil, fmt.Errorf("unsupported proto: %s", option.Proto)
	}

	// Certificates
	if option.Cert != "" {
		vpnOpts.Cert = []byte(option.Cert)
	}
	if option.Key != "" {
		vpnOpts.Key = []byte(option.Key)
	}

	// TLS encryption
	if option.TLSAuth != "" {
		vpnOpts.TLSAuth = []byte(option.TLSAuth)
	}
	if option.TLSCrypt != "" {
		vpnOpts.TLSCrypt = []byte(option.TLSCrypt)
	}
	if option.TLSCryptV2 != "" {
		vpnOpts.TLSCryptV2 = []byte(option.TLSCryptV2)
	}

	// Key direction
	if option.KeyDirection != nil {
		vpnOpts.KeyDirection = option.KeyDirection
	}

	// Encryption settings
	if option.Cipher != "" {
		vpnOpts.Cipher = option.Cipher
	}
	if option.Auth != "" {
		vpnOpts.Auth = option.Auth
	} else {
		vpnOpts.Auth = "SHA1" // Default
	}
	if option.TLSMaxVer != "" {
		vpnOpts.TLSMaxVer = option.TLSMaxVer
	}

	// Compression
	switch option.Compress {
	case "":
		vpnOpts.Compress = miniconfig.CompressionUndef
	case "stub":
		vpnOpts.Compress = miniconfig.CompressionStub
	case "lzo-no":
		vpnOpts.Compress = miniconfig.CompressionLZONo
	default:
		return nil, fmt.Errorf("unsupported compression: %s", option.Compress)
	}

	// Renegotiation settings
	if option.RenegotiateSeconds > 0 {
		vpnOpts.RenegotiateSeconds = option.RenegotiateSeconds
	} else {
		vpnOpts.RenegotiateSeconds = miniconfig.DefaultRenegotiateSeconds
	}
	if option.RenegotiateBytes != 0 {
		vpnOpts.RenegotiateBytes = option.RenegotiateBytes
	} else {
		vpnOpts.RenegotiateBytes = miniconfig.DefaultRenegotiateBytes
	}
	vpnOpts.RenegotiatePackets = option.RenegotiatePackets

	// Keepalive
	vpnOpts.Ping = option.Ping
	vpnOpts.PingRestart = option.PingRestart
	vpnOpts.PingExit = option.PingExit

	// Advanced settings
	vpnOpts.Fragment = option.Fragment
	if option.TransitionWindow > 0 {
		vpnOpts.TransitionWindow = option.TransitionWindow
	} else {
		vpnOpts.TransitionWindow = miniconfig.DefaultTransitionWindow
	}
	if option.HandshakeWindow > 0 {
		vpnOpts.HandshakeWindow = option.HandshakeWindow
	} else {
		vpnOpts.HandshakeWindow = miniconfig.DefaultHandshakeWindow
	}

	// Certificate verification
	if option.VerifyX509Name != "" {
		vpnOpts.VerifyX509Name = option.VerifyX509Name
		switch strings.ToLower(option.VerifyX509Type) {
		case "", "subject":
			vpnOpts.VerifyX509Type = miniconfig.VerifyX509SubjectDN
		case "name":
			vpnOpts.VerifyX509Type = miniconfig.VerifyX509SubjectRDN
		case "name-prefix":
			vpnOpts.VerifyX509Type = miniconfig.VerifyX509SubjectRDNPrefix
		default:
			return nil, fmt.Errorf("unsupported verify-x509-type: %s", option.VerifyX509Type)
		}
	}

	// Remote cert TLS (sets both KU and EKU)
	switch strings.ToLower(option.RemoteCertTLS) {
	case "server":
		vpnOpts.RemoteCertKU = []miniconfig.KeyUsage{miniconfig.KeyUsageRequired}
		vpnOpts.RemoteCertEKU = "TLS Web Server Authentication"
	case "client":
		vpnOpts.RemoteCertKU = []miniconfig.KeyUsage{miniconfig.KeyUsageRequired}
		vpnOpts.RemoteCertEKU = "TLS Web Client Authentication"
	case "":
		// No verification
	default:
		return nil, fmt.Errorf("unsupported remote-cert-tls: %s", option.RemoteCertTLS)
	}

	if option.RemoteCertEKU != "" && option.RemoteCertTLS == "" {
		vpnOpts.RemoteCertEKU = option.RemoteCertEKU
	}

	// Obfuscation
	vpnOpts.ProxyOBFS4 = option.ProxyOBFS4

	// Set AuthUserPass flag if username/password provided
	if option.Username != "" && option.Password != "" {
		vpnOpts.AuthUserPass = true
	}

	return vpnOpts, nil
}

func (d ovpnNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.device.DialContext(ctx, network, M.ParseSocksaddr(address).Unwrap())
}

func NewOpenVPN(option OpenVPNOption) (*OpenVPN, error) {
	vpnOpts, err := buildVPNOptions(option)
	if err != nil {
		return nil, err
	}

	if !vpnOpts.HasAuthInfo() {
		return nil, errors.New("openvpn: missing auth info (need ca + username/password or ca + cert + key)")
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

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
	if mihomolog.Level() == mihomolog.DEBUG {
		apexlog.SetLevel(apexlog.DebugLevel)
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
	initCtx := context.WithoutCancel(ctx)
	ctx, cancel := context.WithTimeout(initCtx, timeout)
	defer cancel()
	tun, err := minitunnel.Start(ctx, underlyingDialer, vpnCfg)
	if err != nil {
		// !!! do not set initErr here !!!
		// let us can retry connection in next time (e.g. DNS resolution failure)
		return err
	}
	o.tun = tun

	localPrefixes, err := localPrefixesFromTUN(tun)
	if err != nil {
		// TUN started but failed to get prefixes, cleanup and allow retry
		_ = tun.Close()
		o.tun = nil
		return err
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
		_ = tun.Close()
		o.tun = nil
		o.initErr = err
		return o.initErr
	}
	if err := device.Start(); err != nil {
		_ = tun.Close()
		o.tun = nil
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
		o.device = nil
	}
	if o.tun != nil {
		_ = o.tun.Close()
		o.tun = nil
	}
	return nil
}
