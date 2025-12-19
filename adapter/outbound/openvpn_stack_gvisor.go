//go:build with_gvisor

package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	mihomolog "github.com/metacubex/mihomo/log"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	minitunnel "github.com/ooni/minivpn/pkg/tunnel"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
)

const defaultOVPNNIC tcpip.NICID = 1

type openvpnStackDevice struct {
	stack      *stack.Stack
	mtu        uint32
	dispatcher stack.NetworkDispatcher
	outbound   chan *stack.PacketBuffer
	done       chan struct{}
	closeOnce  sync.Once
	tun        *minitunnel.TUN
	addr4      tcpip.Address
	addr6      tcpip.Address
	inPackets  uint64
	outPackets uint64
}

func newOpenVPNStackDevice(tun *minitunnel.TUN, localAddresses []netip.Prefix, mtu uint32) (openvpnDevice, error) {
	ipStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		HandleLocal:        true,
	})
	device := &openvpnStackDevice{
		stack:    ipStack,
		mtu:      mtu,
		outbound: make(chan *stack.PacketBuffer, 256),
		done:     make(chan struct{}),
		tun:      tun,
	}
	if err := ipStack.CreateNIC(defaultOVPNNIC, (*openvpnEndpoint)(device)); err != nil {
		return nil, errors.New(err.String())
	}
	for _, prefix := range localAddresses {
		addr := addressFromAddr(prefix.Addr())
		protoAddr := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   addr,
				PrefixLen: prefix.Bits(),
			},
		}
		if prefix.Addr().Is4() {
			device.addr4 = addr
			protoAddr.Protocol = ipv4.ProtocolNumber
		} else {
			device.addr6 = addr
			protoAddr.Protocol = ipv6.ProtocolNumber
		}
		if err := ipStack.AddProtocolAddress(defaultOVPNNIC, protoAddr, stack.AddressProperties{}); err != nil {
			return nil, errors.New(err.String())
		}
	}

	ipStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: defaultOVPNNIC},
		{Destination: header.IPv6EmptySubnet, NIC: defaultOVPNNIC},
	})
	ipStack.SetSpoofing(defaultOVPNNIC, true)
	ipStack.SetPromiscuousMode(defaultOVPNNIC, true)

	bufSize := 20 * 1024
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     1,
		Default: bufSize,
		Max:     bufSize,
	})
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{
		Min:     1,
		Default: bufSize,
		Max:     bufSize,
	})
	sOpt := tcpip.TCPSACKEnabled(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	mOpt := tcpip.TCPModerateReceiveBufferOption(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)
	cOpt := tcpip.CongestionControlOption("cubic")
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &cOpt)

	return device, nil
}

func (d *openvpnStackDevice) Start() error {
	go d.readLoop()
	go d.writeLoop()
	return nil
}

func (d *openvpnStackDevice) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	addr := tcpip.FullAddress{
		NIC:  defaultOVPNNIC,
		Port: destination.Port,
		Addr: addressFromAddr(destination.Addr),
	}
	bind := tcpip.FullAddress{NIC: defaultOVPNNIC}
	var networkProtocol tcpip.NetworkProtocolNumber
	if destination.IsIPv4() {
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = d.addr4
	} else {
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = d.addr6
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return dialTCPWithBind(ctx, d.stack, bind, addr, networkProtocol)
	case N.NetworkUDP:
		return gonet.DialUDP(d.stack, &bind, &addr, networkProtocol)
	default:
		return nil, N.ErrUnknownNetwork
	}
}

func (d *openvpnStackDevice) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	bind := tcpip.FullAddress{NIC: defaultOVPNNIC}
	var networkProtocol tcpip.NetworkProtocolNumber
	if destination.IsIPv4() {
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = d.addr4
	} else {
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = d.addr6
	}
	return gonet.DialUDP(d.stack, &bind, nil, networkProtocol)
}

func (d *openvpnStackDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.done)
		close(d.outbound)
		d.stack.Close()
		for _, endpoint := range d.stack.CleanupEndpoints() {
			endpoint.Abort()
		}
		d.stack.Wait()
	})
	return nil
}

func (d *openvpnStackDevice) readLoop() {
	buf := make([]byte, 1<<16)
	for {
		select {
		case <-d.done:
			return
		default:
		}
		n, err := d.tun.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		d.logPacket("tun->stack", data, atomic.AddUint64(&d.inPackets, 1))
		var networkProtocol tcpip.NetworkProtocolNumber
		switch header.IPVersion(data) {
		case header.IPv4Version:
			networkProtocol = header.IPv4ProtocolNumber
		case header.IPv6Version:
			networkProtocol = header.IPv6ProtocolNumber
		default:
			continue
		}
		packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(data),
		})
		d.dispatcher.DeliverNetworkPacket(networkProtocol, packetBuffer)
		packetBuffer.DecRef()
	}
}

func (d *openvpnStackDevice) writeLoop() {
	for {
		select {
		case <-d.done:
			return
		case packetBuffer, ok := <-d.outbound:
			if !ok {
				return
			}
			total := 0
			for _, slice := range packetBuffer.AsSlices() {
				total += len(slice)
			}
			payload := make([]byte, total)
			offset := 0
			for _, slice := range packetBuffer.AsSlices() {
				offset += copy(payload[offset:], slice)
			}
			packetBuffer.DecRef()
			d.logPacket("stack->tun", payload, atomic.AddUint64(&d.outPackets, 1))
			_, err := d.tun.Write(payload)
			if err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
					return
				}
			}
		}
	}
}

func dialTCPWithBind(ctx context.Context, s *stack.Stack, localAddr, remoteAddr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*gonet.TCPConn, error) {
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if localAddr != (tcpip.FullAddress{}) {
		if err = ep.Bind(localAddr); err != nil {
			return nil, errors.New(err.String())
		}
	}

	err = ep.Connect(remoteAddr)
	if _, ok := err.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-ctx.Done():
			ep.Close()
			return nil, ctx.Err()
		case <-notifyCh:
		}
		err = ep.LastError()
	}
	if err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "connect",
			Net:  "tcp",
			Addr: M.SocksaddrFromNetIP(netip.AddrPortFrom(addrFromAddress(remoteAddr.Addr), remoteAddr.Port)).TCPAddr(),
			Err:  errors.New(err.String()),
		}
	}

	ep.SocketOptions().SetKeepAlive(true)
	keepAliveIdle := tcpip.KeepaliveIdleOption(15 * time.Second)
	ep.SetSockOpt(&keepAliveIdle)
	keepAliveInterval := tcpip.KeepaliveIntervalOption(15 * time.Second)
	ep.SetSockOpt(&keepAliveInterval)

	return gonet.NewTCPConn(&wq, ep), nil
}

func addressFromAddr(destination netip.Addr) tcpip.Address {
	if destination.Is6() {
		return tcpip.AddrFrom16(destination.As16())
	}
	return tcpip.AddrFrom4(destination.As4())
}

func addrFromAddress(address tcpip.Address) netip.Addr {
	if address.Len() == 16 {
		return netip.AddrFrom16(address.As16())
	}
	return netip.AddrFrom4(address.As4())
}

func (d *openvpnStackDevice) logPacket(direction string, payload []byte, count uint64) {
	if mihomolog.Level() != mihomolog.DEBUG {
		return
	}
	if count > 5 && count%100 != 0 {
		return
	}
	var src, dst netip.Addr
	proto := 0
	switch header.IPVersion(payload) {
	case header.IPv4Version:
		ip4 := header.IPv4(payload)
		src = addrFromAddress(ip4.SourceAddress())
		dst = addrFromAddress(ip4.DestinationAddress())
		proto = int(ip4.Protocol())
	case header.IPv6Version:
		ip6 := header.IPv6(payload)
		src = addrFromAddress(ip6.SourceAddress())
		dst = addrFromAddress(ip6.DestinationAddress())
		proto = int(ip6.NextHeader())
	default:
		mihomolog.Debugln("[OpenVPN] %s packet #%d len=%d unknown ip version", direction, count, len(payload))
		return
	}
	mihomolog.Debugln("[OpenVPN] %s packet #%d len=%d proto=%d src=%s dst=%s", direction, count, len(payload), proto, src, dst)
}

var _ stack.LinkEndpoint = (*openvpnEndpoint)(nil)

type openvpnEndpoint openvpnStackDevice

func (ep *openvpnEndpoint) MTU() uint32 {
	return ep.mtu
}

func (ep *openvpnEndpoint) SetMTU(mtu uint32) {
}

func (ep *openvpnEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (ep *openvpnEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (ep *openvpnEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
}

func (ep *openvpnEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (ep *openvpnEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.dispatcher = dispatcher
}

func (ep *openvpnEndpoint) IsAttached() bool {
	return ep.dispatcher != nil
}

func (ep *openvpnEndpoint) Wait() {
}

func (ep *openvpnEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *openvpnEndpoint) AddHeader(buffer *stack.PacketBuffer) {
}

func (ep *openvpnEndpoint) ParseHeader(ptr *stack.PacketBuffer) bool {
	return true
}

func (ep *openvpnEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	for _, packetBuffer := range list.AsSlice() {
		packetBuffer.IncRef()
		select {
		case <-ep.done:
			return 0, &tcpip.ErrClosedForSend{}
		case ep.outbound <- packetBuffer:
		}
	}
	return list.Len(), nil
}

func (ep *openvpnEndpoint) Close() {
}

func (ep *openvpnEndpoint) SetOnCloseAction(f func()) {
}
