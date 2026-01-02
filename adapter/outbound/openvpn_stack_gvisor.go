//go:build with_gvisor

package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	mihomolog "github.com/metacubex/mihomo/log"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	minitunnel "github.com/6ccg/minivpn/pkg/tunnel"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
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

// writePayloadPool is used to reduce GC pressure in writeLoop by reusing payload buffers.
var writePayloadPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 1<<16) // 64KB max MTU
		return &buf
	},
}

var (
	openvpnPacketLogAll   bool
	openvpnPacketLogFirst uint64 = 5
	openvpnPacketLogEvery uint64 = 100
	openvpnPacketLogStats bool
)

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
		outbound: make(chan *stack.PacketBuffer, 1024), // Increased from 256 for better throughput
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

	routes := make([]tcpip.Route, 0, 2)
	if device.addr4.Len() != 0 {
		routes = append(routes, tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: defaultOVPNNIC})
	}
	if device.addr6.Len() != 0 {
		routes = append(routes, tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: defaultOVPNNIC})
	}
	ipStack.SetRouteTable(routes)

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
		if d.stack != nil {
			d.stack.Close()
			for _, endpoint := range d.stack.CleanupEndpoints() {
				endpoint.Abort()
			}
			d.stack.Wait()
		}
		close(d.outbound)
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
			if mihomolog.Level() == mihomolog.DEBUG {
				mihomolog.Debugln("[OpenVPN] tun.Read error: %v", err)
			}
			continue
		}
		if n == 0 {
			continue
		}
		payload := buf[:n]
		inCount := atomic.AddUint64(&d.inPackets, 1)
		d.logPacket("tun->stack", payload, inCount)
		var networkProtocol tcpip.NetworkProtocolNumber
		switch header.IPVersion(payload) {
		case header.IPv4Version:
			networkProtocol = header.IPv4ProtocolNumber
		case header.IPv6Version:
			networkProtocol = header.IPv6ProtocolNumber
		default:
			continue
		}
		v := buffer.NewView(n)
		v.Write(payload)
		packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithView(v),
		})
		d.dispatcher.DeliverNetworkPacket(networkProtocol, packetBuffer)
		packetBuffer.DecRef()
		d.logStats("tun->stack", inCount)
	}
}

func (d *openvpnStackDevice) writeLoop() {
	for packetBuffer := range d.outbound {
		select {
		case <-d.done:
			packetBuffer.DecRef()
			continue
		default:
		}

		payloadLen := packetBuffer.Size()
		// Use pooled buffer to reduce GC pressure
		bufPtr := writePayloadPool.Get().(*[]byte)
		payload := (*bufPtr)[:payloadLen]

		views, viewOffset := packetBuffer.AsViewList()
		written := 0
		skip := viewOffset
		for v := views.Front(); v != nil && written < payloadLen; v = v.Next() {
			s := v.AsSlice()
			if skip >= len(s) {
				skip -= len(s)
				continue
			}
			s = s[skip:]
			skip = 0
			written += copy(payload[written:], s)
		}
		packetBuffer.DecRef()
		outCount := atomic.AddUint64(&d.outPackets, 1)
		d.logPacket("stack->tun", payload, outCount)

		select {
		case <-d.done:
			writePayloadPool.Put(bufPtr)
			continue
		default:
		}

		_, err := d.tun.Write(payload)
		writePayloadPool.Put(bufPtr)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			if mihomolog.Level() == mihomolog.DEBUG {
				mihomolog.Debugln("[OpenVPN] tun.Write error: %v", err)
			}
		}
		d.logStats("stack->tun", outCount)
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
	if !openvpnPacketLogAll {
		if count > openvpnPacketLogFirst {
			if openvpnPacketLogEvery == 0 || count%openvpnPacketLogEvery != 0 {
				return
			}
		}
	}

	var (
		src, dst     netip.Addr
		proto        = 0
		transportOff = 0
		ipSummary    string
	)

	switch header.IPVersion(payload) {
	case header.IPv4Version:
		ip4 := header.IPv4(payload)
		transportOff = int(ip4.HeaderLength())
		src = addrFromAddress(ip4.SourceAddress())
		dst = addrFromAddress(ip4.DestinationAddress())
		proto = int(ip4.Protocol())

		flags := ip4.Flags()
		flagsSummary := ""
		if flags&header.IPv4FlagDontFragment != 0 {
			flagsSummary = "DF"
		}
		if flags&header.IPv4FlagMoreFragments != 0 {
			if flagsSummary != "" {
				flagsSummary += "|"
			}
			flagsSummary += "MF"
		}
		if flagsSummary == "" {
			flagsSummary = "0"
		}

		ipSummary = "ipv4 ttl=" + strconv.Itoa(int(ip4.TTL())) +
			" ihl=" + strconv.Itoa(int(ip4.HeaderLength())) +
			" totlen=" + strconv.Itoa(int(ip4.TotalLength())) +
			" id=" + strconv.Itoa(int(ip4.ID())) +
			" flags=" + flagsSummary + "(" + strconv.Itoa(int(flags)) + ")" +
			" fragOff=" + strconv.Itoa(int(ip4.FragmentOffset()))
	case header.IPv6Version:
		ip6 := header.IPv6(payload)
		transportOff = header.IPv6MinimumSize
		src = addrFromAddress(ip6.SourceAddress())
		dst = addrFromAddress(ip6.DestinationAddress())
		proto = int(ip6.NextHeader())
		ipSummary = "ipv6 hlim=" + strconv.Itoa(int(ip6.HopLimit()))
	default:
		mihomolog.Debugln("[OpenVPN] %s packet #%d len=%d unknown ip version", direction, count, len(payload))
		return
	}

	extra := ""
	switch proto {
	case int(header.TCPProtocolNumber):
		if transportOff+header.TCPMinimumSize <= len(payload) {
			tcpHdr := header.TCP(payload[transportOff:])
			tcpHeaderLen := int(tcpHdr.DataOffset())
			if tcpHeaderLen >= header.TCPMinimumSize && transportOff+tcpHeaderLen <= len(payload) {
				tcpPayload := payload[transportOff+tcpHeaderLen:]

				var (
					ipChecksumOK  = true
					tcpChecksumOK = true
				)

				switch header.IPVersion(payload) {
				case header.IPv4Version:
					ip4 := header.IPv4(payload)
					if int(ip4.HeaderLength()) <= len(payload) {
						ipChecksumOK = ip4.IsChecksumValid()
					}
					payloadChecksum := checksum.Checksum(tcpPayload, 0)
					tcpChecksumOK = tcpHdr.IsChecksumValid(ip4.SourceAddress(), ip4.DestinationAddress(), payloadChecksum, uint16(len(tcpPayload)))
				case header.IPv6Version:
					ip6 := header.IPv6(payload)
					payloadChecksum := checksum.Checksum(tcpPayload, 0)
					tcpChecksumOK = tcpHdr.IsChecksumValid(ip6.SourceAddress(), ip6.DestinationAddress(), payloadChecksum, uint16(len(tcpPayload)))
				}

				extra = " tcp " +
					net.JoinHostPort(src.String(), strconv.Itoa(int(tcpHdr.SourcePort()))) + " -> " +
					net.JoinHostPort(dst.String(), strconv.Itoa(int(tcpHdr.DestinationPort()))) +
					" flags=" + tcpHdr.Flags().String() +
					" seq=" + strconv.FormatUint(uint64(tcpHdr.SequenceNumber()), 10) +
					" ack=" + strconv.FormatUint(uint64(tcpHdr.AckNumber()), 10) +
					" win=" + strconv.Itoa(int(tcpHdr.WindowSize())) +
					" ipxsum=" + strconv.FormatBool(ipChecksumOK) +
					" tcpxsum=" + strconv.FormatBool(tcpChecksumOK)
			}
		}
	case int(header.UDPProtocolNumber):
		if transportOff+header.UDPMinimumSize <= len(payload) {
			udpHdr := header.UDP(payload[transportOff:])
			extra = " udp " +
				net.JoinHostPort(src.String(), strconv.Itoa(int(udpHdr.SourcePort()))) + " -> " +
				net.JoinHostPort(dst.String(), strconv.Itoa(int(udpHdr.DestinationPort())))
		}
	case int(header.ICMPv4ProtocolNumber):
		if transportOff+header.ICMPv4MinimumSize <= len(payload) {
			icmp4 := header.ICMPv4(payload[transportOff:])
			extra = " icmp4 type=" + strconv.Itoa(int(icmp4.Type())) + " code=" + strconv.Itoa(int(icmp4.Code()))
		}
	case int(header.ICMPv6ProtocolNumber):
		if transportOff+header.ICMPv6MinimumSize <= len(payload) {
			icmp6 := header.ICMPv6(payload[transportOff:])
			extra = " icmp6 type=" + strconv.Itoa(int(icmp6.Type())) + " code=" + strconv.Itoa(int(icmp6.Code()))
		}
	}

	mihomolog.Debugln("[OpenVPN] %s packet #%d len=%d proto=%d %s src=%s dst=%s%s", direction, count, len(payload), proto, ipSummary, src, dst, extra)
}

func (d *openvpnStackDevice) logStats(direction string, count uint64) {
	if mihomolog.Level() != mihomolog.DEBUG || !openvpnPacketLogStats || d.stack == nil {
		return
	}
	if !openvpnPacketLogAll {
		if count > openvpnPacketLogFirst {
			if openvpnPacketLogEvery == 0 || count%openvpnPacketLogEvery != 0 {
				return
			}
		}
	}

	stats := d.stack.Stats()

	get := func(counter *tcpip.StatCounter) uint64 {
		if counter == nil {
			return 0
		}
		return counter.Value()
	}

	mihomolog.Debugln(
		"[OpenVPN] %s packet #%d stats ip(rx=%d valid=%d delivered=%d invalidDst=%d invalidSrc=%d malformed=%d preDrop=%d inDrop=%d outDrop=%d) tcp(validRx=%d invalidRx=%d sent=%d retrans=%d rstSent=%d rstRecv=%d fails=%d established=%d)",
		direction,
		count,
		get(stats.IP.PacketsReceived),
		get(stats.IP.ValidPacketsReceived),
		get(stats.IP.PacketsDelivered),
		get(stats.IP.InvalidDestinationAddressesReceived),
		get(stats.IP.InvalidSourceAddressesReceived),
		get(stats.IP.MalformedPacketsReceived),
		get(stats.IP.IPTablesPreroutingDropped),
		get(stats.IP.IPTablesInputDropped),
		get(stats.IP.IPTablesOutputDropped),
		get(stats.TCP.ValidSegmentsReceived),
		get(stats.TCP.InvalidSegmentsReceived),
		get(stats.TCP.SegmentsSent),
		get(stats.TCP.Retransmits),
		get(stats.TCP.ResetsSent),
		get(stats.TCP.ResetsReceived),
		get(stats.TCP.FailedConnectionAttempts),
		get(stats.TCP.CurrentEstablished),
	)
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
	select {
	case <-ep.done:
		return 0, &tcpip.ErrClosedForSend{}
	default:
	}

	written := 0
	for _, packetBuffer := range list.AsSlice() {
		packetBuffer.IncRef()
		select {
		case <-ep.done:
			packetBuffer.DecRef()
			return written, &tcpip.ErrClosedForSend{}
		case ep.outbound <- packetBuffer:
			written++
		}
	}
	return written, nil
}

func (ep *openvpnEndpoint) Close() {
}

func (ep *openvpnEndpoint) SetOnCloseAction(f func()) {
}
