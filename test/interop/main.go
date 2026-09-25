// Command wgpeer is the other side of Wagyu's interoperability tests.
//
//	wgpeer peer <tunnel-address> <mtu> [<delay-ms>]
//	wgpeer vectors
//
// "peer" runs one wireguard-go device over its userspace (gVisor) network
// stack, so it needs neither a TUN device nor root. The device's UDP socket
// is a real one. A delay holds back every datagram the device sends by that
// many milliseconds, in order, which simulates a round trip of that length.
// The test drives it with one command per line on stdin, and each command
// answers "ok", "error <reason>" or, for "get", the device's UAPI dump
// followed by "end":
//
//	set          followed by UAPI "key=value" lines and an empty line,
//	             passed to IpcSet
//	up           brings the device up
//	get          dumps IpcGet, including listen_port and each peer's
//	             last_handshake_time_sec
//	send <address> <port> <payload>
//	             sends one UDP datagram from the netstack, which makes the
//	             device initiate a handshake if it has no session
//	echo udp|tcp <port>
//	             echoes what arrives on that netstack port: each UDP
//	             datagram back to its sender, or each TCP connection's
//	             bytes back until the client closes its side
//	sink <port>  reads each TCP connection on that netstack port until the
//	             client closes its side, then writes the number of bytes it
//	             read, in decimal, and closes
//
// The process exits when stdin closes.
//
// "vectors" prints a WireGuard handshake transcript computed from fixed
// keys, following the whitepaper with golang.org/x/crypto rather than with
// Decibel or Wagyu. Wagyu's golden vectors are this output.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func main() {
	switch {
	case (len(os.Args) == 4 || len(os.Args) == 5) && os.Args[1] == "peer":
		delay := "0"
		if len(os.Args) == 5 {
			delay = os.Args[4]
		}
		if err := runPeer(os.Args[2], os.Args[3], delay); err != nil {
			fmt.Fprintln(os.Stderr, "wgpeer:", err)
			os.Exit(1)
		}
	case len(os.Args) == 2 && os.Args[1] == "vectors":
		printVectors(os.Stdout)
	default:
		fmt.Fprintln(os.Stderr, "usage: wgpeer peer <tunnel-address> <mtu> [<delay-ms>] | wgpeer vectors")
		os.Exit(2)
	}
}

func runPeer(address, mtuText, delayText string) error {
	tunnel, err := netip.ParseAddr(address)
	if err != nil {
		return err
	}
	mtu, err := strconv.Atoi(mtuText)
	if err != nil {
		return err
	}
	delay, err := strconv.Atoi(delayText)
	if err != nil {
		return err
	}
	tunDevice, tnet, err := netstack.CreateNetTUN([]netip.Addr{tunnel}, nil, mtu)
	if err != nil {
		return err
	}

	// wireguard-go's default logger writes to stdout, which carries replies.
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: stderrf}
	if os.Getenv("WGPEER_VERBOSE") != "" {
		logger.Verbosef = stderrf
	}
	bind := conn.NewDefaultBind()
	if delay > 0 {
		bind = newDelayedBind(bind, time.Duration(delay)*time.Millisecond)
	}
	dev := device.NewDevice(tunDevice, bind, logger)
	defer dev.Close()

	in := bufio.NewScanner(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	reply := func(err error) {
		if err != nil {
			fmt.Fprintln(out, "error", strings.ReplaceAll(err.Error(), "\n", " "))
		} else {
			fmt.Fprintln(out, "ok")
		}
		out.Flush()
	}

	for in.Scan() {
		fields := strings.Fields(in.Text())
		switch {
		case len(fields) == 1 && fields[0] == "set":
			var config strings.Builder
			for in.Scan() && in.Text() != "" {
				config.WriteString(in.Text())
				config.WriteByte('\n')
			}
			reply(dev.IpcSet(config.String()))
		case len(fields) == 1 && fields[0] == "up":
			reply(dev.Up())
		case len(fields) == 1 && fields[0] == "get":
			dump, err := dev.IpcGet()
			if err != nil {
				reply(err)
				continue
			}
			fmt.Fprint(out, dump)
			fmt.Fprintln(out, "end")
			out.Flush()
		case len(fields) == 4 && fields[0] == "send":
			reply(send(tnet, fields[1], fields[2], fields[3]))
		case len(fields) == 3 && fields[0] == "echo" && fields[1] == "udp":
			reply(echoUDP(tnet, tunnel, fields[2]))
		case len(fields) == 3 && fields[0] == "echo" && fields[1] == "tcp":
			reply(serveTCP(tnet, tunnel, fields[2], echo))
		case len(fields) == 2 && fields[0] == "sink":
			reply(serveTCP(tnet, tunnel, fields[1], sink))
		default:
			reply(fmt.Errorf("unknown command %q", in.Text()))
		}
	}
	return in.Err()
}

func send(tnet *netstack.Net, address, portText, payload string) error {
	destination, err := netip.ParseAddr(address)
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return err
	}
	socket, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(destination, uint16(port)))
	if err != nil {
		return err
	}
	defer socket.Close()
	_, err = socket.Write([]byte(payload))
	return err
}

func parsePort(text string) (uint16, error) {
	port, err := strconv.ParseUint(text, 10, 16)
	return uint16(port), err
}

func echoUDP(tnet *netstack.Net, tunnel netip.Addr, portText string) error {
	port, err := parsePort(portText)
	if err != nil {
		return err
	}
	socket, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(tunnel, port))
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := socket.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := socket.WriteTo(buf[:n], from); err != nil {
				stderrf("echo udp: %v", err)
			}
		}
	}()
	return nil
}

// serveTCP accepts connections on a netstack port and hands each to handle
// on its own goroutine.
func serveTCP(tnet *netstack.Net, tunnel netip.Addr, portText string, handle func(net.Conn)) error {
	port, err := parsePort(portText)
	if err != nil {
		return err
	}
	listener, err := tnet.ListenTCPAddrPort(netip.AddrPortFrom(tunnel, port))
	if err != nil {
		return err
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go handle(connection)
		}
	}()
	return nil
}

func echo(connection net.Conn) {
	defer connection.Close()
	if _, err := io.Copy(connection, connection); err != nil {
		stderrf("echo tcp: %v", err)
	}
}

func sink(connection net.Conn) {
	defer connection.Close()
	n, err := io.Copy(io.Discard, connection)
	if err != nil {
		stderrf("sink: %v", err)
		return
	}
	fmt.Fprint(connection, n)
}

// delayedBind sends each batch of datagrams a fixed delay after the device
// hands it over, in order. The device reuses its buffers once Send returns,
// so the batch is copied.
type delayedBind struct {
	conn.Bind
	delay time.Duration
	queue chan delayedBatch
}

type delayedBatch struct {
	due      time.Time
	buffers  [][]byte
	endpoint conn.Endpoint
}

func newDelayedBind(bind conn.Bind, delay time.Duration) conn.Bind {
	delayed := &delayedBind{Bind: bind, delay: delay, queue: make(chan delayedBatch, 4096)}
	go delayed.run()
	return delayed
}

func (b *delayedBind) Send(buffers [][]byte, endpoint conn.Endpoint) error {
	copies := make([][]byte, len(buffers))
	for i, buffer := range buffers {
		copies[i] = append([]byte(nil), buffer...)
	}
	b.queue <- delayedBatch{due: time.Now().Add(b.delay), buffers: copies, endpoint: endpoint}
	return nil
}

func (b *delayedBind) run() {
	for batch := range b.queue {
		time.Sleep(time.Until(batch.due))
		if err := b.Bind.Send(batch.buffers, batch.endpoint); err != nil {
			stderrf("delayed send: %v", err)
		}
	}
}

func stderrf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "wgpeer: "+format+"\n", args...)
}
