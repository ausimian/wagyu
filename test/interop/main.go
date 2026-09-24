// Command wgpeer is the other side of Wagyu's interoperability tests.
//
//	wgpeer peer <tunnel-address> <mtu>
//	wgpeer vectors
//
// "peer" runs one wireguard-go device over its userspace (gVisor) network
// stack, so it needs neither a TUN device nor root. The device's UDP socket
// is a real one. The test drives it with one command per line on stdin, and
// each command answers "ok", "error <reason>" or, for "get", the device's
// UAPI dump followed by "end":
//
//	set          followed by UAPI "key=value" lines and an empty line,
//	             passed to IpcSet
//	up           brings the device up
//	get          dumps IpcGet, including listen_port and each peer's
//	             last_handshake_time_sec
//	send <address> <port> <payload>
//	             sends one UDP datagram from the netstack, which makes the
//	             device initiate a handshake if it has no session
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
	"net/netip"
	"os"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func main() {
	switch {
	case len(os.Args) == 4 && os.Args[1] == "peer":
		if err := runPeer(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, "wgpeer:", err)
			os.Exit(1)
		}
	case len(os.Args) == 2 && os.Args[1] == "vectors":
		printVectors(os.Stdout)
	default:
		fmt.Fprintln(os.Stderr, "usage: wgpeer peer <tunnel-address> <mtu> | wgpeer vectors")
		os.Exit(2)
	}
}

func runPeer(address, mtuText string) error {
	tunnel, err := netip.ParseAddr(address)
	if err != nil {
		return err
	}
	mtu, err := strconv.Atoi(mtuText)
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
	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)
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

func stderrf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "wgpeer: "+format+"\n", args...)
}
