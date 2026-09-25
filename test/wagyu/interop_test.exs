defmodule Wagyu.InteropTest do
  # Interoperability with wireguard-go, run by `wgpeer` (test/interop) on
  # gVisor's userspace network stack. Two Wagyu interfaces cannot catch a
  # mistake both make the same way, such as a wrong MAC1 key or TAI64N base;
  # wireguard-go can. These tests need Go (see test_helper.exs).
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.WgPeer

  @moduletag :interop

  # wireguard-go's netstack address and Wagyu's stack address.
  @go_address {10, 13, 0, 1}
  @wagyu_address {10, 13, 0, 2}

  setup_all do
    %{wgpeer: WgPeer.build!()}
  end

  setup %{wgpeer: wgpeer} do
    {go_key, go_private} = keypair()
    {wagyu_key, wagyu_private} = keypair()
    %{wgpeer: wgpeer, go_key: go_key, go_private: go_private, wagyu_key: wagyu_key, wagyu_private: wagyu_private}
  end

  defp start_wagyu(context, endpoint) do
    options =
      options(
        private_key: context.wagyu_private,
        peers: [%{public_key: context.go_key, endpoint: endpoint, allowed_ips: [{{0, 0, 0, 0}, 0}]}]
      )

    interface = start_supervised!({Wagyu, options})
    {:ok, %{listen: %{port: port}}} = Wagyu.info(interface)
    %{interface: interface, port: port, children: children(interface)}
  end

  defp start_go(context, peer, options \\ []) do
    uapi =
      [private_key: context.go_private, listen_port: 0, public_key: context.wagyu_key] ++
        peer ++ [allowed_ip: "10.13.0.2/32"]

    WgPeer.start!(context.wgpeer, @go_address, uapi, options)
  end

  defp open(wagyu, type) do
    {:ok, stack} = Wagyu.stack(wagyu.interface)
    {:ok, socket} = SmolNet.open(:inet, type, if(type == :dgram, do: :udp, else: :tcp), stack: stack)
    socket
  end

  defp udp(wagyu, port \\ 0) do
    socket = open(wagyu, :dgram)
    :ok = SmolNet.bind(socket, %{family: :inet, addr: @wagyu_address, port: port})
    socket
  end

  defp connect(wagyu, port) do
    socket = open(wagyu, :stream)
    :ok = SmolNet.connect(socket, %{family: :inet, addr: @go_address, port: port}, 10_000)
    socket
  end

  # Sends `data` from another process, so that the echo coming back is read
  # while the rest is still going out.
  defp send_async(socket, data), do: Task.async(fn -> :ok = SmolNet.send(socket, data, 30_000) end)

  defp recv_exactly(socket, size, acc \\ [])
  defp recv_exactly(_socket, 0, acc), do: acc |> Enum.reverse() |> IO.iodata_to_binary()

  defp recv_exactly(socket, size, acc) do
    {:ok, data} = SmolNet.recv(socket, 0, 10_000)
    recv_exactly(socket, size - byte_size(data), [data | acc])
  end

  defp recv_all(socket, acc \\ []) do
    case SmolNet.recv(socket, 0, 10_000) do
      {:ok, data} -> recv_all(socket, [data | acc])
      {:error, :closed} -> acc |> Enum.reverse() |> IO.iodata_to_binary()
    end
  end

  # Waits for wireguard-go to record a completed handshake with Wagyu, and
  # returns its view of the peer.
  defp go_handshake(device) do
    eventually(fn ->
      %{peers: [peer]} = WgPeer.get(device)
      if peer["last_handshake_time_sec"] != "0", do: peer
    end)
  end

  defp wagyu_peer(wagyu) do
    [{_id, pid, _type, _modules}] = DynamicSupervisor.which_children(wagyu.children.peer_supervisor)
    pid
  end

  test "wgpeer runs a configured wireguard-go device on a real UDP port", context do
    {device, port} = start_go(context, [])
    assert port in 1..65_535

    assert %{peers: [%{"public_key" => public_key, "last_handshake_time_sec" => "0"}]} = WgPeer.get(device)
    assert public_key == Base.encode16(context.wagyu_key, case: :lower)
  end

  test "Wagyu initiates, wireguard-go responds, and Wagyu's first packet confirms the key", context do
    {device, go_port} = start_go(context, [])
    wagyu = start_wagyu(context, %{address: {127, 0, 0, 1}, port: go_port})

    # An outbound packet starts the handshake.
    {:ok, stack} = Wagyu.stack(wagyu.interface)
    {:ok, socket} = SmolNet.open(:inet, :dgram, :udp, stack: stack)
    :ok = SmolNet.bind(socket, %{family: :inet, addr: @wagyu_address, port: 0})
    :ok = SmolNet.sendto(socket, "hello", %{family: :inet, addr: @go_address, port: 9})

    # wireguard-go records the handshake only once a transport message
    # authenticates under the new key, which here is the packet that
    # started the handshake.
    peer = go_handshake(device)
    assert String.to_integer(peer["rx_bytes"]) > 0
    assert peer["endpoint"] == "127.0.0.1:#{wagyu.port}"

    assert %{initiations_sent: 1, responses_accepted: 1, transport_sent: 1, responses_invalid: 0} =
             counters(wagyu.interface)

    assert %{current: %{}, next: nil} = :sys.get_state(wagyu_peer(wagyu))
  end

  test "wireguard-go initiates, Wagyu responds, and wireguard-go's first packet confirms the key", context do
    # Wagyu has no endpoint for wireguard-go and learns it from the initiation.
    wagyu = start_wagyu(context, nil)
    {device, go_port} = start_go(context, endpoint: "127.0.0.1:#{wagyu.port}")

    # A packet from wireguard-go's netstack to Wagyu's address starts the
    # handshake, and wireguard-go sends it under the new key once Wagyu has
    # responded.
    :ok = WgPeer.send_udp(device, @wagyu_address, 9, "hello")

    assert %{responses_sent: 1, keys_confirmed: 1, transport_invalid: 0} =
             counters(wagyu.interface, &(&1.keys_confirmed == 1))

    assert %{current: %{}, next: nil, endpoint: endpoint} = :sys.get_state(wagyu_peer(wagyu))
    assert endpoint == {{127, 0, 0, 1}, go_port}
    assert go_handshake(device)
  end

  test "Wagyu rekeys with wireguard-go at 120 seconds without interrupting traffic", context do
    {device, go_port} = start_go(context, [])
    :ok = WgPeer.echo(device, :udp, 7)
    wagyu = start_wagyu(context, %{address: {127, 0, 0, 1}, port: go_port})
    socket = udp(wagyu)
    ping = fn -> :ok = SmolNet.sendto(socket, "ping", %{family: :inet, addr: @go_address, port: 7}) end

    ping.()
    assert {:ok, %{data: "ping"}} = SmolNet.recvfrom(socket, 0, 10_000)
    peer = wagyu_peer(wagyu)
    %{current: %{local_index: first}} = :sys.get_state(peer)

    # REKEY_AFTER_TIME passes on Wagyu's clock. The next datagram goes out
    # under the old key and starts a handshake, and the echo comes back.
    # wireguard-go takes at most one initiation from a peer every 20 ms of
    # its own time, which a fake clock does not move.
    clock = fake_clock(peer, System.monotonic_time(:millisecond))
    advance(clock, 120_000)
    Process.sleep(50)
    ping.()
    assert {:ok, %{data: "ping"}} = SmolNet.recvfrom(socket, 0, 10_000)
    assert %{responses_accepted: 2} = counters(wagyu.interface, &(&1.responses_accepted == 2))

    # Both sides carry on under the new key.
    ping.()
    assert {:ok, %{data: "ping"}} = SmolNet.recvfrom(socket, 0, 10_000)
    assert %{current: %{local_index: second}, previous: %{local_index: ^first}} = :sys.get_state(peer)
    refute second == first
    assert %{transport_invalid: 0, transport_expired: 0, responses_invalid: 0} = counters(wagyu.interface)
    assert go_handshake(device)
  end

  describe "the data path" do
    test "SmolNet UDP and TCP sockets exchange data with wireguard-go's netstack", context do
      {device, go_port} = start_go(context, [])
      :ok = WgPeer.echo(device, :udp, 7)
      :ok = WgPeer.echo(device, :tcp, 7)
      wagyu = start_wagyu(context, %{address: {127, 0, 0, 1}, port: go_port})

      # The first datagram waits while Wagyu initiates, and then confirms
      # the key.
      socket = udp(wagyu)
      :ok = SmolNet.sendto(socket, "ping", %{family: :inet, addr: @go_address, port: 7})
      assert {:ok, %{data: "ping", source: %{addr: @go_address, port: 7}}} = SmolNet.recvfrom(socket, 0, 10_000)

      # More than fits in either side's buffers, so the stream runs through
      # both TCP windows many times over.
      data = :crypto.strong_rand_bytes(1_000_000)
      tcp = connect(wagyu, 7)
      sender = send_async(tcp, data)
      assert recv_exactly(tcp, byte_size(data)) == data
      Task.await(sender, 30_000)
      :ok = SmolNet.close(tcp)

      assert %{transport_invalid: 0, transport_replayed: 0, transport_source_denied: 0, transport_malformed: 0} =
               counters = counters(wagyu.interface)

      assert counters.transport_received > 0 and counters.transport_sent > 0
      assert %{initiations_sent: 1, responses_accepted: 1} = counters
    end

    test "wireguard-go initiates to a SmolNet socket, which replies over the same tunnel", context do
      wagyu = start_wagyu(context, nil)
      {device, _go_port} = start_go(context, endpoint: "127.0.0.1:#{wagyu.port}")
      :ok = WgPeer.echo(device, :udp, 7)
      socket = udp(wagyu, 9_000)

      :ok = WgPeer.send_udp(device, @wagyu_address, 9_000, "hello")
      assert {:ok, %{data: "hello", source: %{addr: @go_address}}} = SmolNet.recvfrom(socket, 0, 10_000)

      # Wagyu sends under the key wireguard-go's packet confirmed.
      :ok = SmolNet.sendto(socket, "reply", %{family: :inet, addr: @go_address, port: 7})
      assert {:ok, %{data: "reply", source: %{addr: @go_address, port: 7}}} = SmolNet.recvfrom(socket, 0, 10_000)
      assert %{responses_sent: 1, keys_confirmed: 1, initiations_sent: 0} = counters(wagyu.interface)
    end

    test ":gen_tcp works over the tunnel with SmolNet's TCP module, as the README shows", context do
      {device, go_port} = start_go(context, [])
      :ok = WgPeer.echo(device, :tcp, 443)
      wagyu = start_wagyu(context, %{address: {127, 0, 0, 1}, port: go_port})
      {:ok, stack} = Wagyu.stack(wagyu.interface)

      tcp_options = [{:tcp_module, SmolNet.Inet.Tcp}, {:smolnet_stack, stack}, :inet, :binary, {:active, false}]
      {:ok, socket} = :gen_tcp.connect(@go_address, 443, tcp_options, 10_000)
      :ok = :gen_tcp.send(socket, "hello")
      assert {:ok, "hello"} = :gen_tcp.recv(socket, 5, 10_000)
      :ok = :gen_tcp.close(socket)
    end

    # SmolNet 0.4.1 advertises its whole receive buffer as its TCP window,
    # so one stream is no longer limited to a segment per round trip (about
    # 47 KB/s over 50 ms before). The floor here is loose, to be safe on
    # slow CI runners; WAGYU_THROUGHPUT=1 prints the rate measured.
    test "one TCP stream sustains throughput over a simulated 50 ms round trip", context do
      {device, go_port} = start_go(context, [], delay: 50)
      :ok = WgPeer.sink(device, 9)
      wagyu = start_wagyu(context, %{address: {127, 0, 0, 1}, port: go_port})

      # The handshake and connection set-up are outside the measurement.
      tcp = connect(wagyu, 9)
      size = 2_000_000
      started = System.monotonic_time(:microsecond)
      :ok = SmolNet.send(tcp, :binary.copy(<<0>>, size), 60_000)
      :ok = SmolNet.shutdown(tcp, :write)
      assert recv_all(tcp) == Integer.to_string(size)
      elapsed = System.monotonic_time(:microsecond) - started
      rate = div(size * 1_000_000, elapsed)

      if System.get_env("WAGYU_THROUGHPUT") == "1",
        do: IO.puts("\nsingle-stream TCP over a 50 ms round trip: #{rate} bytes/s (#{size} bytes in #{elapsed} µs)")

      assert rate > 100_000
    end
  end

  describe "preshared keys" do
    # Two wireguard-go devices, each with its own preshared key, and one
    # Wagyu interface with both as peers. Each device's netstack address is
    # routed to it alone.
    setup context do
      remotes =
        for {address, fill} <- [{{10, 13, 0, 1}, 7}, {{10, 13, 0, 3}, 8}] do
          {key, private_key} = keypair()
          %{address: address, key: key, private_key: private_key, psk: :binary.copy(<<fill>>, 32)}
        end

      Map.put(context, :remotes, remotes)
    end

    defp start_wagyu_with(context, endpoints) do
      peers =
        for {remote, endpoint} <- Enum.zip(context.remotes, endpoints) do
          %{public_key: remote.key, endpoint: endpoint, preshared_key: remote.psk, allowed_ips: [{remote.address, 32}]}
        end

      interface = start_supervised!({Wagyu, options(private_key: context.wagyu_private, peers: peers)})
      {:ok, %{listen: %{port: port}}} = Wagyu.info(interface)
      %{interface: interface, port: port, children: children(interface)}
    end

    defp start_go_with(context, remote, psk, peer) do
      uapi =
        [private_key: remote.private_key, listen_port: 0, public_key: context.wagyu_key, preshared_key: psk] ++
          peer ++ [allowed_ip: "10.13.0.2/32"]

      WgPeer.start!(context.wgpeer, remote.address, uapi)
    end

    test "Wagyu responds to, and initiates with, peers with distinct keys", context do
      wagyu = start_wagyu_with(context, [nil, nil])

      devices =
        for remote <- context.remotes do
          {device, _port} = start_go_with(context, remote, remote.psk, endpoint: "127.0.0.1:#{wagyu.port}")
          :ok = WgPeer.echo(device, :udp, 7)
          {remote, device}
        end

      socket = udp(wagyu, 9_000)

      # Both devices initiate at once, and Wagyu reads each initiation again
      # with that device's key.
      for {_remote, device} <- devices, do: :ok = WgPeer.send_udp(device, @wagyu_address, 9_000, "hello")

      for _device <- devices do
        assert {:ok, %{data: "hello", source: %{addr: address}}} = SmolNet.recvfrom(socket, 0, 10_000)
        assert address in Enum.map(context.remotes, & &1.address)
      end

      # Each reply goes under its own device's key.
      for {remote, _device} <- devices do
        :ok = SmolNet.sendto(socket, "reply", %{family: :inet, addr: remote.address, port: 7})
        assert {:ok, %{data: "reply", source: %{addr: address}}} = SmolNet.recvfrom(socket, 0, 10_000)
        assert address == remote.address
      end

      assert %{responses_sent: 2, keys_confirmed: 2, transport_invalid: 0} = counters(wagyu.interface)
    end

    test "Wagyu initiates to peers with distinct keys", context do
      devices =
        for remote <- context.remotes do
          {device, port} = start_go_with(context, remote, remote.psk, [])
          :ok = WgPeer.echo(device, :udp, 7)
          {device, port}
        end

      wagyu =
        start_wagyu_with(context, Enum.map(devices, fn {_device, port} -> %{address: {127, 0, 0, 1}, port: port} end))

      socket = udp(wagyu)

      for remote <- context.remotes do
        :ok = SmolNet.sendto(socket, "ping", %{family: :inet, addr: remote.address, port: 7})
        assert {:ok, %{data: "ping", source: %{addr: address}}} = SmolNet.recvfrom(socket, 0, 10_000)
        assert address == remote.address
      end

      assert %{initiations_sent: 2, responses_accepted: 2, responses_invalid: 0} = counters(wagyu.interface)
    end

    test "a device with another key completes no handshake either way", context do
      [remote, other] = context.remotes

      # Wagyu responds, and wireguard-go rejects the response.
      wagyu = start_wagyu_with(context, [nil, nil])
      {device, go_port} = start_go_with(context, remote, other.psk, endpoint: "127.0.0.1:#{wagyu.port}")
      :ok = WgPeer.send_udp(device, @wagyu_address, 9, "hello")
      assert %{responses_sent: 1} = counters(wagyu.interface, &(&1.responses_sent == 1))

      # wireguard-go responds to Wagyu, and Wagyu refuses the response.
      :ok = stop_supervised!(Wagyu)
      wagyu = start_wagyu_with(context, [%{address: {127, 0, 0, 1}, port: go_port}, nil])
      :ok = SmolNet.sendto(udp(wagyu), "hello", %{family: :inet, addr: remote.address, port: 9})
      assert %{responses_invalid: 1, responses_accepted: 0} = counters(wagyu.interface, &(&1.responses_invalid == 1))

      Process.sleep(200)
      assert %{keys_confirmed: 0, transport_sent: 0} = counters(wagyu.interface)
      assert %{peers: [%{"last_handshake_time_sec" => "0"}]} = WgPeer.get(device)
    end
  end

  test "wgpeer vectors still prints the golden transcript", %{wgpeer: wgpeer} do
    assert WgPeer.vectors!(wgpeer) == Wagyu.GoldenVectors.hex()
  end
end
