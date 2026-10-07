defmodule Wagyu.InteropTest do
  # Interoperability with wireguard-go. `wgpeer` (test/interop) runs
  # wireguard-go on the userspace network stack of gVisor. Two Wagyu
  # interfaces cannot find an error that both make in the same way. Examples
  # are a wrong MAC1 key or a wrong TAI64N base. wireguard-go can find these
  # errors. These tests need Go (see test_helper.exs).
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.WgPeer

  @moduletag :interop

  # The netstack address of wireguard-go and the stack address of Wagyu.
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

  # Sends `data` from a different process. Thus the test can read the echo
  # while the remaining data still goes out.
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

  # Waits until wireguard-go records a completed handshake with Wagyu.
  # Returns the view that wireguard-go has of the peer.
  defp go_handshake(device) do
    eventually(fn ->
      %{peers: [peer]} = WgPeer.get(device)
      if peer["last_handshake_time_sec"] != "0", do: peer
    end)
  end

  defp wagyu_peer(wagyu) do
    [{_id, group, _type, _modules}] = DynamicSupervisor.which_children(wagyu.children.peer_supervisor)
    group_peer(group)
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

    # wireguard-go records the handshake only after a transport message
    # authenticates under the new key. Here, that message is the packet that
    # started the handshake.
    peer = go_handshake(device)
    assert String.to_integer(peer["rx_bytes"]) > 0
    assert peer["endpoint"] == "127.0.0.1:#{wagyu.port}"

    assert %{initiations_sent: 1, responses_accepted: 1, transport_sent: 1, responses_invalid: 0} =
             counters(wagyu.interface)

    assert %{current: %{}, next: nil} = :sys.get_state(wagyu_peer(wagyu))
  end

  test "wireguard-go initiates, Wagyu responds, and wireguard-go's first packet confirms the key", context do
    # Wagyu has no endpoint for wireguard-go. It gets the endpoint from the
    # initiation.
    wagyu = start_wagyu(context, nil)
    {device, go_port} = start_go(context, endpoint: "127.0.0.1:#{wagyu.port}")

    # A packet from the netstack of wireguard-go to the address of Wagyu
    # starts the handshake. After Wagyu responds, wireguard-go sends the
    # packet under the new key.
    :ok = WgPeer.send_udp(device, @wagyu_address, 9, "hello")

    assert %{responses_sent: 1, keys_confirmed: 1, transport_invalid: 0} =
             counters(wagyu.interface, &(&1.keys_confirmed == 1))

    assert %{current: %{}, next: nil, endpoint: endpoint} = :sys.get_state(wagyu_peer(wagyu))
    assert endpoint == {{127, 0, 0, 1}, go_port}
    assert go_handshake(device)
  end

  test "wireguard-go retries with the cookie from Wagyu's reply while Wagyu is under load", context do
    wagyu = start_wagyu(context, nil)

    # Put the interface under load for the next minute, as a loaded
    # initiation queue does.
    :sys.replace_state(wagyu.children.interface, &%{&1 | under_load_until: &1.clock.() + 60_000})
    {device, _go_port} = start_go(context, endpoint: "127.0.0.1:#{wagyu.port}")
    :ok = WgPeer.send_udp(device, @wagyu_address, 9, "hello")

    # The first initiation has no MAC2 and gets a cookie reply. wireguard-go
    # decrypts the reply. After REKEY_TIMEOUT, it tries again with MAC2 under
    # the cookie, and Wagyu accepts it.
    counters =
      eventually(
        fn ->
          {:ok, %{counters: counters}} = Wagyu.info(wagyu.interface)
          if counters.keys_confirmed == 1, do: counters
        end,
        1_000
      )

    assert %{cookie_replies_sent: 1, initiations: 1, responses_sent: 1, handshakes_rate_limited: 0} = counters
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

    # REKEY_AFTER_TIME goes by on the clock of Wagyu. The next datagram goes
    # out under the old key and starts a handshake, and the echo comes back.
    # wireguard-go takes a maximum of one initiation from a peer in each
    # 20 ms of its own time. A fake clock does not move that time.
    clock = fake_clock(peer, System.monotonic_time(:millisecond))
    advance(clock, 120_000)
    Process.sleep(50)
    ping.()
    assert {:ok, %{data: "ping"}} = SmolNet.recvfrom(socket, 0, 10_000)
    assert %{responses_accepted: 2} = counters(wagyu.interface, &(&1.responses_accepted == 2))

    # The two sides continue under the new key.
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

      # The first datagram waits while Wagyu initiates. Then the datagram
      # confirms the key.
      socket = udp(wagyu)
      :ok = SmolNet.sendto(socket, "ping", %{family: :inet, addr: @go_address, port: 7})
      assert {:ok, %{data: "ping", source: %{addr: @go_address, port: 7}}} = SmolNet.recvfrom(socket, 0, 10_000)

      # This is more data than the buffers of each side can hold. Thus the
      # stream goes through the two TCP windows many times.
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

      # Wagyu sends under the key that the packet from wireguard-go confirmed.
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

    # SmolNet advertises its full receive buffer as its TCP window. Thus one
    # stream is not limited to one segment for each round trip. Before
    # SmolNet 0.4.1, that limit applied (about 47 KB/s over 50 ms). The
    # minimum rate is low, for slow CI runners. WAGYU_THROUGHPUT=1 prints the
    # measured rate.
    test "one TCP stream sustains throughput over a simulated 50 ms round trip", context do
      {device, go_port} = start_go(context, [], delay: 50)
      :ok = WgPeer.sink(device, 9)
      wagyu = start_wagyu(context, %{address: {127, 0, 0, 1}, port: go_port})

      # The measurement does not include the handshake or the connection
      # set-up.
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
    # Wagyu interface that has the two devices as peers. The netstack address
    # of each device routes only to that device.
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

      # The two devices initiate at the same time. Wagyu reads each initiation
      # again with the key of that device.
      for {_remote, device} <- devices, do: :ok = WgPeer.send_udp(device, @wagyu_address, 9_000, "hello")

      for _device <- devices do
        assert {:ok, %{data: "hello", source: %{addr: address}}} = SmolNet.recvfrom(socket, 0, 10_000)
        assert address in Enum.map(context.remotes, & &1.address)
      end

      # Each reply goes under the key of its device.
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

  describe "changing peers" do
    defp go_peer(context, go_port, overrides) do
      Map.merge(
        %{
          public_key: context.go_key,
          endpoint: %{address: {127, 0, 0, 1}, port: go_port},
          allowed_ips: [{{0, 0, 0, 0}, 0}]
        },
        overrides
      )
    end

    defp start_wagyu_with_peers(context, peers) do
      interface = start_supervised!({Wagyu, options(private_key: context.wagyu_private, peers: peers)})
      {:ok, %{listen: %{port: port}}} = Wagyu.info(interface)
      %{interface: interface, port: port, children: children(interface)}
    end

    # Receives data until at least `size` bytes have arrived. Returns all of
    # them.
    defp recv_at_least(socket, size, acc \\ "") do
      if byte_size(acc) >= size do
        acc
      else
        {:ok, data} = SmolNet.recv(socket, 0, 10_000)
        recv_at_least(socket, size, acc <> data)
      end
    end

    defp ping(socket, address, payload \\ "ping") do
      :ok = SmolNet.sendto(socket, payload, %{family: :inet, addr: address, port: 7})
      assert {:ok, %{data: ^payload, source: %{addr: ^address}}} = SmolNet.recvfrom(socket, 0, 10_000)
    end

    test "a change of AllowedIPs during a TCP stream keeps the stream and its session", context do
      {device, go_port} = start_go(context, [])
      :ok = WgPeer.echo(device, :tcp, 7)
      wagyu = start_wagyu(context, %{address: {127, 0, 0, 1}, port: go_port})
      data = :crypto.strong_rand_bytes(1_000_000)
      tcp = connect(wagyu, 7)
      sender = send_async(tcp, data)
      first = recv_at_least(tcp, 100_000)
      peer = wagyu_peer(wagyu)

      # The new prefix of wireguard-go is nested in the default route of a
      # second peer. Thus the source filter of wireguard-go also changes.
      {other, _private_key} = keypair()
      narrowed = go_peer(context, go_port, %{allowed_ips: [{{10, 13, 0, 0}, 24}]})
      :ok = Wagyu.replace_peers(wagyu.interface, [narrowed, %{public_key: other, allowed_ips: [{{0, 0, 0, 0}, 0}]}])

      assert first <> recv_exactly(tcp, byte_size(data) - byte_size(first)) == data
      Task.await(sender, 30_000)
      :ok = SmolNet.close(tcp)

      assert %{configured: 1} = :sys.get_state(peer)
      assert wagyu_peer(wagyu) == peer

      assert %{initiations_sent: 1, responses_accepted: 1, transport_invalid: 0, transport_source_denied: 0} =
               counters(wagyu.interface)
    end

    test "a second wireguard-go peer added at run time carries traffic", context do
      {device, go_port} = start_go(context, [])
      :ok = WgPeer.echo(device, :udp, 7)
      first = go_peer(context, go_port, %{allowed_ips: [{@go_address, 32}]})
      wagyu = start_wagyu_with_peers(context, [first])
      socket = udp(wagyu)
      ping(socket, @go_address)

      {second_key, second_private} = keypair()
      second_address = {10, 13, 0, 3}

      {second_device, second_port} =
        WgPeer.start!(context.wgpeer, second_address,
          private_key: second_private,
          listen_port: 0,
          public_key: context.wagyu_key,
          allowed_ip: "10.13.0.2/32"
        )

      :ok = WgPeer.echo(second_device, :udp, 7)

      second = %{
        public_key: second_key,
        endpoint: %{address: {127, 0, 0, 1}, port: second_port},
        allowed_ips: [{second_address, 32}]
      }

      :ok = Wagyu.replace_peers(wagyu.interface, [first, second])

      ping(socket, second_address)
      ping(socket, @go_address)
      assert %{initiations_sent: 2, responses_accepted: 2, transport_invalid: 0} = counters(wagyu.interface)
    end

    test "Wagyu refuses the traffic and the initiations of a removed wireguard-go peer", context do
      {device, go_port} = start_go(context, [])
      :ok = WgPeer.echo(device, :udp, 7)
      wagyu = start_wagyu(context, %{address: {127, 0, 0, 1}, port: go_port})
      socket = udp(wagyu, 9_000)
      ping(socket, @go_address)

      :ok = Wagyu.replace_peers(wagyu.interface, [])

      # wireguard-go still has a session, so its packet goes out under it.
      :ok = WgPeer.send_udp(device, @wagyu_address, 9_000, "late")
      assert %{unknown_index: 1} = counters(wagyu.interface, &(&1.unknown_index == 1))

      # When wireguard-go configures Wagyu again, it discards the session.
      # Thus its next packet starts a handshake.
      :ok = WgPeer.set(device, public_key: context.wagyu_key, remove: "true")

      :ok =
        WgPeer.set(device,
          public_key: context.wagyu_key,
          endpoint: "127.0.0.1:#{wagyu.port}",
          allowed_ip: "10.13.0.2/32"
        )

      :ok = WgPeer.send_udp(device, @wagyu_address, 9_000, "again")

      assert %{initiations_unknown_peer: 1, responses_sent: 0} =
               counters(wagyu.interface, &(&1.initiations_unknown_peer == 1))

      assert SmolNet.recvfrom(socket, 0, 200) == {:error, :timeout}
    end

    test "after a preshared key rotation on both sides, revoked sessions give way to a new handshake",
         context do
      [old_psk, new_psk] = [:binary.copy(<<1>>, 32), :binary.copy(<<2>>, 32)]
      {device, go_port} = start_go(context, preshared_key: old_psk)
      :ok = WgPeer.echo(device, :udp, 7)
      peer = go_peer(context, go_port, %{preshared_key: old_psk})
      wagyu = start_wagyu_with_peers(context, [peer])
      socket = udp(wagyu)
      ping(socket, @go_address)
      old = wagyu_peer(wagyu)

      :ok = WgPeer.set(device, public_key: context.wagyu_key, update_only: "true", preshared_key: new_psk)
      :ok = Wagyu.replace_peers(wagyu.interface, [%{peer | preshared_key: new_psk}])
      :ok = Wagyu.revoke_sessions(wagyu.interface, context.go_key)

      # A new process makes a new handshake with the new key. wireguard-go
      # takes a maximum of one initiation from a peer in each 20 ms.
      Process.sleep(50)
      ping(socket, @go_address, "after rotation")
      refute wagyu_peer(wagyu) == old

      assert %{initiations_sent: 2, responses_accepted: 2, responses_invalid: 0, transport_invalid: 0} =
               counters(wagyu.interface)
    end
  end

  test "wgpeer vectors still prints the golden transcript", %{wgpeer: wgpeer} do
    assert WgPeer.vectors!(wgpeer) == Wagyu.GoldenVectors.hex()
  end
end
