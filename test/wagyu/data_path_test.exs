defmodule Wagyu.DataPathTest do
  # The encrypted data path between SmolNet sockets and two remote parties
  # that the test plays, with their own UDP sockets and Decibel sessions.
  # Their AllowedIPs overlap in both families: B's prefixes are nested in
  # A's. The interface runs on a fake clock, and so does a peer once a test
  # needs it to.
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.Admission
  alias Wagyu.IP

  @local {10, 13, 0, 2}
  @local6 {0xFD00, 0, 0, 0, 0, 0, 0, 2}
  # A's addresses, outside B's nested prefixes.
  @a_host {10, 13, 6, 1}
  @a_host6 {0xFD00, 0, 0, 0, 0, 0, 0, 6}
  # B's addresses, inside A's prefixes too.
  @b_host {10, 13, 5, 1}
  @b_host6 {0xFD00, 0, 0, 0, 0, 0, 0, 5}

  @reject_after_messages 0xFFFFFFFFFFFFDFFF

  setup context do
    {_public_key, private_key} = keypair()
    a = remote([{{10, 0, 0, 0}, 8}, {{0xFD00, 0, 0, 0, 0, 0, 0, 0}, 16}])
    b = remote([{{10, 13, 5, 0}, 24}, {@b_host6, 128}])

    options =
      options(
        private_key: private_key,
        stack: [
          addresses: [{@local, 32}, {@local6, 128}],
          routes: [{{0, 0, 0, 0}, 0, {10, 13, 0, 1}}, {{0, 0, 0, 0, 0, 0, 0, 0}, 0, {0xFD00, 0, 0, 0, 0, 0, 0, 1}}],
          mtu: context[:mtu] || 1280
        ],
        peers: [a.config, b.config]
      )

    interface = start_supervised!({Wagyu, options})
    children = children(interface)
    clock = fake_clock(children.interface)
    {:ok, %{public_key: public_key, listen: %{port: port}}} = Wagyu.info(interface)
    {:ok, stack} = Wagyu.stack(interface)

    %{
      interface: interface,
      children: children,
      clock: clock,
      public_key: public_key,
      port: port,
      stack: stack,
      a: a,
      b: b
    }
  end

  defp remote(allowed_ips) do
    {public_key, _private_key} = keypair = keypair()
    socket = udp_socket()
    {:ok, port} = :inet.port(socket)
    endpoint = %{address: {127, 0, 0, 1}, port: port}

    %{
      key: public_key,
      keypair: keypair,
      socket: socket,
      endpoint: {{127, 0, 0, 1}, port},
      config: %{public_key: public_key, endpoint: endpoint, allowed_ips: allowed_ips}
    }
  end

  defp udp_socket do
    {:ok, socket} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}, active: false])
    socket
  end

  defp peer(context, %{key: key}) do
    case :sys.get_state(context.children.interface).peers do
      %{^key => %{pid: pid}} -> pid
      _not_running -> nil
    end
  end

  # The remote party initiates and confirms the handshake with a keepalive,
  # so the peer sends under the new key. Returns the remote party's
  # transport session and the peer's index.
  defp handshake(context, remote) do
    {initiation, session} = initiate_to(context.public_key, remote.keypair, timestamp(1), 77)
    to_wagyu(context, initiation, remote.socket)
    response = receive_datagram(context, remote)
    assert <<2, 0, 0, 0, index::little-32, 77::little-32, _rest::binary>> = response
    assert complete(session, response) == :ok
    to_wagyu(context, transport_frame(session, index), remote.socket)
    peer = eventually(fn -> peer(context, remote) end)
    assert eventually(fn -> match?(%{current: %{local_index: ^index}}, :sys.get_state(peer)) end)
    %{session: session, index: index, peer: peer}
  end

  defp to_wagyu(context, frame, from), do: :ok = :gen_udp.send(from, {127, 0, 0, 1}, context.port, frame)

  defp send_data(context, remote, key, packet, from \\ nil),
    do: to_wagyu(context, transport_frame(key.session, key.index, packet), from || remote.socket)

  # A frame under `key` with a chosen counter, which only moves forward.
  defp frame_at(key, counter, packet) do
    :ok = Decibel.set_nonce(key.session, :out, counter)
    transport_frame(key.session, key.index, packet)
  end

  defp receive_datagram(context, remote) do
    port = context.port
    assert {:ok, {{127, 0, 0, 1}, ^port, frame}} = :gen_udp.recv(remote.socket, 0, 1_000)
    frame
  end

  defp refute_datagram(socket), do: assert(:gen_udp.recv(socket, 0, 100) == {:error, :timeout})

  # A SmolNet UDP socket bound to the interface's own address in `family`.
  defp smolnet_udp(context, family) do
    {:ok, socket} = SmolNet.open(family, :dgram, :udp, stack: context.stack)
    :ok = SmolNet.bind(socket, %{family: family, addr: if(family == :inet, do: @local, else: @local6), port: 0})
    {:ok, %{port: port}} = SmolNet.sockname(socket)
    {socket, port}
  end

  defp smolnet_recv(socket) do
    assert {:ok, %{data: data, source: %{addr: address}}} = SmolNet.recvfrom(socket, 0, 1_000)
    {address, data}
  end

  defp refute_smolnet(socket), do: assert(SmolNet.recvfrom(socket, 0, 100) == {:error, :timeout})

  # A packet for a SmolNet socket from `source`, with some sender padding.
  defp inbound({_a, _b, _c, _d} = source, port, payload),
    do: ipv4_udp(source, @local, 4_000, port, payload) <> <<0::64>>

  defp inbound(source, port, payload), do: ipv6_udp(source, @local6, 4_000, port, payload) <> <<0::64>>

  defp staged(peer), do: peer |> :sys.get_state() |> Map.fetch!(:staged) |> :queue.to_list()

  describe "inbound" do
    test "authenticated packets from the peer's own AllowedIPs reach SmolNet sockets, trimmed", context do
      key = handshake(context, context.a)
      {udp, port} = smolnet_udp(context, :inet)
      {udp6, port6} = smolnet_udp(context, :inet6)

      send_data(context, context.a, key, inbound(@a_host, port, "over IPv4"))
      send_data(context, context.a, key, inbound(@a_host6, port6, "over IPv6"))

      assert smolnet_recv(udp) == {@a_host, "over IPv4"}
      assert smolnet_recv(udp6) == {@a_host6, "over IPv6"}
      assert %{transport_received: 2, keepalives_received: 1, ingress: 2} = counters(context.interface)
    end

    test "packets whose source's longest AllowedIPs match is another peer, or none, are dropped", context do
      key = handshake(context, context.a)
      {udp, port} = smolnet_udp(context, :inet)
      {udp6, port6} = smolnet_udp(context, :inet6)

      # B's nested prefixes, and addresses that no peer's prefixes cover.
      send_data(context, context.a, key, inbound(@b_host, port, "spoofed"))
      send_data(context, context.a, key, inbound({192, 0, 2, 1}, port, "spoofed"))
      send_data(context, context.a, key, inbound(@b_host6, port6, "spoofed"))
      send_data(context, context.a, key, inbound({0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, port6, "spoofed"))

      assert %{transport_source_denied: 4, transport_received: 0} =
               counters(context.interface, &(&1.transport_source_denied == 4))

      refute_smolnet(udp)
      refute_smolnet(udp6)
      assert %{ingress: 0} = counters(context.interface)
    end

    test "reordered counters within the window pass, and duplicate and stale ones are refused before decryption",
         context do
      key = handshake(context, context.a)
      {udp, port} = smolnet_udp(context, :inet)
      data = fn counter -> frame_at(key, counter, inbound(@a_host, port, Integer.to_string(counter))) end

      # Counter 0 was the keepalive. Frames can only be made in counter
      # order, so they are made first and sent out of order.
      [one, two, three, edge, genuine, highest] = Enum.map([1, 2, 3, 873, 5_000, 9_000], data)

      # A forgery of the frame with counter 5000, which does not
      # authenticate, so its counter is never committed.
      <<header::binary-16, first, rest::binary>> = genuine
      forged = <<header::binary, Bitwise.bxor(first, 1), rest::binary>>

      # A counter 8128 or more behind the highest (9000 - 8128 = 872) is
      # stale. The window refuses it before decryption, so it counts as a
      # replay although it would not have authenticated either.
      stale = <<4, 0, 0, 0, key.index::little-32, 872::little-64, 0::128>>

      for frame <- [three, one, two, two, forged, highest, genuine, edge, stale] do
        to_wagyu(context, frame, context.a.socket)
      end

      assert %{transport_replayed: 2, transport_invalid: 1, transport_received: 6} =
               counters(context.interface, &(&1.transport_replayed == 2 and &1.transport_received == 6))

      received = for _n <- 1..6, do: udp |> smolnet_recv() |> elem(1)
      assert received == ~w(3 1 2 9000 5000 873)
      refute_smolnet(udp)
    end

    test "malformed, spoofed, replayed and forged messages never move the endpoint, and data that passes does",
         context do
      key = handshake(context, context.a)
      {udp, port} = smolnet_udp(context, :inet)
      attacker = udp_socket()
      replayed = transport_frame(key.session, key.index, inbound(@a_host, port, "first"))
      to_wagyu(context, replayed, context.a.socket)
      assert smolnet_recv(udp) == {@a_host, "first"}

      # An IP length beyond the plaintext, and a plaintext that is not IP.
      <<too_short::binary-30, _rest::binary>> = ipv4_udp(@a_host, @local, 4_000, port, String.duplicate("x", 20))
      send_data(context, context.a, key, too_short, attacker)
      send_data(context, context.a, key, "not an IP packet", attacker)
      send_data(context, context.a, key, inbound(@b_host, port, "spoofed"), attacker)
      to_wagyu(context, replayed, attacker)
      <<header::binary-16, first, rest::binary>> = transport_frame(key.session, key.index, inbound(@a_host, port, "x"))
      to_wagyu(context, <<header::binary, Bitwise.bxor(first, 1), rest::binary>>, attacker)

      assert %{transport_malformed: 2, transport_source_denied: 1, transport_replayed: 1, transport_invalid: 1} =
               counters(context.interface, &(&1.transport_invalid == 1))

      assert %{endpoint: endpoint} = :sys.get_state(key.peer)
      assert endpoint == context.a.endpoint
      assert peer(context, context.a) == key.peer
      refute_smolnet(udp)

      # Data that passes every check moves the endpoint to its source, and
      # the peer then sends there.
      send_data(context, context.a, key, inbound(@a_host, port, "roamed"), attacker)
      assert smolnet_recv(udp) == {@a_host, "roamed"}
      {:ok, attacker_port} = :inet.port(attacker)
      assert eventually(fn -> :sys.get_state(key.peer).endpoint == {{127, 0, 0, 1}, attacker_port} end)

      :ok = SmolNet.sendto(udp, "reply", %{family: :inet, addr: @a_host, port: 4_000})
      assert {:ok, {{127, 0, 0, 1}, _port, <<4, _rest::binary>>}} = :gen_udp.recv(attacker, 0, 1_000)

      # So does a keepalive.
      send_data(context, context.a, key, "")
      assert eventually(fn -> :sys.get_state(key.peer).endpoint == context.a.endpoint end)
    end
  end

  describe "outbound" do
    test "packets route to the peer with the longest matching prefix, in both families", context do
      {udp, _port} = smolnet_udp(context, :inet)
      {udp6, _port6} = smolnet_udp(context, :inet6)

      for destination <- [{10, 13, 5, 9}, {10, 13, 6, 9}] do
        :ok = SmolNet.sendto(udp, "hello", %{family: :inet, addr: destination, port: 9})
      end

      for destination <- [@b_host6, @a_host6] do
        :ok = SmolNet.sendto(udp6, "hello", %{family: :inet6, addr: destination, port: 9})
      end

      # With no keys yet, each peer stages its packets.
      [a, b] = Enum.map([context.a, context.b], fn remote -> eventually(fn -> peer(context, remote) end) end)
      assert eventually(fn -> length(staged(a)) == 2 and length(staged(b)) == 2 end)

      destinations = fn peer -> Enum.map(staged(peer), &elem(IP.parse(&1), 1).destination) end
      assert destinations.(a) == [{10, 13, 6, 9}, @a_host6]
      assert destinations.(b) == [{10, 13, 5, 9}, @b_host6]
    end

    test "packets staged by a responder go to where the confirming message came from", context do
      {initiation, session} = initiate_to(context.public_key, context.a.keypair, timestamp(1), 77)
      to_wagyu(context, initiation, context.a.socket)
      response = receive_datagram(context, context.a)
      assert <<2, 0, 0, 0, index::little-32, 77::little-32, _rest::binary>> = response
      assert complete(session, response) == :ok

      # The responder has no key to send with until it is confirmed, and
      # REKEY_TIMEOUT stops it initiating, so the packet waits.
      {udp, _port} = smolnet_udp(context, :inet)
      :ok = SmolNet.sendto(udp, "staged", %{family: :inet, addr: @a_host, port: 9})
      peer = eventually(fn -> peer(context, context.a) end)
      assert eventually(fn -> length(staged(peer)) == 1 end)

      # The remote party roams and confirms the key from its new address.
      roamed = udp_socket()
      to_wagyu(context, transport_frame(session, index), roamed)
      assert {:ok, {{127, 0, 0, 1}, _port, frame}} = :gen_udp.recv(roamed, 0, 1_000)
      assert {:ok, plaintext} = open_transport(session, frame)
      assert {:ok, %{destination: @a_host}} = IP.parse(plaintext)
      refute_datagram(context.a.socket)
    end

    @tag mtu: 1285
    test "plaintext is padded with zeros to a multiple of 16 bytes, but not beyond the MTU", context do
      key = handshake(context, context.a)
      {udp, _port} = smolnet_udp(context, :inet)

      # IP lengths of 29, 48, 1283 and 1285: 28 bytes of headers and the
      # payload.
      for size <- [1, 20, 1_255, 1_257] do
        :ok = SmolNet.sendto(udp, String.duplicate("p", size), %{family: :inet, addr: @a_host, port: 9})
      end

      sizes =
        for _n <- 1..4 do
          {:ok, plaintext} = open_transport(key.session, receive_datagram(context, context.a))
          {:ok, %{length: length}} = IP.parse(plaintext)
          padding = byte_size(plaintext) - length
          assert binary_part(plaintext, length, padding) == <<0::size(padding * 8)>>
          {length, byte_size(plaintext)}
        end

      assert sizes == [{29, 32}, {48, 48}, {1_283, 1_285}, {1_285, 1_285}]
      assert %{transport_sent: 4} = counters(context.interface)
    end

    test "packets staged for a key go out in order under it, and at most 128 wait", context do
      {udp, _port} = smolnet_udp(context, :inet)

      # The first packet starts the handshake; the rest wait for its key.
      send_egress(udp, 1, @a_host)
      initiation = receive_datagram(context, context.a)

      for n <- 2..130 do
        :ok = SmolNet.sendto(udp, "packet #{n}", %{family: :inet, addr: @a_host, port: 9})
      end

      peer = eventually(fn -> peer(context, context.a) end)
      assert %{staged_dropped: 2} = counters(context.interface, &(&1.staged_dropped == 2))
      assert length(staged(peer)) == 128

      {response, session, _sent} = respond_to(initiation, context.a.keypair, 7)
      to_wagyu(context, response, context.a.socket)

      payloads =
        for counter <- 0..127 do
          frame = receive_datagram(context, context.a)
          assert <<4, 0, 0, 0, 7::little-32, ^counter::little-64, _rest::binary>> = frame
          {:ok, plaintext} = open_transport(session, frame)
          {:ok, %{length: length}} = IP.parse(plaintext)
          <<_headers::binary-28, payload::binary>> = binary_part(plaintext, 0, length)
          payload
        end

      assert payloads == Enum.map(1..128, &"packet #{&1}")
      assert staged(peer) == []
      assert %{keepalives_sent: 0, transport_sent: 128} = counters(context.interface, &(&1.transport_sent == 128))
    end

    @tag mtu: 16_384
    test "staging is bounded in bytes too", context do
      {udp, _port} = smolnet_udp(context, :inet)

      # 16,028-byte packets: 16 fit in 256 KiB. The first starts the
      # handshake, and the rest wait with it for its key.
      send = fn -> :ok = SmolNet.sendto(udp, :binary.copy("b", 16_000), %{family: :inet, addr: @a_host, port: 9}) end
      send.()
      assert <<1, _rest::binary>> = receive_datagram(context, context.a)
      for _n <- 2..17, do: send.()

      peer = eventually(fn -> peer(context, context.a) end)
      assert %{staged_dropped: 1} = counters(context.interface, &(&1.staged_dropped == 1))
      assert length(staged(peer)) == 16
      assert Admission.usage(:sys.get_state(peer).staging) == {16, 256_448}
    end

    # Killing the peer logs its exit.
    @tag :capture_log
    test "staged packets never show in the peer's status, and count as dropped if it exits", context do
      {udp, _port} = smolnet_udp(context, :inet)
      send_egress(udp, 3, @a_host)
      peer = eventually(fn -> peer(context, context.a) end)
      assert eventually(fn -> length(staged(peer)) == 3 end)

      {:status, ^peer, _module, [_pdict, _status, _parent, _debug, [_header, _data, {:data, [{~c"State", state}]}]]} =
        :sys.get_status(peer)

      assert state.staged == :redacted

      monitor = Process.monitor(peer)
      Process.exit(peer, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^peer, :killed}
      assert %{egress_peer_dropped: 3} = counters(context.interface, &(&1.egress_peer_dropped == 3))
    end
  end

  describe "key limits" do
    test "a key's age runs from the initiation, so a response 180 seconds late yields no usable key", context do
      {udp, _port} = smolnet_udp(context, :inet)
      :ok = SmolNet.sendto(udp, "waiting", %{family: :inet, addr: @a_host, port: 9})
      initiation = receive_datagram(context, context.a)
      peer = eventually(fn -> peer(context, context.a) end)
      %{initiation: %{sent_at: sent_at}} = :sys.get_state(peer)
      advance(fake_clock(peer, sent_at), 180_000)

      # The response still completes the handshake, but its key is already
      # as old as the responder's will be, so the staged packet waits for a
      # new handshake instead of going out under it.
      {response, _session, _sent} = respond_to(initiation, context.a.keypair, 7)
      to_wagyu(context, response, context.a.socket)
      assert <<1, _rest::binary>> = receive_datagram(context, context.a)
      refute_datagram(context.a.socket)
      assert %{current: %{remote_index: 7}} = state = :sys.get_state(peer)
      assert [_waiting] = :queue.to_list(state.staged)
      assert %{responses_accepted: 1, transport_sent: 0, initiations_sent: 2} = counters(context.interface)
    end

    test "a key sends and receives nothing once it is 180 seconds old", context do
      key = handshake(context, context.a)
      {udp, port} = smolnet_udp(context, :inet)
      %{current: %{created_at: created_at}} = :sys.get_state(key.peer)
      clock = fake_clock(key.peer, created_at)

      advance(clock, 179_999)
      send_data(context, context.a, key, inbound(@a_host, port, "in time"))
      assert smolnet_recv(udp) == {@a_host, "in time"}
      :ok = SmolNet.sendto(udp, "in time", %{family: :inet, addr: @a_host, port: 9})
      assert <<4, _rest::binary>> = receive_datagram(context, context.a)

      advance(clock, 1)
      send_data(context, context.a, key, inbound(@a_host, port, "too late"))
      assert %{transport_expired: 1} = counters(context.interface, &(&1.transport_expired == 1))
      refute_smolnet(udp)

      # An outbound packet waits for a new handshake instead.
      :ok = SmolNet.sendto(udp, "too late", %{family: :inet, addr: @a_host, port: 9})
      assert <<1, _rest::binary>> = receive_datagram(context, context.a)
      assert [_one] = staged(key.peer)
      assert %{transport_sent: 1, initiations_sent: 1} = counters(context.interface)
    end

    test "a key sends nothing at REJECT_AFTER_MESSAGES, and the packet waits for a new handshake", context do
      key = handshake(context, context.a)
      {udp, _port} = smolnet_udp(context, :inet)
      # REKEY_TIMEOUT has passed since the peer's response, so it may
      # initiate.
      %{handshake_sent_at: sent_at} = :sys.get_state(key.peer)
      advance(fake_clock(key.peer, sent_at), 5_000)

      :ok =
        in_process(key.peer, fn %{current: key_pair} ->
          Decibel.set_nonce(key_pair.session, :out, @reject_after_messages - 1)
        end)

      for payload <- ["last", "one too many"] do
        :ok = SmolNet.sendto(udp, payload, %{family: :inet, addr: @a_host, port: 9})
      end

      last = @reject_after_messages - 1
      assert <<4, 0, 0, 0, _index::little-32, ^last::little-64, _rest::binary>> = receive_datagram(context, context.a)
      assert <<1, _rest::binary>> = receive_datagram(context, context.a)
      refute_datagram(context.a.socket)
      assert [_one] = staged(key.peer)
      assert %{transport_sent: 1, initiations_sent: 1} = counters(context.interface)
    end
  end
end
