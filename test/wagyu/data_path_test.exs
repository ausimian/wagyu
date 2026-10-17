defmodule Wagyu.DataPathTest do
  # The encrypted data path between SmolNet sockets and two remote parties.
  # The test simulates the remote parties, with their own UDP sockets and
  # Decibel sessions. Their AllowedIPs overlap in the two families: the
  # prefixes of B are in the prefixes of A. The interface runs on a fake
  # clock. A peer also runs on a fake clock when a test needs it.
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.Admission
  alias Wagyu.EgressCredit
  alias Wagyu.IndexTable
  alias Wagyu.IP

  @local {10, 13, 0, 2}
  @local6 {0xFD00, 0, 0, 0, 0, 0, 0, 2}
  # The addresses of A, outside the nested prefixes of B.
  @a_host {10, 13, 6, 1}
  @a_host6 {0xFD00, 0, 0, 0, 0, 0, 0, 6}
  # The addresses of B, which are also in the prefixes of A.
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

  # OTP 27 gives a UDP socket an 8 KiB receive buffer. On loopback, a burst
  # of staged packets overflows this buffer. Thus, set the buffer as the
  # interface does.
  defp udp_socket do
    {:ok, socket} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}, active: false, recbuf: 1_048_576])
    socket
  end

  defp peer(context, %{key: key}) do
    case :sys.get_state(context.children.interface).peers do
      %{^key => %{pid: pid}} -> pid
      _not_running -> nil
    end
  end

  # The remote party initiates and confirms the handshake with a keepalive.
  # Thus the peer sends under the new key. Returns the transport session of
  # the remote party and the index of the peer.
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

  # Returns a frame under `key` with a selected counter. The counter can only
  # increase.
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

  # Returns a SmolNet UDP socket bound to the address of the interface in
  # `family`.
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

  # Returns a packet for a SmolNet socket from `source`, with some padding
  # from the sender.
  defp inbound({_a, _b, _c, _d} = source, port, payload),
    do: ipv4_udp(source, @local, 4_000, port, payload) <> <<0::64>>

  defp inbound(source, port, payload), do: ipv6_udp(source, @local6, 4_000, port, payload) <> <<0::64>>

  # Returns an egress packet from a SmolNet socket to `destination`.
  defp outbound(destination, payload), do: ipv4_udp(@local, destination, 4_000, 9, payload)

  # Returns the payload of the next packet that `remote` receives under
  # `key`.
  defp receive_payload(context, remote, key) do
    {:ok, plaintext} = open_transport(key.session, receive_datagram(context, remote))
    {:ok, %{length: length}} = IP.parse(plaintext)
    <<_headers::binary-28, payload::binary>> = binary_part(plaintext, 0, length)
    payload
  end

  defp message_queue_len(pid), do: elem(Process.info(pid, :message_queue_len), 1)

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

    test "packets decrypted back to back go to the link together, and their frames stay admitted until then",
         context do
      key = handshake(context, context.a)
      {udp, port} = smolnet_udp(context, :inet)
      link = context.children.link
      a_key = context.a.key
      %{peers: %{^a_key => %{inbound: inbound}}} = :sys.get_state(context.children.interface)

      # Ten frames wait for the peer, and the link also waits.
      :ok = :sys.suspend(key.peer)
      :ok = :sys.suspend(link)
      for n <- 1..10, do: send_data(context, context.a, key, inbound(@a_host, port, "packet #{n}"))
      assert eventually(fn -> match?({10, _bytes}, Admission.usage(inbound)) end)

      # The peer takes all ten frames before its mailbox is empty. Then it
      # sends their trimmed packets in one message.
      :ok = :sys.resume(key.peer)
      {:messages, messages} = eventually(fn -> message_queue_len(link) > 0 and Process.info(link, :messages) end)
      assert [packets] = for({:wg_plaintext, packets} <- messages, do: packets)
      assert packets == for(n <- 1..10, do: ipv4_udp(@a_host, @local, 4_000, port, "packet #{n}"))
      assert eventually(fn -> Admission.usage(inbound) == {0, 0} end)

      :ok = :sys.resume(link)
      for n <- 1..10, do: assert(smolnet_recv(udp) == {@a_host, "packet #{n}"})
      assert %{transport_received: 10, ingress: 10} = counters(context.interface, &(&1.ingress == 10))
    end

    test "frames that carry no packet cannot hold back one waiting for the link", context do
      key = handshake(context, context.a)
      {_udp, port} = smolnet_udp(context, :inet)
      link = context.children.link
      a_key = context.a.key
      %{peers: %{^a_key => %{inbound: inbound}}} = :sys.get_state(context.children.interface)
      :ok = :sys.suspend(key.peer)
      :ok = :sys.suspend(link)

      # A packet, 40 replays of that packet, which the peer refuses, and one
      # more packet.
      first = transport_frame(key.session, key.index, inbound(@a_host, port, "first"))
      for _n <- 0..40, do: to_wagyu(context, first, context.a.socket)
      send_data(context, context.a, key, inbound(@a_host, port, "second"))
      assert eventually(fn -> match?({42, _bytes}, Admission.usage(inbound)) end)

      # The first packet goes after the peer takes 32 frames. It does not wait
      # until the mailbox of the peer is empty.
      :ok = :sys.resume(key.peer)

      deliveries =
        eventually(fn ->
          {:messages, messages} = Process.info(link, :messages)
          deliveries = for {:wg_plaintext, packets} <- messages, do: packets
          length(deliveries) == 2 and deliveries
        end)

      assert deliveries == [
               [ipv4_udp(@a_host, @local, 4_000, port, "first")],
               [ipv4_udp(@a_host, @local, 4_000, port, "second")]
             ]

      :ok = :sys.resume(link)

      assert %{transport_replayed: 40, transport_received: 2} =
               counters(context.interface, &(&1.transport_received == 2))
    end

    test "packets whose source's longest AllowedIPs match is another peer, or none, are dropped", context do
      key = handshake(context, context.a)
      {udp, port} = smolnet_udp(context, :inet)
      {udp6, port6} = smolnet_udp(context, :inet6)

      # The nested prefixes of B, and addresses that the prefixes of no peer
      # include.
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

      # Counter 0 was the keepalive. The test can make frames only in the
      # sequence of their counters. Thus it makes them first and then sends them
      # out of sequence.
      [one, two, three, edge, genuine, highest] = Enum.map([1, 2, 3, 873, 5_000, 9_000], data)

      # A forgery of the frame with counter 5000. The forgery does not
      # authenticate, so the peer does not commit its counter.
      <<header::binary-16, first, rest::binary>> = genuine
      forged = <<header::binary, Bitwise.bxor(first, 1), rest::binary>>

      # A counter that is 8128 or more less than the highest counter
      # (9000 - 8128 = 872) is stale. The window refuses it before decryption,
      # so it counts as a replay. If the peer decrypted it, it would also fail
      # to authenticate.
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

      # An IP length that is more than the plaintext, and a plaintext that is
      # not IP.
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

      # Data that passes all checks moves the endpoint to its source. The peer
      # then sends to that source.
      send_data(context, context.a, key, inbound(@a_host, port, "roamed"), attacker)
      assert smolnet_recv(udp) == {@a_host, "roamed"}
      {:ok, attacker_port} = :inet.port(attacker)
      assert eventually(fn -> :sys.get_state(key.peer).endpoint == {{127, 0, 0, 1}, attacker_port} end)

      :ok = SmolNet.sendto(udp, "reply", %{family: :inet, addr: @a_host, port: 4_000})
      assert {:ok, {{127, 0, 0, 1}, _port, <<4, _rest::binary>>}} = :gen_udp.recv(attacker, 0, 1_000)

      # A keepalive also moves the endpoint.
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

      # The peers do not have keys yet, so each peer stages its packets.
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

      # The responder has no key to send with until its key is confirmed.
      # REKEY_TIMEOUT prevents an initiation by the responder. Thus the packet
      # waits.
      {udp, _port} = smolnet_udp(context, :inet)
      :ok = SmolNet.sendto(udp, "staged", %{family: :inet, addr: @a_host, port: 9})
      peer = eventually(fn -> peer(context, context.a) end)
      assert eventually(fn -> length(staged(peer)) == 1 end)

      # The remote party roams, and confirms the key from its new address.
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

      # IP lengths of 29, 48, 1283 and 1285. Each length is 28 bytes of headers
      # and the payload.
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

      # The first packet starts the handshake. The other packets wait for its
      # key.
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

    test "each peer gets its share of an egress batch as one message, in order, admitted up to its bound", context do
      a = handshake(context, context.a)
      b = handshake(context, context.b)
      {a_sealer, b_sealer} = {sealer(a.peer), sealer(b.peer)}
      :ok = :sys.suspend(a_sealer)
      :ok = :sys.suspend(b_sealer)

      # One batch from the link. The packets of B are mixed with the packets of
      # A. There are more packets for A than its queue can hold.
      as = for n <- 1..130, do: outbound(@a_host, "a #{n}")
      [b1, b2, b3] = for n <- 1..3, do: outbound(@b_host, "b #{n}")
      batch = [b1 | Enum.take(as, 60)] ++ [b2 | Enum.drop(as, 60)] ++ [b3]
      assert {0, {_interface, egress, _credit}} = Wagyu.Interface.deliver(context.interface, batch)
      assert eventually(fn -> Admission.usage(egress) == {0, 0} end)

      assert message_queue_len(a_sealer) == 1
      assert message_queue_len(b_sealer) == 1
      assert %{egress_routed: 131, egress_peer_dropped: 2} = counters(context.interface)
      peers = :sys.get_state(context.children.interface).peers
      assert {128, _bytes} = Admission.usage(peers[context.a.key].outbound)
      assert {3, _bytes} = Admission.usage(peers[context.b.key].outbound)

      :ok = :sys.resume(a_sealer)
      :ok = :sys.resume(b_sealer)
      assert for(_n <- 1..128, do: receive_payload(context, context.a, a)) == Enum.map(1..128, &"a #{&1}")
      assert for(_n <- 1..3, do: receive_payload(context, context.b, b)) == ["b 1", "b 2", "b 3"]
      assert %{transport_sent: 131} = counters(context.interface, &(&1.transport_sent == 131))
      assert Admission.usage(peers[context.a.key].outbound) == {0, 0}
    end

    @tag mtu: 16_384
    test "staging is bounded in bytes too", context do
      {udp, _port} = smolnet_udp(context, :inet)

      # Packets of 16,028 bytes. 16 of them fit in 256 KiB. The first packet
      # starts the handshake. The other packets wait with it for its key.
      send = fn -> :ok = SmolNet.sendto(udp, :binary.copy("b", 16_000), %{family: :inet, addr: @a_host, port: 9}) end
      send.()
      assert <<1, _rest::binary>> = receive_datagram(context, context.a)
      for _n <- 2..17, do: send.()

      peer = eventually(fn -> peer(context, context.a) end)
      assert %{staged_dropped: 1} = counters(context.interface, &(&1.staged_dropped == 1))
      assert length(staged(peer)) == 16
      assert Admission.usage(:sys.get_state(sealer(peer)).staging) == {16, 256_448}
    end

    # When the test kills the peer, the peer logs its exit.
    @tag :capture_log
    test "staged packets never show in the sealer's status, and count as dropped if the peer exits", context do
      {udp, _port} = smolnet_udp(context, :inet)
      send_egress(udp, 3, @a_host)
      peer = eventually(fn -> peer(context, context.a) end)
      assert eventually(fn -> length(staged(peer)) == 3 end)

      sealer = sealer(peer)

      {:status, ^sealer, _module, [_pdict, _status, _parent, _debug, [_header, _data, {:data, [{~c"State", state}]}]]} =
        :sys.get_status(sealer)

      assert state.staged == :redacted

      monitor = Process.monitor(peer)
      Process.exit(peer, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^peer, :killed}
      assert %{egress_peer_dropped: 3} = counters(context.interface, &(&1.egress_peer_dropped == 3))
    end
  end

  describe "peer group" do
    # When the test kills the sender, the group logs the exit.
    @tag :capture_log
    test "a sender that fails stops its group, and its queued packets count as dropped", context do
      key = handshake(context, context.a)
      interface = context.children.interface
      %{sender: sender, outbound: outbound} = :sys.get_state(interface).peers[context.a.key]
      %{credit: credit} = :sys.get_state(interface)

      # The sealer seals the batch, and the frames wait for the sender. Their
      # packets stay admitted.
      :ok = :sys.suspend(sender)
      batch = for n <- 1..3, do: outbound(@a_host, "queued #{n}")
      assert {0, _admitted} = Wagyu.Interface.deliver(context.interface, batch)
      assert eventually(fn -> match?({3, _bytes}, Admission.usage(outbound)) end)
      %{egress_peer_dropped: dropped} = counters(context.interface)

      monitor = Process.monitor(key.peer)
      Process.exit(sender, :kill)
      assert_receive {:DOWN, ^monitor, :process, _peer, :shutdown}

      assert counters(context.interface, &(&1.egress_peer_dropped == dropped + 3))
      assert eventually(fn -> EgressCredit.outstanding(credit) == {0, 0} end)
      assert IndexTable.lookup(:sys.get_state(interface).indices, key.index) == :retired
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

      # The response still completes the handshake. But its key is already as
      # old as the key of the responder will be. Thus the staged packet does not
      # go out under that key. It waits for a new handshake.
      {response, _session, _sent} = respond_to(initiation, context.a.keypair, 7)
      to_wagyu(context, response, context.a.socket)
      assert <<1, _rest::binary>> = receive_datagram(context, context.a)
      refute_datagram(context.a.socket)
      assert %{current: %{remote_index: 7}} = :sys.get_state(peer)
      assert [_waiting] = staged(peer)
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

      # An outbound packet does not go out under the expired key. It waits for
      # a new handshake.
      :ok = SmolNet.sendto(udp, "too late", %{family: :inet, addr: @a_host, port: 9})
      assert <<1, _rest::binary>> = receive_datagram(context, context.a)
      assert [_one] = staged(key.peer)
      assert %{transport_sent: 1, initiations_sent: 1} = counters(context.interface)
    end

    test "a batch that reaches REJECT_AFTER_MESSAGES sends what it can and stages the rest in order", context do
      key = handshake(context, context.a)
      %{handshake_sent_at: sent_at} = :sys.get_state(key.peer)
      advance(fake_clock(key.peer, sent_at), 5_000)
      sealer = sealer(key.peer)

      :ok =
        in_process(sealer, fn %{key: sealer_key} ->
          Decibel.set_nonce(sealer_key.session, :out, @reject_after_messages - 2)
        end)

      # One batch of four packets. The key can seal only two of them.
      :ok = :sys.suspend(sealer)
      batch = for n <- 1..4, do: outbound(@a_host, "packet #{n}")
      assert {0, _admitted} = Wagyu.Interface.deliver(context.interface, batch)
      assert eventually(fn -> message_queue_len(sealer) == 1 end)
      :ok = :sys.resume(sealer)

      for counter <- [@reject_after_messages - 2, @reject_after_messages - 1] do
        assert <<4, 0, 0, 0, _index::little-32, ^counter::little-64, _rest::binary>> =
                 receive_datagram(context, context.a)
      end

      assert <<1, _rest::binary>> = receive_datagram(context, context.a)
      refute_datagram(context.a.socket)
      assert staged(key.peer) == Enum.drop(batch, 2)

      %{outbound: outbound, staging: staging} = :sys.get_state(context.children.interface).peers[context.a.key]
      assert eventually(fn -> Admission.usage(outbound) == {0, 0} end)
      assert {2, _bytes} = Admission.usage(staging)
      assert %{transport_sent: 2, initiations_sent: 1} = counters(context.interface)
    end

    test "a key sends nothing at REJECT_AFTER_MESSAGES, and the packet waits for a new handshake", context do
      key = handshake(context, context.a)
      {udp, _port} = smolnet_udp(context, :inet)
      # REKEY_TIMEOUT is past since the response of the peer. Thus the peer can
      # initiate.
      %{handshake_sent_at: sent_at} = :sys.get_state(key.peer)
      advance(fake_clock(key.peer, sent_at), 5_000)

      :ok =
        in_process(sealer(key.peer), fn %{key: key} ->
          Decibel.set_nonce(key.session, :out, @reject_after_messages - 1)
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
