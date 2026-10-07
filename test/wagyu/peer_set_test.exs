defmodule Wagyu.PeerSetTest do
  # Changes to the peer set of a running interface: `Wagyu.replace_peers/2`
  # and `Wagyu.revoke_sessions/2`. The test simulates two remote parties
  # with their own UDP sockets and Decibel sessions. The prefixes of B are
  # in the prefixes of A, as in the data path tests. The interface runs on a
  # fake clock.
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.Admission
  alias Wagyu.AllowedIPs
  alias Wagyu.Config
  alias Wagyu.EgressCredit
  alias Wagyu.HandshakeWorker
  alias Wagyu.IndexTable
  alias Wagyu.IP
  alias Wagyu.Noise

  @local {10, 13, 0, 2}
  # An address of A, outside the nested prefix of B.
  @a_host {10, 13, 6, 1}
  # An address of B, which is also in the prefix of A.
  @b_host {10, 13, 5, 1}

  setup context do
    {_public_key, private_key} = keypair()
    a = remote([{{10, 0, 0, 0}, 8}], Map.get(context, :a, %{}))
    b = remote([{{10, 13, 5, 0}, 24}], Map.get(context, :b, %{}))

    options =
      options(
        private_key: private_key,
        stack: [addresses: [{@local, 32}], routes: [{{0, 0, 0, 0}, 0, {10, 13, 0, 1}}], mtu: 1280],
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
      private_key: private_key,
      public_key: public_key,
      port: port,
      stack: stack,
      a: a,
      b: b
    }
  end

  defp remote(allowed_ips, overrides \\ %{}) do
    {public_key, _private_key} = keypair = keypair()
    socket = udp_socket()
    {:ok, port} = :inet.port(socket)
    endpoint = %{address: {127, 0, 0, 1}, port: port}

    %{
      key: public_key,
      keypair: keypair,
      socket: socket,
      endpoint: {{127, 0, 0, 1}, port},
      config: Map.merge(%{public_key: public_key, endpoint: endpoint, allowed_ips: allowed_ips}, overrides)
    }
  end

  # OTP 27 gives a UDP socket an 8 KiB receive buffer. Thus, set the buffer
  # as the interface does.
  defp udp_socket do
    {:ok, socket} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}, active: false, recbuf: 1_048_576])
    socket
  end

  defp interface_state(context), do: :sys.get_state(context.children.interface)

  defp peer(context, %{key: key}) do
    case interface_state(context).peers do
      %{^key => %{pid: pid}} -> pid
      _not_running -> nil
    end
  end

  # Returns the sorted keys of the peer set, or nil while the interface
  # restarts.
  defp info_keys(context) do
    case Wagyu.info(context.interface) do
      {:ok, %{peers: peers}} -> peers |> Enum.map(& &1.public_key) |> Enum.sort()
      {:error, :not_running} -> nil
    end
  end

  defp running?(context, remote) do
    {:ok, %{peers: peers}} = Wagyu.info(context.interface)
    Enum.any?(peers, &(&1.public_key == remote.key and &1.running))
  end

  # The remote party initiates from `from` and confirms the handshake with a
  # keepalive. Returns the transport session of the remote party, the index
  # of the peer and the peer.
  defp handshake(context, remote, n \\ 1, from \\ nil) do
    from = from || remote.socket
    {initiation, session} = initiate_to(context.public_key, remote.keypair, timestamp(n), 77)
    to_wagyu(context, initiation, from)
    response = receive_datagram(context, from)
    assert <<2, 0, 0, 0, index::little-32, 77::little-32, _rest::binary>> = response
    assert complete(session, response) == :ok
    to_wagyu(context, transport_frame(session, index), from)
    peer = eventually(fn -> peer(context, remote) end)
    assert eventually(fn -> match?(%{current: %{local_index: ^index}}, :sys.get_state(peer)) end)
    %{session: session, index: index, peer: peer, initiation: initiation}
  end

  defp to_wagyu(context, frame, from), do: :ok = :gen_udp.send(from, {127, 0, 0, 1}, context.port, frame)

  defp receive_datagram(context, socket) do
    port = context.port
    assert {:ok, {{127, 0, 0, 1}, ^port, frame}} = :gen_udp.recv(socket, 0, 1_000)
    frame
  end

  defp receive_datagram_within(context, socket, timeout) do
    port = context.port
    assert {:ok, {{127, 0, 0, 1}, ^port, frame}} = :gen_udp.recv(socket, 0, timeout)
    frame
  end

  defp refute_datagram(socket), do: assert(:gen_udp.recv(socket, 0, 100) == {:error, :timeout})

  defp smolnet_udp(context) do
    {:ok, socket} = SmolNet.open(:inet, :dgram, :udp, stack: context.stack)
    :ok = SmolNet.bind(socket, %{family: :inet, addr: @local, port: 0})
    {:ok, %{port: port}} = SmolNet.sockname(socket)
    {socket, port}
  end

  defp to_host(socket, destination, payload \\ "hello"),
    do: :ok = SmolNet.sendto(socket, payload, %{family: :inet, addr: destination, port: 9})

  # A packet for a SmolNet socket on `port` from `source`.
  defp inbound(source, port, payload), do: ipv4_udp(source, @local, 4_000, port, payload)

  defp receive_payload(context, socket, key) do
    {:ok, plaintext} = open_transport(key.session, receive_datagram(context, socket))
    {:ok, %{length: length}} = IP.parse(plaintext)
    <<_headers::binary-28, payload::binary>> = binary_part(plaintext, 0, length)
    payload
  end

  defp lookup(context, index), do: IndexTable.lookup(interface_state(context).indices, index)

  defp monitor_exit(pid) do
    monitor = Process.monitor(pid)

    fn reason ->
      assert_receive {:DOWN, ^monitor, :process, ^pid, ^reason}
      :ok
    end
  end

  defp config(context), do: elem(Wagyu.ConfigStore.fetch(context.interface), 1)

  # Waits until the counters stop changing, and returns them.
  defp settled(context) do
    eventually(fn ->
      before = counters(context.interface)
      Process.sleep(50)
      if counters(context.interface) == before, do: before
    end)
  end

  # A pool of keys and nested prefixes, for random peer sets. Each set
  # gives each prefix to one peer at most.
  @prefixes [
    {{0, 0, 0, 0}, 0},
    {{10, 0, 0, 0}, 8},
    {{10, 1, 0, 0}, 16},
    {{10, 1, 2, 0}, 24},
    {{10, 1, 2, 3}, 32},
    {{10, 2, 0, 0}, 16},
    {{192, 168, 0, 0}, 16},
    {{0xFD00, 0, 0, 0, 0, 0, 0, 0}, 8},
    {{0xFD00, 0, 0, 0, 0, 0, 0, 0}, 64},
    {{0xFD00, 0, 0, 0, 0, 0, 0, 1}, 128}
  ]

  defp random_peers(keys) do
    owners = for prefix <- @prefixes, owner = Enum.random([nil | keys]), owner != nil, do: {owner, prefix}

    keys
    |> Enum.filter(fn _key -> :rand.uniform(4) > 1 end)
    |> Enum.map(fn key ->
      %{
        public_key: key,
        allowed_ips: for({^key, prefix} <- owners, do: prefix),
        persistent_keepalive: Enum.random([0, 0, 25])
      }
    end)
  end

  defp kill_and_wait(context, role) do
    old = child(context.interface, role)
    exited = monitor_exit(old)
    Process.exit(old, :kill)
    exited.(:killed)
    eventually(fn -> match?({:ok, _info}, Wagyu.info(context.interface)) and child(context.interface, :interface) end)
  end

  describe "replace_peers/2" do
    test "an invalid peer set changes nothing, and the error gives the first invalid option", context do
      %{a: a, b: b} = context
      {:ok, info} = Wagyu.info(context.interface)
      state = interface_state(context)
      stored = config(context)
      ipv6 = %{address: {0, 0, 0, 0, 0, 0, 0, 1}, port: 1}
      psk = :binary.copy(<<0xA5>>, 31)

      for {peers, path, reason} <- [
            # The caller finds these errors.
            {:not_a_list, [:peers], :invalid},
            {List.duplicate(%{public_key: a.key}, 1025), [:peers], :too_many},
            {[a.config, Map.put(b.config, :preshared_key, psk)], [:peers, 1, :preshared_key], :invalid_length},
            {[a.config, a.config], [:peers, 1, :public_key], :duplicate},
            {[a.config, %{b.config | allowed_ips: [{{10, 1, 2, 3}, 8}]}], [:peers, 1, :allowed_ips, 0], :duplicate},
            {[Map.put(a.config, :keepalive, 25)], [:peers, 0, :keepalive], :unknown},
            # The interface finds these errors, because they need its
            # identity.
            {[a.config, %{public_key: context.public_key}], [:peers, 1, :public_key], :local_key},
            {[a.config, %{public_key: <<0::256>>}], [:peers, 1, :public_key], :invalid},
            {[%{a.config | endpoint: ipv6}], [:peers, 0, :endpoint, :address], :family_mismatch},
            {[%{a.config | endpoint: %{address: {0, 0, 0, 0}, port: 1}}], [:peers, 0, :endpoint, :address], :invalid}
          ] do
        assert {:error, {:invalid_option, ^path, ^reason} = error} = Wagyu.replace_peers(context.interface, peers)
        refute inspect(error, limit: :infinity) =~ inspect(psk, limit: :infinity)
      end

      assert Wagyu.info(context.interface) == {:ok, info}
      assert interface_state(context) == state
      assert config(context) == stored
    end

    test "applies a valid peer set in one call, and info/1 shows it immediately", context do
      c = remote([{{192, 0, 2, 0}, 24}])
      assert :ok = Wagyu.replace_peers(context.interface, [context.b.config, c.config])

      assert info_keys(context) == Enum.sort([context.b.key, c.key])
      {:ok, %{peers: peers}} = Wagyu.info(context.interface)

      assert %{endpoint: %{port: _port}, allowed_ips: [{{192, 0, 2, 0}, 24}]} =
               Enum.find(peers, &(&1.public_key == c.key))

      assert Map.keys(config(context).peers) |> Enum.sort() == Enum.sort([context.b.key, c.key])

      # Egress routes with the new table immediately.
      {socket, _port} = smolnet_udp(context)
      to_host(socket, @a_host)
      to_host(socket, {192, 0, 2, 9})
      assert %{egress_unroutable: 1, egress_routed: 1} = counters(context.interface, &(&1.egress_routed == 1))
    end

    test "returns :not_running when no interface runs, and checks the peers first" do
      assert Wagyu.replace_peers(:wagyu_peer_set_test_none, []) == {:error, :not_running}
      assert Wagyu.replace_peers(self(), []) == {:error, :not_running}

      assert Wagyu.replace_peers(:wagyu_peer_set_test_none, [%{}]) ==
               {:error, {:invalid_option, [:peers, 0, :public_key], :missing}}
    end

    test "an added peer starts when traffic needs it, and one with a persistent keepalive starts immediately",
         context do
      c = remote([{{192, 0, 2, 0}, 24}])
      d = remote([{{198, 51, 100, 0}, 24}], %{persistent_keepalive: 25})
      :ok = Wagyu.replace_peers(context.interface, [context.a.config, context.b.config, c.config])

      refute running?(context, c)
      {socket, _port} = smolnet_udp(context)
      to_host(socket, {192, 0, 2, 9})
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context, c.socket)
      assert running?(context, c)

      :ok = Wagyu.replace_peers(context.interface, [context.a.config, context.b.config, c.config, d.config])
      assert running?(context, d)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context, d.socket)
    end

    test "a removed peer is forgotten, and its traffic, handshakes and restarts are refused", context do
      %{a: a, b: b} = context
      key = handshake(context, a)
      %{credit: credit} = interface_state(context)

      # Packets wait in the queue of the peer, and hold egress credit.
      {socket, _port} = smolnet_udp(context)
      :ok = :sys.suspend(key.peer)
      for _n <- 1..3, do: to_host(socket, @a_host)
      %{outbound: outbound} = interface_state(context).peers[a.key]
      assert eventually(fn -> match?({3, _bytes}, Admission.usage(outbound)) end)
      exited = monitor_exit(key.peer)
      %{egress_peer_dropped: dropped} = counters(context.interface)

      assert :ok = Wagyu.replace_peers(context.interface, [b.config])

      # The interface stops the process. It drops and counts the queued
      # packets, and retires their credit.
      exited.(:shutdown)
      state = interface_state(context)
      refute Map.has_key?(state.peers, a.key)
      refute Map.has_key?(state.endpoints, a.key)
      assert Map.values(state.monitors) == []
      assert %{egress_peer_dropped: after_drop} = counters(context.interface)
      assert after_drop == dropped + 3
      assert eventually(fn -> EgressCredit.outstanding(credit) == {0, 0} end)
      assert info_keys(context) == [b.key]

      # The index of the old session is a tombstone, and egress to the old
      # prefixes is unroutable.
      assert lookup(context, key.index) == :retired
      to_wagyu(context, transport_frame(key.session, key.index, inbound(@a_host, 9, "late")), a.socket)
      to_host(socket, @a_host)

      # A new initiation authenticates, but the key is not configured.
      advance(context.clock, 1_000)
      to_wagyu(context, noise_initiation(context.public_key, a.keypair, timestamp(2)), a.socket)

      assert %{unknown_index: 1, egress_unroutable: 1, initiations_unknown_peer: 1} =
               counters(context.interface, &(&1.initiations_unknown_peer == 1 and &1.unknown_index == 1))

      # A restart that was pending for the key does nothing.
      interface = context.children.interface
      send(interface, {:restart_peer, a.key})
      assert interface_state(context).peers == %{}
      assert child(context.interface, :interface) == interface
      refute_datagram(a.socket)
    end

    test "a claim in progress during a removal does not crash the interface", context do
      %{a: a} = context
      {:ok, identity} = Config.new(private_key: context.private_key)
      frame = noise_initiation(context.public_key, a.keypair, timestamp(1))

      # The worker claims the peer, and then the key is removed before the
      # worker hands off its session.
      claim = fn remote_key, timestamp ->
        claimed = Wagyu.Interface.claim_peer(context.interface, remote_key, timestamp)
        :ok = Wagyu.replace_peers(context.interface, [context.b.config])
        claimed
      end

      responder = &Noise.responder(identity, &1)
      session = responder.(<<0::256>>)
      test = self()

      claim = fn remote_key, timestamp ->
        result = claim.(remote_key, timestamp)
        send(test, {:claimed, result})
        result
      end

      # The old process can stop before the handoff, or after it with the
      # ticket in its mailbox.
      result = HandshakeWorker.respond(session, frame, {{127, 0, 0, 1}, 9}, claim, responder)
      assert match?({:ok, _old}, result) or result == {:error, :handoff_failed}
      assert_received {:claimed, {:ok, old, _config}}
      assert eventually(fn -> not Process.alive?(old) end)
      refute_datagram(a.socket)

      # A claim after the removal does not find the key.
      advance(context.clock, 1_000)
      assert Wagyu.Interface.claim_peer(context.interface, a.key, timestamp(2)) == {:error, :unknown_peer}
      assert %{initiations_accepted: 1, initiations_unknown_peer: 1} = counters(context.interface)
      assert interface_state(context).peers == %{}
    end

    test "a change of AllowedIPs moves the routes and gives each affected peer a new source filter", context do
      %{a: a, b: b} = context
      key_a = handshake(context, a)
      key_b = handshake(context, b)
      {socket, port} = smolnet_udp(context)
      %{initiations_sent: initiated, responses_sent: responded} = counters(context.interface)

      # B moves to a different prefix inside the prefix of A. The filter of A
      # changes with it.
      moved = %{b.config | allowed_ips: [{{10, 13, 7, 0}, 24}]}
      :ok = Wagyu.replace_peers(context.interface, [a.config, moved])
      %{config: %{allowed_ips: table}} = interface_state(context)

      for {remote, key} <- [{a, key_a}, {b, key_b}] do
        assert %{allowed_ips: filter, configured: 1, current: %{local_index: index}} = :sys.get_state(key.peer)
        assert filter == AllowedIPs.source_filter(table, remote.key)
        assert index == key.index
        assert peer(context, remote) == key.peer
      end

      # A can now send from the old prefix of B, and B cannot.
      to_wagyu(context, transport_frame(key_a.session, key_a.index, inbound(@b_host, port, "from a")), a.socket)
      assert {:ok, %{data: "from a"}} = SmolNet.recvfrom(socket, 0, 1_000)
      to_wagyu(context, transport_frame(key_b.session, key_b.index, inbound(@b_host, port, "from b")), b.socket)
      assert %{transport_source_denied: 1} = counters(context.interface, &(&1.transport_source_denied == 1))

      # Egress follows the new routes.
      to_host(socket, @b_host, "to a")
      assert receive_payload(context, a.socket, key_a) == "to a"
      to_host(socket, {10, 13, 7, 9}, "to b")
      assert receive_payload(context, b.socket, key_b) == "to b"

      # A peer whose configuration and filter stay gets nothing. No change
      # starts a handshake.
      c = remote([{{192, 0, 2, 0}, 24}])
      :ok = Wagyu.replace_peers(context.interface, [a.config, moved, c.config])
      assert %{configured: 1} = :sys.get_state(key_a.peer)
      assert %{configured: 1} = :sys.get_state(key_b.peer)
      assert %{initiations_sent: ^initiated, responses_sent: ^responded} = settled(context)
    end

    test "a change keeps the staged packets, timers and process of a peer", context do
      %{a: a, b: b} = context
      {socket, _port} = smolnet_udp(context)
      to_host(socket, @b_host)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context, b.socket)
      peer = eventually(fn -> peer(context, b) end)
      assert eventually(fn -> :queue.len(:sys.get_state(peer).staged) == 1 end)
      %{timers: timers, initiation: initiation} = :sys.get_state(peer)

      :ok = Wagyu.replace_peers(context.interface, [a.config, %{b.config | allowed_ips: [{{10, 13, 5, 0}, 25}]}])

      assert %{configured: 1, timers: ^timers, initiation: ^initiation} = state = :sys.get_state(peer)
      assert :queue.len(state.staged) == 1
      assert peer(context, b) == peer
      refute_datagram(b.socket)
      assert %{initiations_sent: 1} = counters(context.interface)
    end

    test "a new endpoint replaces the current and the learned endpoint, and nil keeps it", context do
      %{a: a, b: b} = context
      roamed = udp_socket()
      {:ok, roamed_port} = :inet.port(roamed)
      key = handshake(context, a, 1, roamed)
      assert eventually(fn -> interface_state(context).endpoints[a.key] == {{127, 0, 0, 1}, roamed_port} end)

      moved = udp_socket()
      {:ok, moved_port} = :inet.port(moved)
      moved_config = %{a.config | endpoint: %{address: {127, 0, 0, 1}, port: moved_port}}
      :ok = Wagyu.replace_peers(context.interface, [moved_config, b.config])

      assert :sys.get_state(key.peer).endpoint == {{127, 0, 0, 1}, moved_port}
      assert eventually(fn -> interface_state(context).endpoints[a.key] == {{127, 0, 0, 1}, moved_port} end)
      {socket, _port} = smolnet_udp(context)
      to_host(socket, @a_host, "moved")
      assert receive_payload(context, moved, key) == "moved"

      # A change to nil keeps the current endpoint.
      :ok = Wagyu.replace_peers(context.interface, [%{a.config | endpoint: nil}, b.config])
      assert :sys.get_state(key.peer).endpoint == {{127, 0, 0, 1}, moved_port}
      to_host(socket, @a_host, "still moved")
      assert receive_payload(context, moved, key) == "still moved"
    end

    test "a change of the endpoint to nil keeps the configured endpoint for the next process", context do
      %{a: a, b: b} = context
      {socket, _port} = smolnet_udp(context)

      # A runs, and has not learned an endpoint. B does not run.
      to_host(socket, @a_host)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context, a.socket)
      assert interface_state(context).endpoints == %{}

      :ok = Wagyu.replace_peers(context.interface, [%{a.config | endpoint: nil}, %{b.config | endpoint: nil}])
      :ok = Wagyu.revoke_sessions(context.interface, a.key)

      # The next processes initiate to the endpoints from the old
      # configuration.
      to_host(socket, @a_host)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context, a.socket)
      to_host(socket, @b_host)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context, b.socket)
      assert %{initiations_no_endpoint: 0} = counters(context.interface)
    end

    test "a peer reports its endpoint again after a change, so a report that the change made old is not lost",
         context do
      %{a: a, b: b} = context
      roamed = udp_socket()
      {:ok, roamed_port} = :inet.port(roamed)
      handshake(context, a, 1, roamed)
      assert eventually(fn -> interface_state(context).endpoints[a.key] == {{127, 0, 0, 1}, roamed_port} end)

      # The interface ignored the report, as it does for a report that
      # arrives after the configure message.
      :sys.replace_state(context.children.interface, &%{&1 | endpoints: %{}})
      :ok = Wagyu.replace_peers(context.interface, [Map.put(a.config, :persistent_keepalive, 25), b.config])

      assert eventually(fn -> interface_state(context).endpoints[a.key] == {{127, 0, 0, 1}, roamed_port} end)
    end

    test "a new endpoint also replaces the endpoint that the interface keeps for a stopped peer", context do
      %{a: a, b: b} = context
      roamed = udp_socket()
      key = handshake(context, b, 1, roamed)
      :ok = Wagyu.revoke_sessions(context.interface, b.key)
      assert {:ok, roamed_port} = :inet.port(roamed)
      assert interface_state(context).endpoints[b.key] == {{127, 0, 0, 1}, roamed_port}
      refute Process.alive?(key.peer)

      moved = udp_socket()
      {:ok, moved_port} = :inet.port(moved)

      :ok =
        Wagyu.replace_peers(context.interface, [
          a.config,
          %{b.config | endpoint: %{address: {127, 0, 0, 1}, port: moved_port}}
        ])

      refute Map.has_key?(interface_state(context).endpoints, b.key)

      {socket, _port} = smolnet_udp(context)
      to_host(socket, @b_host)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context, moved)
      refute_datagram(roamed)
    end

    test "a new persistent keepalive arms the timer again, and a change to 0 cancels it", context do
      %{a: a, b: b} = context
      key = handshake(context, a)
      clock = fake_clock(key.peer)
      now = :atomics.get(clock, 1)

      :ok = Wagyu.replace_peers(context.interface, [Map.put(a.config, :persistent_keepalive, 25), b.config])
      assert %{persistent_keepalive: 25_000, timers: %{persistent_keepalive: deadline}} = :sys.get_state(key.peer)
      assert deadline == now + 25_000

      advance(clock, 1_000)
      :ok = Wagyu.replace_peers(context.interface, [Map.put(a.config, :persistent_keepalive, 30), b.config])
      assert %{timers: %{persistent_keepalive: deadline}} = :sys.get_state(key.peer)
      assert deadline == now + 31_000

      :ok = Wagyu.replace_peers(context.interface, [a.config, b.config])
      assert %{persistent_keepalive: 0, timers: timers} = :sys.get_state(key.peer)
      refute Map.has_key?(timers, :persistent_keepalive)
    end

    test "a keepalive change from 0 starts the peer, and a change to 0 stops its restarts", context do
      %{a: a, b: b} = context
      refute running?(context, b)

      :ok = Wagyu.replace_peers(context.interface, [a.config, Map.put(b.config, :persistent_keepalive, 25)])
      assert running?(context, b)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context, b.socket)

      :ok = Wagyu.replace_peers(context.interface, [a.config, b.config])
      peer = peer(context, b)
      exited = monitor_exit(peer)
      Process.exit(peer, :kill)
      exited.(:killed)

      # A peer with a persistent keepalive starts again 1 second after it
      # fails. This peer no longer has one.
      Process.sleep(1_200)
      refute running?(context, b)
    end

    test "a new preshared key applies to new handshakes, and the current sessions stay", context do
      %{a: a, b: b} = context
      key = handshake(context, a)
      psk = :crypto.strong_rand_bytes(32)

      :ok = Wagyu.replace_peers(context.interface, [Map.put(a.config, :preshared_key, psk), b.config])
      assert %{current: %{local_index: index}, peer: %{preshared_key: ^psk}} = :sys.get_state(key.peer)
      assert index == key.index

      # The current session still carries traffic both ways.
      {socket, port} = smolnet_udp(context)
      to_wagyu(context, transport_frame(key.session, key.index, inbound(@a_host, port, "old")), a.socket)
      assert {:ok, %{data: "old"}} = SmolNet.recvfrom(socket, 0, 1_000)
      to_host(socket, @a_host, "old")
      assert receive_payload(context, a.socket, key) == "old"

      # A handshake that A starts uses the new key.
      advance(context.clock, 1_000)
      {initiation, session} = initiate_to(context.public_key, a.keypair, timestamp(2), 78, psk)
      to_wagyu(context, initiation, a.socket)
      response = receive_datagram(context, a.socket)
      assert complete(session, response) == :ok

      # A handshake that the peer starts uses the new key.
      clock = fake_clock(key.peer)
      advance(clock, 5_000)
      send(key.peer, :wg_initiate)
      {response, _session, _sent} = respond_to(receive_datagram(context, a.socket), a.keypair, 79, psk)
      to_wagyu(context, response, a.socket)
      assert %{responses_accepted: 1, responses_invalid: 0} = counters(context.interface, &(&1.responses_accepted == 1))
    end

    test "a different public key is a removal and an addition", context do
      %{a: a, b: b} = context
      key = handshake(context, a)
      exited = monitor_exit(key.peer)
      {other, _private_key} = keypair()

      :ok = Wagyu.replace_peers(context.interface, [%{a.config | public_key: other}, b.config])

      exited.(:shutdown)
      assert info_keys(context) == Enum.sort([other, b.key])
      refute running?(context, a)
      assert lookup(context, key.index) == :retired
    end
  end

  describe "revoke_sessions/2" do
    test "stops the process of a peer, and keeps its configuration, routes, endpoint and timestamps", context do
      %{a: a} = context
      roamed = udp_socket()
      key = handshake(context, a, 1, roamed)
      {socket, _port} = smolnet_udp(context)
      :ok = :sys.suspend(key.peer)
      for _n <- 1..2, do: to_host(socket, @a_host)
      %{outbound: outbound} = interface_state(context).peers[a.key]
      assert eventually(fn -> match?({2, _bytes}, Admission.usage(outbound)) end)
      exited = monitor_exit(key.peer)
      before = interface_state(context)
      stored = config(context)

      assert :ok = Wagyu.revoke_sessions(context.interface, a.key)

      exited.(:shutdown)
      state = interface_state(context)
      assert state.config == before.config
      assert config(context) == stored
      assert state.endpoints[a.key] == before.endpoints[a.key]
      assert state.initiations[a.key] == before.initiations[a.key]
      refute Map.has_key?(state.peers, a.key)
      assert lookup(context, key.index) == :retired
      assert %{egress_peer_dropped: 2} = counters(context.interface)

      # The next packet starts a new process. It initiates to the endpoint
      # that the old process learned, and completes a new handshake.
      to_host(socket, @a_host, "again")
      initiation = receive_datagram(context, roamed)
      {response, session, _sent} = respond_to(initiation, a.keypair, 80)
      to_wagyu(context, response, roamed)
      assert receive_payload(context, roamed, %{session: session}) == "again"
      assert peer(context, a) not in [nil, key.peer]
    end

    test "returns :ok and changes nothing for a peer that has no process", context do
      state = interface_state(context)
      assert :ok = Wagyu.revoke_sessions(context.interface, context.b.key)
      assert interface_state(context) == state
    end

    test "returns :unknown_peer for a key that is not configured, and :not_running without an interface", context do
      {other, _private_key} = keypair()
      assert Wagyu.revoke_sessions(context.interface, other) == {:error, :unknown_peer}
      assert Wagyu.revoke_sessions(context.interface, :not_a_key) == {:error, :unknown_peer}
      assert Wagyu.revoke_sessions(context.interface, context.public_key) == {:error, :unknown_peer}
      assert Wagyu.revoke_sessions(:wagyu_peer_set_test_none, other) == {:error, :not_running}
    end

    @tag a: %{persistent_keepalive: 25}
    test "starts a peer with a persistent keepalive again immediately", context do
      %{a: a} = context
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context, a.socket)
      old = peer(context, a)
      exited = monitor_exit(old)

      assert :ok = Wagyu.revoke_sessions(context.interface, a.key)

      new = peer(context, a)
      assert new not in [nil, old]
      exited.(:shutdown)
      # The new process sends its first keepalive, which starts a handshake,
      # without the delay of a restart.
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context, a.socket)
    end

    @tag a: %{persistent_keepalive: 25}
    test "tries again later to start a peer with a persistent keepalive that cannot start", context do
      %{a: a} = context
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context, a.socket)
      supervisor = context.children.peer_supervisor

      # The peer supervisor has no free slot, as when it still counts the
      # stopped process.
      :sys.replace_state(supervisor, &%{&1 | max_children: 0})
      :ok = Wagyu.revoke_sessions(context.interface, a.key)
      refute running?(context, a)

      :sys.replace_state(supervisor, &%{&1 | max_children: 1024})
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram_within(context, a.socket, 3_000)
      assert running?(context, a)
    end

    test "egress to the peer always has a route, during and after the call", context do
      %{a: a} = context
      {socket, _port} = smolnet_udp(context)
      sender = Task.async(fn -> for _n <- 1..200, do: to_host(socket, @a_host) end)

      for _n <- 1..10 do
        assert :ok = Wagyu.revoke_sessions(context.interface, a.key)
        Process.sleep(2)
      end

      Task.await(sender)
      counters = counters(context.interface, &(&1.egress == 200 and &1.egress_routed + &1.egress_dropped == 200))
      assert counters.egress_unroutable == 0
      assert counters.egress_routed > 0
    end

    test "a session from a claim before the call goes to the stopped process and carries no traffic", context do
      %{a: a} = context
      {:ok, identity} = Config.new(private_key: context.private_key)
      {frame, initiator} = initiate_to(context.public_key, a.keypair, timestamp(1), 77)

      claim = fn remote_key, timestamp ->
        claimed = Wagyu.Interface.claim_peer(context.interface, remote_key, timestamp)
        :ok = Wagyu.revoke_sessions(context.interface, remote_key)
        claimed
      end

      responder = &Noise.responder(identity, &1)
      session = responder.(<<0::256>>)
      result = HandshakeWorker.respond(session, frame, a.endpoint, claim, responder)

      # The old process can stop before the handoff, or after it with the
      # ticket in its mailbox. In both cases, no response goes out.
      assert match?({:ok, _old}, result) or result == {:error, :handoff_failed}
      refute_datagram(a.socket)
      assert interface_state(context).peers == %{}
      :ok = Decibel.close(initiator)

      # A new initiation makes a new process, which responds.
      advance(context.clock, 1_000)
      {frame, initiator} = initiate_to(context.public_key, a.keypair, timestamp(2), 78)
      to_wagyu(context, frame, a.socket)
      assert complete(initiator, receive_datagram(context, a.socket)) == :ok
    end
  end

  describe "replay timestamps" do
    test "a removed key keeps its timestamps, so a replay is refused after the key is added again", context do
      %{a: a, b: b} = context
      key = handshake(context, a)
      %{initiations: %{} = initiations, sent: sent} = interface_state(context)

      :ok = Wagyu.replace_peers(context.interface, [b.config])
      assert :queue.to_list(interface_state(context).removed) == [a.key]
      :ok = Wagyu.replace_peers(context.interface, [a.config, b.config])
      assert %{initiations: ^initiations, sent: ^sent, removed: removed} = interface_state(context)
      assert :queue.is_empty(removed)

      advance(context.clock, 1_000)
      to_wagyu(context, key.initiation, a.socket)

      assert %{initiations_replayed: 1, initiations_accepted: 1} =
               counters(context.interface, &(&1.initiations_replayed == 1))

      refute_datagram(a.socket)

      # A newer initiation is accepted.
      to_wagyu(context, noise_initiation(context.public_key, a.keypair, timestamp(2)), a.socket)
      assert %{initiations_accepted: 2} = counters(context.interface, &(&1.initiations_accepted == 2))
    end

    test "the timestamps of at most 1024 removed keys stay, and the first removal goes first", context do
      interface = context.children.interface
      keys = for _n <- 1..1024, do: elem(keypair(), 0)
      [first | rest] = keys
      peers = Enum.map(keys, &%{public_key: &1})
      :ok = Wagyu.replace_peers(context.interface, peers)

      # Each key has timestamps, as after an accepted initiation.
      entry = %{timestamp: timestamp(1), accepted_at: 0}
      :sys.replace_state(interface, &%{&1 | initiations: Map.new(keys, fn key -> {key, entry} end)})

      :ok = Wagyu.replace_peers(context.interface, tl(peers))
      {late, _private_key} = keypair()
      :ok = Wagyu.replace_peers(context.interface, [%{public_key: late}])
      assert %{removed: removed, initiations: initiations} = interface_state(context)
      assert :queue.len(removed) == 1024
      assert :queue.head(removed) == first
      assert map_size(initiations) == 1024

      # One more removal discards the timestamps of the first removed key.
      :sys.replace_state(interface, &put_in(&1.sent[late], timestamp(1)))
      :ok = Wagyu.replace_peers(context.interface, [])
      assert %{removed: removed, initiations: initiations, sent: sent} = interface_state(context)
      assert :queue.len(removed) == 1024
      refute Map.has_key?(initiations, first)
      assert Map.has_key?(initiations, hd(rest))
      assert Map.has_key?(sent, late)

      # A key that is added again leaves the removed set with its timestamps.
      :ok = Wagyu.replace_peers(context.interface, [%{public_key: hd(rest)}])
      assert %{removed: removed, initiations: %{} = initiations} = interface_state(context)
      assert :queue.len(removed) == 1023
      refute :queue.member(hd(rest), removed)
      assert initiations[hd(rest)] == entry
    end
  end

  describe "the source filter of each running peer" do
    test "is the filter of the final table after a random sequence of peer sets", context do
      keys = for _n <- 1..6, do: elem(keypair(), 0)
      interface = context.children.interface

      for _round <- 1..40 do
        sets = for _n <- 1..Enum.random(1..5), do: random_peers(keys)
        for peers <- sets, do: assert(:ok = Wagyu.replace_peers(context.interface, peers))

        %{peers: running, config: %{allowed_ips: table}} = :sys.get_state(interface)
        assert table == elem(Config.put_peers(config(context), List.last(sets)), 1).allowed_ips

        for {key, %{pid: pid, filter: filter}} <- running do
          assert filter == AllowedIPs.source_filter(table, key)
          assert :sys.get_state(pid).allowed_ips == filter
        end
      end
    end
  end

  describe "restarts" do
    # When a test kills a process, the process logs its exit.
    @describetag :capture_log

    setup context do
      c = remote([{{192, 0, 2, 0}, 24}])
      :ok = Wagyu.replace_peers(context.interface, [context.b.config, c.config])
      %{expected: Enum.sort([context.b.key, c.key]), started: Enum.sort([context.a.key, context.b.key])}
    end

    test "an interface restart keeps the latest peer set", context do
      old = context.children.interface
      kill_and_wait(context, :interface)
      assert child(context.interface, :interface) != old
      assert info_keys(context) == context.expected
    end

    test "a link restart keeps the latest peer set", context do
      kill_and_wait(context, :link)
      assert {:ok, stack} = Wagyu.stack(context.interface)
      refute stack == context.stack
      assert info_keys(context) == context.expected
    end

    test "a stack stopped with SmolNet.stop_stack/1 keeps the latest peer set", context do
      monitor = SmolNet.monitor(context.stack)
      :ok = SmolNet.stop_stack(context.stack)
      assert_receive {:DOWN, ^monitor, :process, _object, _reason}

      assert eventually(fn ->
               match?({:ok, stack} when stack != context.stack, Wagyu.stack(context.interface)) and
                 match?({:ok, _info}, Wagyu.info(context.interface))
             end)

      assert info_keys(context) == context.expected
    end

    test "a failure of the configuration store goes back to the start options", context do
      kill_and_wait(context, :config)
      assert eventually(fn -> info_keys(context) == context.started end)
      assert {:ok, stack} = Wagyu.stack(context.interface)
      refute stack == context.stack
    end
  end

  describe "secrets" do
    test "the status of the processes and their messages hide the new preshared keys", context do
      psk = :crypto.strong_rand_bytes(32)
      peer = handshake(context, context.a).peer
      %{interface: interface, config: store} = context.children
      for pid <- [interface, store, peer], do: :ok = :sys.log(pid, true)

      :ok = Wagyu.replace_peers(context.interface, [Map.put(context.a.config, :preshared_key, psk), context.b.config])
      assert %{peer: %{preshared_key: ^psk}} = :sys.get_state(peer)

      # The raw debug data in the status (#20) and `Inspect` hide the keys
      # when the status is printed. The formatted state and log, which crash
      # reports also show, do not contain them in any form.
      for pid <- [interface, store, peer] do
        {:status, _pid, _module, [_dictionary, _sys_state, _parent, _debug, formatted]} =
          status = :sys.get_status(pid)

        {:ok, log} = :sys.log(pid, :get)
        assert log != []
        inspected = inspect(status, limit: :infinity, printable_limit: :infinity)
        terms = IO.iodata_to_binary(:io_lib.format(~c"~w", [formatted]))
        assert terms =~ "redacted"

        for form <- [inspect(psk, binaries: :as_binaries, limit: :infinity), Base.encode16(psk)] do
          refute inspected =~ form
        end

        refute terms =~ IO.iodata_to_binary(:io_lib.format(~c"~w", [psk]))
      end

      # The redaction also covers the last message of a crash report.
      message = {:"$gen_call", {self(), make_ref()}, {:replace_peers, [%Config.Peer{public_key: context.a.key}]}}

      assert %{message: {:"$gen_call", _from, {:replace_peers, :redacted}}} =
               Wagyu.Interface.format_status(%{message: message})

      config = config(context)

      assert %{message: {:"$gen_call", _from, {:put, :redacted}}} =
               Wagyu.ConfigStore.format_status(%{message: {:"$gen_call", {self(), make_ref()}, {:put, config}}})

      assert %{message: {:wg_configure, :redacted, %AllowedIPs{}}} =
               Wagyu.Peer.format_status(%{message: {:wg_configure, config.peers[context.a.key], %AllowedIPs{}}})
    end
  end
end
