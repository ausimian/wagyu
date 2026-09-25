defmodule Wagyu.PeerTest do
  # A peer's handshakes with a remote party that the test plays, with its
  # own UDP socket and Decibel sessions: initiating on outbound demand,
  # responding, key confirmation and the key slots. The interface runs on a
  # fake clock, and so does the peer once it has started.
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.IndexTable
  alias Wagyu.Packet
  alias Wagyu.TAI64N

  setup context do
    {_public_key, private_key} = keypair()
    {remote_key, _private_key} = remote = keypair()
    {:ok, remote_socket} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}, active: false])
    {:ok, remote_port} = :inet.port(remote_socket)
    endpoint = unless context[:no_endpoint], do: %{address: {127, 0, 0, 1}, port: remote_port}
    peers = [%{public_key: remote_key, endpoint: endpoint, allowed_ips: [{{0, 0, 0, 0}, 0}]}]
    options = options(private_key: private_key, peers: peers)

    Map.merge(start_interface(options), %{
      options: options,
      remote: remote,
      remote_key: remote_key,
      remote_socket: remote_socket,
      remote_endpoint: {{127, 0, 0, 1}, remote_port}
    })
  end

  defp start_interface(options) do
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
      udp: open_udp(stack)
    }
  end

  # An outbound packet for the remote party.
  defp demand(context), do: send_egress(context.udp, 1)

  defp peer(%{remote_key: key} = context) do
    case :sys.get_state(context.children.interface).peers do
      %{^key => %{pid: pid}} -> pid
      _not_running -> nil
    end
  end

  # Waits for the peer to start and puts it on a fake clock.
  defp started_peer(context) do
    pid = eventually(fn -> peer(context) end)
    {pid, fake_peer_clock(pid)}
  end

  # The fake clock starts when the peer last sent a handshake message, once
  # it has finished what it was doing, so REKEY_TIMEOUT runs from there.
  defp fake_peer_clock(pid) do
    %{handshake_sent_at: sent_at} = :sys.get_state(pid)
    fake_clock(pid, sent_at || System.monotonic_time(:millisecond))
  end

  defp to_wagyu(context, frame, from \\ nil),
    do: :ok = :gen_udp.send(from || context.remote_socket, {127, 0, 0, 1}, context.port, frame)

  # The next datagram the remote party receives, which must come from the
  # interface's socket.
  defp receive_datagram(context) do
    port = context.port
    assert {:ok, {{127, 0, 0, 1}, ^port, frame}} = :gen_udp.recv(context.remote_socket, 0, 1_000)
    frame
  end

  defp refute_datagram(context), do: assert(:gen_udp.recv(context.remote_socket, 0, 100) == {:error, :timeout})

  defp lookup(context, index), do: IndexTable.lookup(:sys.get_state(context.children.interface).indices, index)

  defp sender_index(<<_type, 0, 0, 0, index::little-32, _rest::binary>>), do: index

  # Waits until the peer has taken `count` more frames off its mailbox.
  defp dropped_after(peer, before, count),
    do: eventually(fn -> :sys.get_state(peer).inbound_dropped == before + count end)

  defp kill(pid) do
    monitor = Process.monitor(pid)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :killed}
  end

  defp strictly_increasing?(timestamps),
    do: timestamps |> Enum.chunk_every(2, 1, :discard) |> Enum.all?(fn [a, b] -> TAI64N.after?(b, a) end)

  describe "initiating" do
    test "outbound demand starts a handshake, and the staged packet confirms the key", context do
      demand(context)
      initiation = receive_datagram(context)
      {peer, _clock} = started_peer(context)

      # The initiation comes from a live index and carries a wall-clock
      # timestamp, never one ahead of the time it was sent.
      assert <<1, 0, 0, 0, index::little-32, _rest::binary-140>> = initiation
      assert %{initiation: %{local_index: ^index}, current: nil} = :sys.get_state(peer)
      assert lookup(context, index) == {:active, {context.remote_key, peer}}

      {response, session, sent} = respond_to(initiation, context.remote, 99)
      assert sent.initiator_key == context.public_key
      assert sent.sender_index == index
      {:ok, at} = TAI64N.to_unix(sent.timestamp)
      assert at <= System.os_time(:nanosecond)
      assert System.os_time(:nanosecond) - at < 2_000_000_000

      # The response completes the handshake, and the packet that started
      # it, sent to the responder's index, confirms the key.
      to_wagyu(context, response)
      confirmation = receive_datagram(context)
      assert <<4, 0, 0, 0, 99::little-32, 0::little-64, _rest::binary>> = confirmation
      assert {:ok, plaintext} = open_transport(session, confirmation)
      assert {:ok, %{destination: {192, 0, 2, 9}, length: length}} = Wagyu.IP.parse(plaintext)
      assert plaintext == binary_part(plaintext, 0, length) <> <<0::size((byte_size(plaintext) - length) * 8)>>

      assert %{initiation: nil, next: nil, previous: nil, current: %{local_index: ^index, remote_index: 99}} =
               :sys.get_state(peer)

      assert %{initiations_sent: 1, responses_accepted: 1, keepalives_sent: 0, transport_sent: 1} =
               counters(context.interface)

      # With a current key, outbound packets go straight out under it and
      # start no more handshakes.
      demand(context)
      assert <<4, 0, 0, 0, 99::little-32, 1::little-64, _rest::binary>> = next = receive_datagram(context)
      assert {:ok, _plaintext} = open_transport(session, next)
      refute_datagram(context)
    end

    test "a response with the wrong index, MAC1 or authentication changes nothing", context do
      demand(context)
      initiation = receive_datagram(context)
      index = sender_index(initiation)
      {peer, _clock} = started_peer(context)
      {response, session, _sent} = respond_to(initiation, context.remote, 99)
      before = :sys.get_state(peer)

      mac1_key = Packet.mac1_key(context.public_key)
      {:ok, genuine} = Packet.decode(response)
      remac = fn message -> message |> Packet.encode() |> Packet.put_mac1(mac1_key) end
      <<covered::binary-60, mac1::binary-16, mac2::binary-16>> = response
      <<first, rest::binary>> = genuine.encrypted_nothing

      # From a different address, which must not become the endpoint.
      {:ok, attacker} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}, active: false])

      for forged <- [
            # Another index, re-MACed: dropped at the interface.
            remac.(%{genuine | receiver_index: Bitwise.bxor(index, 1)}),
            # A bad MAC1: dropped at the interface.
            <<covered::binary, :crypto.exor(mac1, <<1::128>>)::binary, mac2::binary>>,
            # Right index and MAC1, but it does not authenticate.
            remac.(%{genuine | encrypted_nothing: <<Bitwise.bxor(first, 1), rest::binary>>}),
            # An all-zero ephemeral key, which X25519 rejects.
            remac.(%{genuine | ephemeral: <<0::256>>}),
            # A transport message for the initiation's index.
            <<4, 0, 0, 0, index::little-32, 0::little-64, 0::128>>
          ] do
        to_wagyu(context, forged, attacker)
      end

      assert %{unknown_index: 1, invalid_mac1: 1, responses_invalid: 2, transport_invalid: 1} =
               counters(context.interface, &(&1.responses_invalid == 2 and &1.transport_invalid == 1))

      dropped_after(peer, before.inbound_dropped, 3)

      assert Process.alive?(peer)
      assert peer(context) == peer
      after_forgeries = :sys.get_state(peer)

      for field <- [:initiation, :endpoint, :next, :current, :previous, :handshake_sent_at] do
        assert Map.fetch!(after_forgeries, field) == Map.fetch!(before, field)
      end

      assert :gen_udp.recv(attacker, 0, 100) == {:error, :timeout}

      # The genuine response still completes the handshake.
      to_wagyu(context, response)
      assert {:ok, _confirmation} = open_transport(session, receive_datagram(context))
      assert %{current: %{local_index: ^index}, endpoint: endpoint} = :sys.get_state(peer)
      assert endpoint == context.remote_endpoint
    end

    test "a response to a replaced initiation, or a replayed one, is dropped", context do
      demand(context)
      first = receive_datagram(context)
      {peer, clock} = started_peer(context)
      %{initiation: %{session: first_session}} = :sys.get_state(peer)
      {late_response, _session, _sent} = respond_to(first, context.remote, 11)

      # No handshake message goes out within REKEY_TIMEOUT of the last one.
      send(peer, :wg_initiate)
      advance(clock, 4_999)
      send(peer, :wg_initiate)
      refute_datagram(context)

      advance(clock, 1)
      send(peer, :wg_initiate)
      second = receive_datagram(context)
      refute sender_index(second) == sender_index(first)

      # The replaced initiation's session is closed and its index retired.
      assert lookup(context, sender_index(first)) == :retired
      assert in_process(peer, fn _state -> closed?(first_session) end)

      {response, session, _sent} = respond_to(second, context.remote, 22)
      to_wagyu(context, response)
      assert {:ok, _confirmation} = open_transport(session, receive_datagram(context))
      %{current: current} = :sys.get_state(peer)
      assert %{local_index: local_index, remote_index: 22} = current
      assert local_index == sender_index(second)

      # The first initiation's response arrives late, and the second's again.
      to_wagyu(context, late_response)
      to_wagyu(context, response)

      assert %{unknown_index: 1, responses_invalid: 1, responses_accepted: 1} =
               counters(context.interface, &(&1.unknown_index + &1.responses_invalid == 2))

      refute_datagram(context)
      assert %{current: ^current, previous: nil, next: nil, initiation: nil} = :sys.get_state(peer)
    end

    test "a rekey reuses the peer process and rotates the key slots", context do
      demand(context)
      {peer, clock} = started_peer(context)

      handshake = fn remote_index ->
        {response, session, _sent} = respond_to(receive_datagram(context), context.remote, remote_index)
        to_wagyu(context, response)
        assert {:ok, _confirmation} = open_transport(session, receive_datagram(context))
        session
      end

      first = handshake.(1)
      %{current: %{local_index: first_index, session: first_session}} = :sys.get_state(peer)

      advance(clock, 5_000)
      send(peer, :wg_initiate)
      _second = handshake.(2)

      assert %{current: %{remote_index: 2}, previous: %{local_index: ^first_index}, next: nil} =
               :sys.get_state(peer)

      # A packet delayed under the previous key still authenticates.
      dropped = :sys.get_state(peer).inbound_dropped
      to_wagyu(context, transport_frame(first, first_index, "delayed"))
      dropped_after(peer, dropped, 1)
      assert %{transport_invalid: 0} = counters(context.interface)

      # A third handshake retires the first key pair and closes its session.
      advance(clock, 5_000)
      send(peer, :wg_initiate)
      _third = handshake.(3)

      assert %{current: %{remote_index: 3}, previous: %{remote_index: 2}, next: nil} = :sys.get_state(peer)
      assert lookup(context, first_index) == :retired
      assert in_process(peer, fn _state -> closed?(first_session) end)

      assert peer(context) == peer
      assert [_one] = DynamicSupervisor.which_children(context.children.peer_supervisor)

      assert %{initiations_sent: 3, responses_accepted: 3, keepalives_sent: 2, transport_sent: 1} =
               counters(context.interface)
    end

    # Killing the peer logs its exit.
    @tag :capture_log
    test "initiation timestamps follow the wall clock and strictly increase, across restarts", context do
      initiation_timestamp = fn context ->
        {_response, session, %{timestamp: timestamp}} = respond_to(receive_datagram(context), context.remote)
        :ok = Decibel.close(session)
        {:ok, at} = TAI64N.to_unix(timestamp)
        assert at <= System.os_time(:nanosecond)
        timestamp
      end

      demand(context)
      first = initiation_timestamp.(context)
      {peer, clock} = started_peer(context)

      # Rekeys retriggered as fast as REKEY_TIMEOUT allows on the peer's
      # clock, within a few milliseconds of the wall clock.
      retriggered =
        for _n <- 1..4 do
          advance(clock, 5_000)
          send(peer, :wg_initiate)
          initiation_timestamp.(context)
        end

      # A new peer process, and then a new interface, follow on from them.
      kill(peer)
      assert eventually(fn -> peer(context) == nil end)
      demand(context)
      after_peer_restart = initiation_timestamp.(context)

      :ok = stop_supervised(Wagyu)
      context = Map.merge(context, start_interface(context.options))
      demand(context)
      after_interface_restart = initiation_timestamp.(context)

      assert strictly_increasing?([first | retriggered] ++ [after_peer_restart, after_interface_restart])
    end

    @tag :no_endpoint
    test "a peer with no endpoint cannot initiate until an initiation teaches it one", context do
      demand(context)

      assert %{initiations_no_endpoint: 1, initiations_sent: 0} =
               counters(context.interface, &(&1.initiations_no_endpoint == 1))

      {peer, clock} = started_peer(context)
      assert :sys.get_state(peer).endpoint == nil

      # The remote party initiates, and the peer responds to where the
      # initiation came from.
      {initiation, session} = initiate_to(context.public_key, context.remote, timestamp(1))
      to_wagyu(context, initiation)
      assert complete(session, receive_datagram(context)) == :ok
      assert :sys.get_state(peer).endpoint == context.remote_endpoint

      # It has no key to send with until the initiator confirms the new one,
      # and it waits REKEY_TIMEOUT after its response before initiating
      # itself, to the learned endpoint.
      demand(context)
      assert eventually(fn -> :queue.len(:sys.get_state(peer).staged) == 2 end)
      refute_datagram(context)

      advance(clock, 5_000)
      demand(context)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context)
      assert %{initiations_no_endpoint: 1, initiations_sent: 1} = counters(context.interface)
    end
  end

  describe "responding" do
    # The remote party initiates with `timestamp(n)` from `remote_index`
    # and completes the handshake. Returns its session and the peer's index.
    defp remote_handshake(context, n, remote_index) do
      {initiation, session} = initiate_to(context.public_key, context.remote, timestamp(n), remote_index)
      to_wagyu(context, initiation)
      response = receive_datagram(context)
      assert <<2, 0, 0, 0, local_index::little-32, ^remote_index::little-32, _rest::binary>> = response
      assert Packet.valid_mac1?(response, Packet.mac1_key(context.remote_key))
      assert complete(session, response) == :ok
      {session, local_index}
    end

    defp slots(peer) do
      state = :sys.get_state(peer)
      Map.new([:next, :current, :previous], &{&1, state |> Map.fetch!(&1) |> then(fn kp -> kp && kp.local_index end)})
    end

    test "the responder confirms a new key on the initiator's first transport message and keeps the old one",
         context do
      {first, first_index} = remote_handshake(context, 1, 1)
      peer = eventually(fn -> peer(context) end)

      # Until the initiator sends under the new key, the responder has no
      # key to send with.
      assert slots(peer) == %{next: first_index, current: nil, previous: nil}
      to_wagyu(context, transport_frame(first, first_index))
      assert eventually(fn -> slots(peer) == %{next: nil, current: first_index, previous: nil} end)
      assert %{keys_confirmed: 1} = counters(context.interface)

      # A rekey leaves the confirmed key current, the one to send with,
      # until the new one is confirmed in turn.
      advance(context.clock, 20)
      {second, second_index} = remote_handshake(context, 2, 2)
      assert eventually(fn -> slots(peer) == %{next: second_index, current: first_index, previous: nil} end)

      # A packet under the current key authenticates but confirms nothing.
      dropped = :sys.get_state(peer).inbound_dropped
      to_wagyu(context, transport_frame(first, first_index, "still the current key"))
      dropped_after(peer, dropped, 1)
      assert slots(peer) == %{next: second_index, current: first_index, previous: nil}

      # The first packet under the new key promotes it, and the old key
      # becomes the previous one, for packets delayed under it.
      to_wagyu(context, transport_frame(second, second_index))
      assert eventually(fn -> slots(peer) == %{next: nil, current: second_index, previous: first_index} end)
      to_wagyu(context, transport_frame(first, first_index, "delayed"))
      dropped_after(peer, dropped, 2)
      assert %{keys_confirmed: 2, transport_invalid: 0} = counters(context.interface)

      # A third handshake makes room for its key: the previous key pair is
      # closed and its index retired.
      %{previous: %{session: first_session}} = :sys.get_state(peer)
      advance(context.clock, 20)
      {_third, third_index} = remote_handshake(context, 3, 3)
      assert eventually(fn -> slots(peer) == %{next: third_index, current: second_index, previous: nil} end)
      assert lookup(context, first_index) == :retired
      assert in_process(peer, fn _state -> closed?(first_session) end)

      assert peer(context) == peer
      assert [_one] = DynamicSupervisor.which_children(context.children.peer_supervisor)
      assert %{responses_sent: 3} = counters(context.interface)
    end

    test "an unconfirmed key is replaced by a newer handshake, and kept when the peer initiates", context do
      {_first, first_index} = remote_handshake(context, 1, 1)
      peer = eventually(fn -> peer(context) end)
      clock = fake_peer_clock(peer)

      # A second handshake before the first is confirmed replaces it.
      advance(context.clock, 20)
      {_second, second_index} = remote_handshake(context, 2, 2)
      assert eventually(fn -> slots(peer) == %{next: second_index, current: nil, previous: nil} end)
      assert lookup(context, first_index) == :retired

      # When the peer's own handshake completes, the unconfirmed key is
      # newer than any current one, so it becomes the previous key.
      advance(clock, 5_000)
      send(peer, :wg_initiate)
      {response, session, _sent} = respond_to(receive_datagram(context), context.remote, 3)
      to_wagyu(context, response)
      assert open_transport(session, receive_datagram(context)) == {:ok, ""}

      %{current: %{local_index: third_index}} = :sys.get_state(peer)
      assert slots(peer) == %{next: nil, current: third_index, previous: second_index}
    end
  end
end
