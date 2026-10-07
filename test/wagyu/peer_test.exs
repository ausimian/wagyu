defmodule Wagyu.PeerTest do
  # The handshakes of a peer with a remote party. The test simulates the
  # remote party, with its own UDP socket and Decibel sessions. The tests
  # cover these items:
  #
  #   * initiation on outbound demand
  #   * responses
  #   * key confirmation
  #   * the key slots
  #   * the timers
  #
  # The interface runs on a fake clock. After the peer starts, it also runs
  # on a fake clock. Tests move the clock of the peer and then make it run
  # the timers that are due (`run_timers/1`). They do not wait for the
  # timers.
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.Admission
  alias Wagyu.Cookie
  alias Wagyu.IndexTable
  alias Wagyu.Packet
  alias Wagyu.TAI64N

  setup context do
    {_public_key, private_key} = keypair()
    {remote_key, _private_key} = remote = keypair()
    {:ok, remote_socket} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}, active: false])
    {:ok, remote_port} = :inet.port(remote_socket)
    endpoint = unless context[:no_endpoint], do: %{address: {127, 0, 0, 1}, port: remote_port}
    keepalive = Map.get(context, :persistent_keepalive, 0)

    peers = [
      %{public_key: remote_key, endpoint: endpoint, allowed_ips: [{{0, 0, 0, 0}, 0}], persistent_keepalive: keepalive}
    ]

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

  # Returns an outbound packet for the remote party.
  defp demand(context), do: send_egress(context.udp, 1)

  defp peer(%{remote_key: key} = context) do
    case :sys.get_state(context.children.interface).peers do
      %{^key => %{pid: pid}} -> pid
      _not_running -> nil
    end
  end

  # Waits until the peer starts, and puts it on a fake clock.
  defp started_peer(context) do
    pid = eventually(fn -> peer(context) end)
    {pid, fake_peer_clock(pid)}
  end

  # The fake clock starts at the time that the peer last sent a handshake
  # message, after the peer completes its current work. Thus REKEY_TIMEOUT
  # starts from that time.
  defp fake_peer_clock(pid) do
    %{handshake_sent_at: sent_at} = :sys.get_state(pid)
    fake_clock(pid, sent_at || System.monotonic_time(:millisecond))
  end

  defp to_wagyu(context, frame, from \\ nil),
    do: :ok = :gen_udp.send(from || context.remote_socket, {127, 0, 0, 1}, context.port, frame)

  # Returns the next datagram that the remote party receives. The datagram
  # must come from the socket of the interface.
  defp receive_datagram(context) do
    port = context.port
    assert {:ok, {{127, 0, 0, 1}, ^port, frame}} = :gen_udp.recv(context.remote_socket, 0, 1_000)
    frame
  end

  defp receive_datagram_within(context, timeout) do
    port = context.port
    assert {:ok, {{127, 0, 0, 1}, ^port, frame}} = :gen_udp.recv(context.remote_socket, 0, timeout)
    frame
  end

  defp refute_datagram(context), do: assert(:gen_udp.recv(context.remote_socket, 0, 100) == {:error, :timeout})

  defp lookup(context, index), do: IndexTable.lookup(:sys.get_state(context.children.interface).indices, index)

  defp sender_index(<<_type, 0, 0, 0, index::little-32, _rest::binary>>), do: index

  # Waits until the peer takes `count` more frames from its mailbox.
  defp dropped_after(peer, before, count),
    do: eventually(fn -> :sys.get_state(peer).inbound_dropped == before + count end)

  defp kill(pid) do
    monitor = Process.monitor(pid)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :killed}
  end

  # Moves a fake clock to `at`.
  defp advance_to(clock, at), do: advance(clock, at - :atomics.get(clock, 1))

  defp now(clock), do: :atomics.get(clock, 1)

  # Completes a handshake that the peer initiates on outbound demand. The
  # index of the remote party is `remote_index`. The remote party takes the
  # packet that confirms the handshake. Returns the peer, its clock, the
  # session of the remote party and the index of the peer.
  defp initiated(context, remote_index \\ 99) do
    demand(context)
    initiation = receive_datagram(context)
    {peer, clock} = started_peer(context)
    {response, session, _sent} = respond_to(initiation, context.remote, remote_index)
    to_wagyu(context, response)
    assert {:ok, _plaintext} = open_transport(session, receive_datagram(context))
    {peer, clock, session, sender_index(initiation)}
  end

  # The remote party sends a keepalive. Returns the state of the peer after
  # the peer takes the keepalive.
  defp remote_keepalive(context, peer, session, index) do
    %{keepalives_received: received} = counters(context.interface)
    to_wagyu(context, transport_frame(session, index))
    counters(context.interface, &(&1.keepalives_received == received + 1))
    :sys.get_state(peer)
  end

  defp strictly_increasing?(timestamps),
    do: timestamps |> Enum.chunk_every(2, 1, :discard) |> Enum.all?(fn [a, b] -> TAI64N.after?(b, a) end)

  describe "initiating" do
    test "outbound demand starts a handshake, and the staged packet confirms the key", context do
      demand(context)
      initiation = receive_datagram(context)
      {peer, _clock} = started_peer(context)

      # The initiation comes from a live index and contains a wall-clock
      # timestamp. This timestamp is never later than the time that the peer
      # sent the initiation.
      assert <<1, 0, 0, 0, index::little-32, _rest::binary-140>> = initiation
      assert %{initiation: %{local_index: ^index}, current: nil} = :sys.get_state(peer)
      assert lookup(context, index) == {:active, {context.remote_key, peer}}

      {response, session, sent} = respond_to(initiation, context.remote, 99)
      assert sent.initiator_key == context.public_key
      assert sent.sender_index == index
      {:ok, at} = TAI64N.to_unix(sent.timestamp)
      assert at <= System.os_time(:nanosecond)
      assert System.os_time(:nanosecond) - at < 2_000_000_000

      # The response completes the handshake. The packet that started the
      # handshake goes to the index of the responder and confirms the key.
      to_wagyu(context, response)
      confirmation = receive_datagram(context)
      assert <<4, 0, 0, 0, 99::little-32, 0::little-64, _rest::binary>> = confirmation
      assert {:ok, plaintext} = open_transport(session, confirmation)
      assert {:ok, %{destination: {192, 0, 2, 9}, length: length}} = Wagyu.IP.parse(plaintext)
      assert plaintext == binary_part(plaintext, 0, length) <> <<0::size((byte_size(plaintext) - length) * 8)>>

      assert %{initiation: nil, next: nil, previous: nil, current: %{local_index: ^index, remote_index: 99}} =
               state = :sys.get_state(peer)

      # The handshake stops the attempt.
      refute Map.has_key?(state.timers, :retry) or Map.has_key?(state.timers, :give_up)

      assert %{initiations_sent: 1, responses_accepted: 1, keepalives_sent: 0, transport_sent: 1} =
               counters(context.interface)

      # With a current key, outbound packets go out immediately under that key.
      # They do not start more handshakes.
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

      # These come from a different address, which must not become the
      # endpoint.
      {:ok, attacker} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}, active: false])

      for forged <- [
            # A different index, with a new MAC. The interface drops it.
            remac.(%{genuine | receiver_index: Bitwise.bxor(index, 1)}),
            # A bad MAC1. The interface drops it.
            <<covered::binary, :crypto.exor(mac1, <<1::128>>)::binary, mac2::binary>>,
            # The correct index and MAC1, but it does not authenticate.
            remac.(%{genuine | encrypted_nothing: <<Bitwise.bxor(first, 1), rest::binary>>}),
            # An all-zero ephemeral key, which X25519 rejects.
            remac.(%{genuine | ephemeral: <<0::256>>}),
            # A transport message for the index of the initiation.
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

      # The real response still completes the handshake.
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

      # The retry replaces the initiation at REKEY_TIMEOUT plus jitter after
      # that initiation. Nothing sends a retry earlier.
      %{handshake_sent_at: sent_at, timers: %{retry: retry}} = :sys.get_state(peer)
      assert (retry - sent_at) in 5_000..5_333
      send(peer, :wg_initiate)
      advance(clock, retry - sent_at - 1)
      run_timers(peer)
      refute_datagram(context)

      advance(clock, 1)
      run_timers(peer)
      second = receive_datagram(context)
      refute sender_index(second) == sender_index(first)

      # The session of the replaced initiation is closed, and its index is
      # retired.
      assert lookup(context, sender_index(first)) == :retired
      assert in_process(peer, fn _state -> closed?(first_session) end)

      {response, session, _sent} = respond_to(second, context.remote, 22)
      to_wagyu(context, response)
      assert {:ok, _confirmation} = open_transport(session, receive_datagram(context))
      %{current: current} = :sys.get_state(peer)
      assert %{local_index: local_index, remote_index: 22} = current
      assert local_index == sender_index(second)

      # The response to the first initiation arrives late. The response to the
      # second initiation arrives again.
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

      # A delayed packet under the previous key still authenticates.
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

    # When the test kills the peer, the peer logs its exit.
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

      # The peer sends retries as fast as REKEY_TIMEOUT and jitter allow on its
      # clock. Its clock stays in a few milliseconds of the wall clock.
      retriggered =
        for _n <- 1..4 do
          advance(clock, 5_333)
          run_timers(peer)
          initiation_timestamp.(context)
        end

      # A new peer process, and then a new interface, continue from those
      # timestamps.
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

      # The remote party initiates. The peer sends its response to the source
      # of the initiation.
      {initiation, session} = initiate_to(context.public_key, context.remote, timestamp(1))
      to_wagyu(context, initiation)
      assert complete(session, receive_datagram(context)) == :ok
      assert :sys.get_state(peer).endpoint == context.remote_endpoint

      # The peer has no key to send with until the initiator confirms the new
      # key. After its response, the peer waits for REKEY_TIMEOUT plus jitter.
      # Then it initiates to the endpoint that it learned.
      demand(context)
      assert eventually(fn -> :queue.len(:sys.get_state(peer).staged) == 2 end)
      refute_datagram(context)

      advance(clock, 5_333)
      run_timers(peer)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context)
      assert %{initiations_no_endpoint: 1, initiations_sent: 1} = counters(context.interface)
    end
  end

  describe "responding" do
    # The remote party initiates with `timestamp(n)` from `remote_index` and
    # completes the handshake. Returns its session and the index of the peer.
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

      # The responder has no key to send with until the initiator sends under
      # the new key.
      assert slots(peer) == %{next: first_index, current: nil, previous: nil}
      to_wagyu(context, transport_frame(first, first_index))
      assert eventually(fn -> slots(peer) == %{next: nil, current: first_index, previous: nil} end)
      assert %{keys_confirmed: 1} = counters(context.interface)

      # After a rekey, the confirmed key stays current, and the peer sends with
      # it. It stays current until the new key is also confirmed.
      advance(context.clock, 20)
      {second, second_index} = remote_handshake(context, 2, 2)
      assert eventually(fn -> slots(peer) == %{next: second_index, current: first_index, previous: nil} end)

      # A packet under the current key authenticates but does not confirm a key.
      dropped = :sys.get_state(peer).inbound_dropped
      to_wagyu(context, transport_frame(first, first_index, "still the current key"))
      dropped_after(peer, dropped, 1)
      assert slots(peer) == %{next: second_index, current: first_index, previous: nil}

      # The first packet under the new key promotes that key. The old key
      # becomes the previous key, for delayed packets under the old key.
      to_wagyu(context, transport_frame(second, second_index))
      assert eventually(fn -> slots(peer) == %{next: nil, current: second_index, previous: first_index} end)
      to_wagyu(context, transport_frame(first, first_index, "delayed"))
      dropped_after(peer, dropped, 2)
      assert %{keys_confirmed: 2, transport_invalid: 0} = counters(context.interface)

      # A third handshake makes space for its key. The previous key pair is
      # closed, and its index is retired.
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

      # A second handshake replaces the first handshake if the first is not yet
      # confirmed.
      advance(context.clock, 20)
      {_second, second_index} = remote_handshake(context, 2, 2)
      assert eventually(fn -> slots(peer) == %{next: second_index, current: nil, previous: nil} end)
      assert lookup(context, first_index) == :retired

      # When the handshake of the peer completes, the key that is not confirmed
      # is newer than a current key. Thus it becomes the previous key.
      advance(clock, 5_000)
      send(peer, :wg_initiate)
      {response, session, _sent} = respond_to(receive_datagram(context), context.remote, 3)
      to_wagyu(context, response)
      assert open_transport(session, receive_datagram(context)) == {:ok, ""}

      %{current: %{local_index: third_index}} = :sys.get_state(peer)
      assert slots(peer) == %{next: nil, current: third_index, previous: second_index}
    end
  end

  describe "cookies" do
    # Returns a cookie reply that contains `cookie`. The reply is to `frame`,
    # a handshake message to the holder of `public_key`. That party encrypts
    # the reply in this way when it is under load.
    defp cookie_reply(frame, cookie, public_key) do
      {:ok, mac1} = Packet.mac1(frame)
      Cookie.seal(Cookie.key(public_key), cookie, sender_index(frame), :crypto.strong_rand_bytes(24), mac1)
    end

    defp cookie_replies(context, accepted, invalid) do
      counters(context.interface, &(&1.cookie_replies_accepted == accepted and &1.cookie_replies_invalid == invalid))
    end

    test "a cookie reply to the last initiation keys MAC2 on the next ones for 120 seconds", context do
      demand(context)
      first = receive_datagram(context)
      {peer, clock} = started_peer(context)
      assert <<_covered::binary-132, 0::128>> = first
      cookie = :crypto.strong_rand_bytes(16)
      {other_key, _private_key} = keypair()

      # The peer takes a reply only if it decrypts with the key of the remote
      # party and the MAC1 of this initiation. It does not take a reply for a
      # different key. It also does not take a reply to a different message
      # from the same index.
      <<head::binary-116, _mac1::binary-16, _mac2::binary-16>> = first
      other_message = <<head::binary, :crypto.strong_rand_bytes(16)::binary, 0::128>>
      to_wagyu(context, cookie_reply(first, cookie, other_key))
      to_wagyu(context, cookie_reply(other_message, cookie, context.remote_key))
      assert cookie_replies(context, 0, 2)

      # The peer takes the real reply one time. The reply alone does not cause
      # the peer to send.
      reply = cookie_reply(first, cookie, context.remote_key)
      to_wagyu(context, reply)
      assert cookie_replies(context, 1, 2)
      received_at = now(clock)
      to_wagyu(context, reply)
      assert cookie_replies(context, 1, 3)
      refute_datagram(context)

      # The retry contains MAC2 under the cookie, and also MAC1.
      %{timers: %{retry: retry}} = :sys.get_state(peer)
      advance_to(clock, retry)
      run_timers(peer)
      second = receive_datagram(context)
      assert Packet.valid_mac1?(second, Packet.mac1_key(context.remote_key))
      assert Packet.valid_mac2?(second, cookie)

      # A retry immediately before the cookie is 120 seconds old also contains
      # MAC2. The attempt also stops at that time. The next initiation after
      # that has no MAC2.
      advance_to(clock, received_at + 119_999)
      run_timers(peer)
      assert Packet.valid_mac2?(receive_datagram(context), cookie)

      advance_to(clock, received_at + 125_000)
      demand(context)
      assert <<_covered::binary-132, 0::128>> = receive_datagram(context)
    end

    test "a cookie reply to a response keys MAC2 on the next response", context do
      {initiation, _session} = initiate_to(context.public_key, context.remote, timestamp(1), 1)
      to_wagyu(context, initiation)
      response = receive_datagram(context)
      assert <<_covered::binary-76, 0::128>> = response

      # The reply goes to the sender index of the response, which is the new
      # index of the peer.
      cookie = :crypto.strong_rand_bytes(16)
      to_wagyu(context, cookie_reply(response, cookie, context.remote_key))
      assert cookie_replies(context, 1, 0)

      advance(context.clock, 20)
      {initiation, session} = initiate_to(context.public_key, context.remote, timestamp(2), 2)
      to_wagyu(context, initiation)
      response = receive_datagram(context)
      assert Packet.valid_mac1?(response, Packet.mac1_key(context.remote_key))
      assert Packet.valid_mac2?(response, cookie)
      assert complete(session, response) == :ok
    end
  end

  describe "retrying" do
    # Runs each retry that the peer schedules until the attempt stops, and
    # checks the jitter of each retry. Returns the index of each initiation
    # that the peer sent.
    defp retry_until_abandoned(context, peer, clock, indices) do
      state = :sys.get_state(peer)

      case state.timers do
        %{retry: retry, give_up: give_up} when retry < give_up ->
          assert (retry - state.handshake_sent_at) in 5_000..5_333
          advance_to(clock, retry)
          run_timers(peer)
          retry_until_abandoned(context, peer, clock, [sender_index(receive_datagram(context)) | indices])

        %{give_up: give_up} ->
          advance_to(clock, give_up)
          run_timers(peer)
          Enum.reverse(indices)
      end
    end

    # When the test kills the peer, the peer logs its exit.
    test "an unanswered initiation is retried with jitter for 90 seconds, then its packet is dropped", context do
      # The attempt starts on the real clock of the peer, after the demand and
      # before the first initiation arrives. It continues for 90 seconds.
      demanded = System.monotonic_time(:millisecond)
      demand(context)
      first = receive_datagram(context)
      arrived = System.monotonic_time(:millisecond)
      {peer, clock} = started_peer(context)
      %{timers: %{give_up: give_up}} = :sys.get_state(peer)
      assert give_up in (demanded + 90_000)..(arrived + 90_000)

      # A new initiation each 5 to 5.333 seconds. Each initiation comes from a
      # new index, and all come from the same process.
      indices = retry_until_abandoned(context, peer, clock, [sender_index(first)])
      assert length(indices) in 17..18
      assert indices == Enum.uniq(indices)
      assert peer(context) == peer
      assert [_one] = DynamicSupervisor.which_children(context.children.peer_supervisor)

      # Then the attempt stops. The peer discards the initiation, retires its
      # index and drops the staged packet. It sends nothing more.
      refute_datagram(context)
      assert Enum.all?(indices, &(lookup(context, &1) == :retired))
      state = :sys.get_state(peer)
      assert %{initiation: nil, timers: %{zero: zero} = timers} = state
      assert :queue.is_empty(state.staged)
      refute Map.has_key?(timers, :retry) or Map.has_key?(timers, :give_up)
      assert zero == now(clock) + 540_000

      count = length(indices)

      assert %{initiations_sent: ^count, staged_dropped: 1, handshakes_abandoned: 1, egress_peer_dropped: 0} =
               counters(context.interface)

      # The idle peer has no more keys to keep, so it exits 540 seconds later.
      # The next packet starts a new peer.
      monitor = Process.monitor(peer)
      advance_to(clock, zero)
      send(peer, {:wg_timer, make_ref()})
      assert_receive {:DOWN, ^monitor, :process, ^peer, :normal}
      assert peer(context) == nil

      demand(context)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context)
      assert peer(context) not in [nil, peer]
    end

    test "only an outbound packet that has to wait for a key extends the attempt", context do
      demand(context)
      _initiation = receive_datagram(context)
      {peer, clock} = started_peer(context)
      %{timers: %{give_up: give_up}} = :sys.get_state(peer)

      # A rekey becomes part of the current attempt.
      advance(clock, 30_000)
      send(peer, :wg_initiate)
      assert %{timers: %{give_up: ^give_up}} = :sys.get_state(peer)

      # One more packet that waits for the key extends the attempt to 90
      # seconds from now.
      demand(context)
      extended = now(clock) + 90_000
      assert eventually(fn -> :sys.get_state(peer).timers.give_up == extended end)

      # A packet that has no space to wait does not extend the attempt.
      %{staging: staging} = :sys.get_state(peer)
      {packets, bytes} = Admission.usage(staging)
      free = staging.max_packets - packets
      :ok = Admission.admit(staging, free, 0)
      advance(clock, 30_000)
      demand(context)
      assert counters(context.interface, &(&1.staged_dropped == 1))
      assert %{timers: %{give_up: ^extended}} = :sys.get_state(peer)
      Admission.release(staging, free, 0)
      assert Admission.usage(staging) == {packets, bytes}
    end
  end

  describe "keepalives" do
    test "a peer that receives data answers with a keepalive after 10 seconds, and is otherwise quiet", context do
      {session, index} = remote_handshake(context, 1, 1)
      peer = eventually(fn -> peer(context) end)
      clock = fake_peer_clock(peer)

      # A keepalive confirms the key, but does not ask for an answer.
      to_wagyu(context, transport_frame(session, index))
      assert eventually(fn -> :sys.get_state(peer).current end)
      refute Map.has_key?(:sys.get_state(peer).timers, :keepalive)

      # Data asks for an answer. This is also true for data that the peer drops
      # because it is not IP.
      to_wagyu(context, transport_frame(session, index, "data"))
      at = eventually(fn -> :sys.get_state(peer).timers[:keepalive] end)
      assert at == now(clock) + 10_000

      advance_to(clock, at - 1)
      run_timers(peer)
      refute_datagram(context)

      advance(clock, 1)
      run_timers(peer)
      assert open_transport(session, receive_datagram(context)) == {:ok, ""}

      # No persistent keepalive is configured, so nothing else goes out.
      advance(clock, 60_000)
      run_timers(peer)
      refute_datagram(context)
      assert %{keepalives_sent: 1, initiations_sent: 0} = counters(context.interface)
    end

    test "a peer whose key expires before it can answer data starts a handshake instead", context do
      {session, index} = remote_handshake(context, 1, 1)
      peer = eventually(fn -> peer(context) end)
      clock = fake_peer_clock(peer)
      to_wagyu(context, transport_frame(session, index))
      %{created_at: created} = eventually(fn -> :sys.get_state(peer).current end)

      advance_to(clock, created + 179_999)
      to_wagyu(context, transport_frame(session, index, "data"))
      at = eventually(fn -> :sys.get_state(peer).timers[:keepalive] end)

      advance_to(clock, at)
      run_timers(peer)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context)
      assert %{keepalives_sent: 0} = counters(context.interface)
    end

    test "sending data instead cancels the keepalive", context do
      {session, index} = remote_handshake(context, 1, 1)
      peer = eventually(fn -> peer(context) end)
      clock = fake_peer_clock(peer)

      to_wagyu(context, transport_frame(session, index, "data"))
      assert eventually(fn -> :sys.get_state(peer).timers[:keepalive] end)

      demand(context)
      assert {:ok, _packet} = open_transport(session, receive_datagram(context))
      refute Map.has_key?(:sys.get_state(peer).timers, :keepalive)

      advance(clock, 10_000)
      run_timers(peer)
      refute_datagram(context)

      # A handshake message that the peer sends also cancels the keepalive.
      to_wagyu(context, transport_frame(session, index, "more data"))
      assert eventually(fn -> :sys.get_state(peer).timers[:keepalive] end)
      send(peer, :wg_initiate)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context)
      refute Map.has_key?(:sys.get_state(peer).timers, :keepalive)
    end

    test "a peer that sends data and hears nothing for 15 seconds starts a new handshake", context do
      {peer, clock, session, index} = initiated(context)

      # An authenticated message from the other side delays it.
      refute Map.has_key?(remote_keepalive(context, peer, session, index).timers, :new_handshake)

      demand(context)
      assert <<4, 0, 0, 0, _rest::binary>> = receive_datagram(context)
      sent = now(clock)
      at = :sys.get_state(peer).timers.new_handshake
      assert (at - sent) in 15_000..15_333

      advance_to(clock, at - 1)
      run_timers(peer)
      refute_datagram(context)

      # This occurs much earlier than REKEY_AFTER_TIME.
      advance(clock, 1)
      run_timers(peer)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context)
      assert %{initiations_sent: 2} = counters(context.interface)
    end

    @tag persistent_keepalive: 25
    test "a persistent keepalive starts with the interface and fills every 25-second silence", context do
      # The peer starts without traffic. It has no key, so its first keepalive
      # starts a handshake. The keepalive then confirms the handshake.
      initiation = receive_datagram(context)
      {peer, clock} = started_peer(context)
      index = sender_index(initiation)
      {response, session, _sent} = respond_to(initiation, context.remote, 7)
      to_wagyu(context, response)
      assert open_transport(session, receive_datagram(context)) == {:ok, ""}

      for _n <- 1..2 do
        at = :sys.get_state(peer).timers.persistent_keepalive
        advance_to(clock, at - 1)
        run_timers(peer)
        refute_datagram(context)

        advance(clock, 1)
        run_timers(peer)
        assert open_transport(session, receive_datagram(context)) == {:ok, ""}
      end

      # Traffic from the other side starts the wait again.
      advance(clock, 10_000)
      %{timers: %{persistent_keepalive: at}} = remote_keepalive(context, peer, session, index)
      assert at == now(clock) + 25_000
    end

    # When the test kills the peer, the peer logs its exit.
    @tag :capture_log
    @tag persistent_keepalive: 25
    test "a peer with a persistent keepalive is started again after it fails", context do
      _initiation = receive_datagram(context)
      peer = eventually(fn -> peer(context) end)
      kill(peer)

      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram_within(context, 3_000)
      assert peer(context) not in [nil, peer]
    end
  end

  describe "rekeying" do
    test "an initiator rekeys when it sends under a key 120 seconds old", context do
      {peer, clock, session, index} = initiated(context)
      %{current: %{created_at: created}} = remote_keepalive(context, peer, session, index)

      advance_to(clock, created + 119_999)
      demand(context)
      assert {:ok, _packet} = open_transport(session, receive_datagram(context))
      refute_datagram(context)

      # The packet still goes out under the old key, and a handshake starts
      # after it.
      advance(clock, 1)
      demand(context)
      assert {:ok, _packet} = open_transport(session, receive_datagram(context))
      {response, new_session, _sent} = respond_to(receive_datagram(context), context.remote, 100)
      to_wagyu(context, response)
      assert open_transport(new_session, receive_datagram(context)) == {:ok, ""}
      assert %{current: %{remote_index: 100}, previous: %{local_index: ^index}} = :sys.get_state(peer)
    end

    test "a responder does not rekey on age alone, but does after 2^60 messages", context do
      {session, index} = remote_handshake(context, 1, 1)
      peer = eventually(fn -> peer(context) end)
      clock = fake_peer_clock(peer)
      to_wagyu(context, transport_frame(session, index))
      %{created_at: created} = eventually(fn -> :sys.get_state(peer).current end)

      advance_to(clock, created + 170_000)
      demand(context)
      assert {:ok, _packet} = open_transport(session, receive_datagram(context))
      refute_datagram(context)

      in_process(peer, fn %{current: key_pair} -> Decibel.set_nonce(key_pair.session, :out, 2 ** 60 - 1) end)
      demand(context)
      assert <<4, 0, 0, 0, 1::little-32, counter::little-64, _rest::binary>> = receive_datagram(context)
      assert counter == 2 ** 60 - 1
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context)
    end

    test "an initiator that is still receiving at 165 seconds starts a handshake", context do
      {peer, clock, session, index} = initiated(context)
      %{current: %{created_at: created}} = remote_keepalive(context, peer, session, index)

      advance_to(clock, created + 164_999)
      remote_keepalive(context, peer, session, index)
      refute_datagram(context)

      advance(clock, 1)
      remote_keepalive(context, peer, session, index)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context)
      assert %{last_minute_rekey: true} = :sys.get_state(peer)
    end

    test "no key sends REJECT_AFTER_MESSAGES messages", context do
      {peer, _clock, session, index} = initiated(context)
      remote_keepalive(context, peer, session, index)
      reject_after_messages = 2 ** 64 - 2 ** 13 - 1

      in_process(peer, fn %{current: key_pair} ->
        Decibel.set_nonce(key_pair.session, :out, reject_after_messages - 1)
      end)

      demand(context)
      assert <<4, 0, 0, 0, 99::little-32, counter::little-64, _rest::binary>> = receive_datagram(context)
      assert counter == reject_after_messages - 1

      # The next packet waits for a new key.
      demand(context)
      assert eventually(fn -> :queue.len(:sys.get_state(peer).staged) == 1 end)
      assert %{transport_sent: 2} = counters(context.interface)
    end
  end

  describe "key lifetimes" do
    test "a responder keeps its old key until the new one is confirmed, and retires each at 180 seconds",
         context do
      {first, first_index} = remote_handshake(context, 1, 1)
      peer = eventually(fn -> peer(context) end)
      clock = fake_peer_clock(peer)
      to_wagyu(context, transport_frame(first, first_index))
      assert eventually(fn -> slots(peer) == %{next: nil, current: first_index, previous: nil} end)

      advance(context.clock, 20)
      advance(clock, 1_000)
      {second, second_index} = remote_handshake(context, 2, 2)
      assert eventually(fn -> slots(peer) == %{next: second_index, current: first_index, previous: nil} end)

      # The responder sends with the old key until the new key is confirmed.
      demand(context)
      assert <<4, 0, 0, 0, 1::little-32, _rest::binary>> = frame = receive_datagram(context)
      assert {:ok, _packet} = open_transport(first, frame)

      to_wagyu(context, transport_frame(second, second_index))
      assert eventually(fn -> slots(peer) == %{next: nil, current: second_index, previous: first_index} end)

      # A delayed packet under the old key still authenticates until that key
      # is 180 seconds old. The quantity of traffic does not change this.
      %{previous: %{created_at: created}, inbound_dropped: dropped} = :sys.get_state(peer)
      advance_to(clock, created + 179_999)
      to_wagyu(context, transport_frame(first, first_index, "delayed"))
      dropped_after(peer, dropped, 1)
      assert %{transport_invalid: 0, transport_expired: 0, transport_malformed: 1} = counters(context.interface)

      # Then the old key is retired, and the interface drops the next delayed
      # packet.
      advance(clock, 1)
      run_timers(peer)
      assert slots(peer) == %{next: nil, current: second_index, previous: nil}
      assert lookup(context, first_index) == :retired

      %{unknown_index: unknown} = counters(context.interface)
      to_wagyu(context, transport_frame(first, first_index, "late"))
      assert counters(context.interface, &(&1.unknown_index == unknown + 1))
    end

    # When the test kills the peer, the peer logs its exit.
    @tag :capture_log
    test "540 seconds after its last new key pair an idle peer has no keys and exits", context do
      {peer, clock, session, index} = initiated(context)
      %{timers: %{zero: zero}} = remote_keepalive(context, peer, session, index)

      # The key retires at 180 seconds, and nothing else occurs.
      advance_to(clock, zero - 1)
      assert %{next: nil, current: nil, previous: nil, initiation: nil} = run_timers(peer)
      assert lookup(context, index) == :retired
      refute_datagram(context)

      monitor = Process.monitor(peer)
      advance(clock, 1)
      send(peer, {:wg_timer, make_ref()})
      assert_receive {:DOWN, ^monitor, :process, ^peer, :normal}
      assert {:ok, %{peers: [%{running: false}]}} = Wagyu.info(context.interface)

      demand(context)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context)
      assert peer(context) not in [nil, peer]
    end

    @tag :no_endpoint
    test "a peer that idles out keeps the endpoint it learned", context do
      {session, index} = remote_handshake(context, 1, 1)
      peer = eventually(fn -> peer(context) end)
      clock = fake_peer_clock(peer)
      to_wagyu(context, transport_frame(session, index))
      %{timers: %{zero: zero}} = eventually(fn -> :sys.get_state(peer).current && :sys.get_state(peer) end)

      monitor = Process.monitor(peer)
      advance_to(clock, zero)
      send(peer, {:wg_timer, make_ref()})
      assert_receive {:DOWN, ^monitor, :process, ^peer, :normal}

      # The next process has the endpoint that the last process learned. It
      # does not use the configuration, which has no endpoint.
      demand(context)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context)
      assert :sys.get_state(peer(context)).endpoint == context.remote_endpoint
      assert %{initiations_no_endpoint: 0} = counters(context.interface)
    end

    test "a peer's process dictionary does not grow with its handshakes", context do
      {peer, clock, _session, _index} = initiated(context)
      entries = fn -> in_process(peer, fn _state -> length(Process.get()) end) end

      rekey = fn remote_index ->
        advance(clock, 5_000)
        send(peer, :wg_initiate)
        {response, session, _sent} = respond_to(receive_datagram(context), context.remote, remote_index)
        to_wagyu(context, response)
        assert open_transport(session, receive_datagram(context)) == {:ok, ""}
        :ok = Decibel.close(session)
      end

      Enum.each(1..3, rekey)
      after_three = entries.()
      Enum.each(4..30, rekey)
      assert entries.() == after_three
    end
  end

  describe "crashes and shutdown" do
    # When the test kills the peer, the peer logs its exit.
    @tag :capture_log
    test "a peer's timers go with it, and its indices are retired", context do
      demand(context)
      index = sender_index(receive_datagram(context))
      {peer, _clock} = started_peer(context)
      assert Map.has_key?(:sys.get_state(peer).timers, :retry)

      kill(peer)
      assert eventually(fn -> lookup(context, index) == :retired end)
      assert peer(context) == nil

      # When the interface stops, a peer and its pending retry also stop.
      demand(context)
      _initiation = receive_datagram(context)
      {peer, _clock} = started_peer(context)
      monitor = Process.monitor(peer)
      :ok = stop_supervised(Wagyu)
      assert_receive {:DOWN, ^monitor, :process, ^peer, :shutdown}
      refute_datagram(context)
    end

    # When the test kills the peer, the peer logs its exit.
    @tag :capture_log
    @tag :no_endpoint
    test "a peer that fails keeps the endpoint it learned", context do
      {_session, _index} = remote_handshake(context, 1, 1)
      peer = eventually(fn -> peer(context) end)
      assert eventually(fn -> :sys.get_state(context.children.interface).endpoints[context.remote_key] end)
      kill(peer)

      # The next process has the endpoint that the failed process learned.
      demand(context)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context)
      assert :sys.get_state(peer(context)).endpoint == context.remote_endpoint
      assert %{initiations_no_endpoint: 0} = counters(context.interface)
    end

    # When the test kills the peer, the peer logs its exit.
    @tag :capture_log
    test "the interface forgets a peer only when nothing is waiting for it", context do
      {peer, _clock, _session, index} = initiated(context)
      %{peers: %{} = peers} = :sys.get_state(context.children.interface)
      %{outbound: outbound} = Map.fetch!(peers, context.remote_key)
      release = fn -> in_process(peer, &Wagyu.Interface.release_peer(&1.root, &1.public_key)) end

      :ok = Admission.admit(outbound, 1, 10)
      assert release.() == :busy
      assert peer(context) == peer

      Admission.release(outbound, 1, 10)
      assert release.() == :ok
      assert peer(context) == nil
      assert lookup(context, index) == :retired

      # A packet now starts a new process. The exit of the old process does not
      # affect the new process.
      demand(context)
      assert <<1, 0, 0, 0, _rest::binary-144>> = receive_datagram(context)
      new = peer(context)
      assert new not in [nil, peer]
      kill(peer)
      assert peer(context) == new
    end
  end
end
