defmodule Wagyu.HandshakeTest do
  # Inbound initiations through a running interface: authorization, the
  # handoff to peers, their responses, and the receiver-index lifecycle. The
  # interface runs on a fake clock, so every time-based rule is exact.
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.Admission
  alias Wagyu.IndexTable
  alias Wagyu.Packet

  setup do
    {public_key, private_key} = keypair()
    {peer_key, _peer_private_key} = initiator = keypair()

    peers = [
      %{public_key: peer_key, endpoint: %{address: {127, 0, 0, 1}, port: 51_820}, allowed_ips: [{{0, 0, 0, 0}, 0}]}
    ]

    interface = start_supervised!({Wagyu, options(private_key: private_key, peers: peers)})
    %{interface: pid} = children = children(interface)
    clock = fake_clock(pid)

    {:ok, %{listen: %{port: port}}} = Wagyu.info(interface)
    {:ok, client} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}, active: false])
    {:ok, client_port} = :inet.port(client)

    %{
      interface: interface,
      children: children,
      clock: clock,
      public_key: public_key,
      peer_key: peer_key,
      initiator: initiator,
      port: port,
      client: client,
      source: {{127, 0, 0, 1}, client_port}
    }
  end

  defp send_datagrams(%{client: client, port: port}, datagrams) do
    for datagram <- datagrams, do: :ok = :gen_udp.send(client, {127, 0, 0, 1}, port, datagram)
    :ok
  end

  defp genuine(context, n, sender_index \\ :rand.uniform(0xFFFFFFFF)),
    do: noise_initiation(context.public_key, context.initiator, timestamp(n), sender_index)

  defp transport(index), do: <<4, 0, 0, 0, index::little-32, 0::little-64, 0::128>>

  defp interface_state(context), do: :sys.get_state(context.children.interface)

  # The running peer's process, or nil.
  defp peer(%{peer_key: key} = context) do
    case interface_state(context).peers do
      %{^key => %{pid: pid}} -> pid
      _not_running -> nil
    end
  end

  defp peer_children(context), do: DynamicSupervisor.which_children(context.children.peer_supervisor)

  # Waits for the peer to have responded to the initiation carrying
  # `timestamp`, and returns the key pair it holds for that handshake, which
  # waits in `:next` for the initiator to confirm it.
  defp responded(context, timestamp) do
    eventually(fn ->
      with pid when is_pid(pid) <- peer(context),
           %{received: ^timestamp, next: %{} = next, endpoint: endpoint} <- :sys.get_state(pid) do
        Map.merge(next, %{peer: pid, endpoint: endpoint})
      else
        _not_yet -> nil
      end
    end)
  end

  defp lookup(context, index), do: IndexTable.lookup(interface_state(context).indices, index)

  # Waits until every initiation has been settled and the counters have
  # stopped changing, and returns them.
  defp settled(context) do
    eventually(fn ->
      before = counters(context.interface)
      Process.sleep(50)
      %{handshakes: handshakes} = interface_state(context)
      counters = counters(context.interface)
      if counters == before and handshakes.active == 0 and handshakes.queued == 0, do: counters
    end)
  end

  defp kill(pid) do
    monitor = Process.monitor(pid)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :killed}
  end

  # Receives datagrams on `socket` until one is a cookie reply to
  # `receiver_index`, and returns it.
  defp cookie_reply_to(socket, receiver_index) do
    assert {:ok, {{127, 0, 0, 1}, _port, datagram}} = :gen_udp.recv(socket, 0, 1_000)

    case datagram do
      <<3, 0, 0, 0, ^receiver_index::little-32, _rest::binary>> -> datagram
      _other -> cookie_reply_to(socket, receiver_index)
    end
  end

  # Puts the interface under load for the next second of its clock, as a
  # loaded initiation queue would.
  defp under_load(context),
    do: :sys.replace_state(context.children.interface, &%{&1 | under_load_until: &1.clock.() + 1_000})

  # Occupies every worker slot with a stand-in process, as a flood of
  # initiations would, and puts `queued` forged initiations in the waiting
  # room. A stand-in frees its slot when it is sent `:stop`.
  defp saturate(context, queued) do
    stand_ins = for _n <- 1..8, do: spawn(fn -> receive do: (:stop -> :ok) end)
    waiting = for _n <- 1..queued//1, do: %{frame: initiation(context.public_key), source: context.source}

    # The function runs in the interface, so the interface monitors them.
    :sys.replace_state(context.children.interface, fn state ->
      monitors = Map.new(stand_ins, &{Process.monitor(&1), :worker})
      handshakes = %{state.handshakes | active: 8, queued: queued, queue: :queue.from_list(waiting)}
      %{state | monitors: Map.merge(state.monitors, monitors), handshakes: handshakes}
    end)

    stand_ins
  end

  # Waits until the counters stop changing, and returns them.
  defp quiet(context) do
    eventually(fn ->
      before = counters(context.interface)
      Process.sleep(50)
      if counters(context.interface) == before, do: before
    end)
  end

  test "an authenticated initiation starts its peer, which responds from a live index", context do
    send_datagrams(context, [genuine(context, 1, 77)])

    responded = responded(context, timestamp(1))
    assert %{remote_index: 77, endpoint: endpoint, local_index: index} = responded
    assert endpoint == context.source
    assert lookup(context, index) == {:active, {context.peer_key, responded.peer}}

    assert %{initiations: 1, initiations_accepted: 1, initiations_failed: 0, responses_sent: 1} = settled(context)
    assert [_one] = peer_children(context)

    # The response comes from the new index to the initiator's, with MAC1
    # keyed for the initiator.
    assert {:ok, {{127, 0, 0, 1}, _port, response}} = :gen_udp.recv(context.client, 0, 1_000)
    assert {:ok, %Packet.Response{sender_index: ^index, receiver_index: 77}} = Packet.decode(response)
    assert Packet.valid_mac1?(response, Packet.mac1_key(context.peer_key))

    # Messages for the index reach the peer, which drops this unauthenticated
    # one; others drop at the interface.
    send_datagrams(context, [transport(index), transport(index + 1)])
    assert %{inbound_routed: 1, unknown_index: 1} = counters(context.interface, &(&1.datagrams == 3))
    assert eventually(fn -> :sys.get_state(responded.peer).inbound_dropped == 1 end)
    assert %{transport_invalid: 1} = counters(context.interface)
  end

  test "concurrent initiations for one key start one peer and accept one timestamp", context do
    # With the clock stopped, whichever claim comes first is accepted and
    # every other one is a replay or within 20 ms of it.
    send_datagrams(context, for(n <- 1..8, do: genuine(context, n)))

    counters =
      counters(
        context.interface,
        &(&1.initiations_accepted + &1.initiations_replayed + &1.initiations_rate_limited == 8)
      )

    assert counters.initiations_accepted == 1
    assert [_one] = peer_children(context)

    %{initiations: %{} = initiations} = interface_state(context)
    %{timestamp: accepted} = Map.fetch!(initiations, context.peer_key)
    assert responded(context, accepted)

    # The same initiation arriving many times is accepted at most once.
    advance(context.clock, 1_000)
    duplicate = genuine(context, 100)
    send_datagrams(context, List.duplicate(duplicate, 6))

    counters =
      counters(
        context.interface,
        &(&1.initiations_accepted + &1.initiations_replayed + &1.initiations_rate_limited == 14)
      )

    assert counters.initiations_accepted == 2
    assert responded(context, timestamp(100))
    assert [_one] = peer_children(context)
  end

  test "an initiation within 20 ms of the last accepted one is dropped", context do
    send_datagrams(context, [genuine(context, 1)])
    counters(context.interface, &(&1.initiations_accepted == 1))

    advance(context.clock, 19)
    send_datagrams(context, [genuine(context, 2)])
    assert %{initiations_rate_limited: 1} = counters(context.interface, &(&1.initiations_rate_limited == 1))

    # The window runs from the last accepted initiation, not the dropped one.
    advance(context.clock, 1)
    send_datagrams(context, [genuine(context, 3)])

    assert %{initiations_accepted: 2, initiations_rate_limited: 1} =
             counters(context.interface, &(&1.initiations_accepted == 2))

    assert responded(context, timestamp(3))
  end

  # Killing the peer logs its exit.
  @tag :capture_log
  test "replayed and stale timestamps are dropped, even after the peer restarts", context do
    frame = genuine(context, 2)
    send_datagrams(context, [frame])
    %{peer: first} = responded(context, timestamp(2))

    advance(context.clock, 1_000)
    send_datagrams(context, [frame, genuine(context, 1)])
    assert %{initiations_replayed: 2} = counters(context.interface, &(&1.initiations_replayed == 2))

    # The interface keeps the timestamp after the peer exits, and a replay
    # does not start a new peer.
    kill(first)
    assert eventually(fn -> peer(context) == nil end)

    advance(context.clock, 1_000)
    send_datagrams(context, [frame, genuine(context, 2)])
    assert %{initiations_replayed: 4, initiations_accepted: 1} = settled(context)
    assert peer(context) == nil

    send_datagrams(context, [genuine(context, 3)])
    assert %{peer: second} = responded(context, timestamp(3))
    refute second == first
  end

  test "unknown keys and failed authentication get no peer and no response", context do
    {other_key, _private_key} = keypair()
    stranger = noise_initiation(context.public_key, keypair(), timestamp(1))

    for_other =
      context.public_key
      |> Packet.mac1_key()
      |> then(&Packet.put_mac1(noise_initiation(other_key, context.initiator, timestamp(1)), &1))

    send_datagrams(context, [stranger, initiation(context.public_key), for_other])

    assert %{initiations: 3, initiations_unknown_peer: 1, initiations_failed: 2, initiations_accepted: 0} =
             settled(context)

    assert peer_children(context) == []
    assert DynamicSupervisor.count_children(context.children.handshake_supervisor).active == 0
    assert :gen_udp.recv(context.client, 0, 100) == {:error, :timeout}
  end

  test "a peer that has not accepted its ticket is neither waited on nor killed", context do
    send_datagrams(context, [genuine(context, 1)])
    %{peer: peer} = responded(context, timestamp(1))
    :ok = :sys.suspend(peer)

    # The claim and the handoff finish without the peer, which is left with
    # the ticket unread.
    advance(context.clock, 20)
    send_datagrams(context, [genuine(context, 2), "not wireguard"])
    assert %{initiations_accepted: 2, invalid_datagrams: 1} = settled(context)
    assert DynamicSupervisor.count_children(context.children.handshake_supervisor).active == 0

    assert Process.alive?(peer)
    assert peer(context) == peer

    # The ticket is still good when the peer gets to it.
    :ok = :sys.resume(peer)
    assert %{peer: ^peer} = responded(context, timestamp(2))
  end

  test "a peer with handoffs waiting refuses more, apart from its inbound queue", context do
    send_datagrams(context, [genuine(context, 1)])
    %{local_index: index, peer: peer} = responded(context, timestamp(1))
    %{handoffs: handoffs, inbound: inbound} = Map.fetch!(interface_state(context).peers, context.peer_key)
    :ok = :sys.suspend(peer)

    # A full inbound queue does not hold up handshakes.
    send_datagrams(context, List.duplicate(transport(index), 200))
    assert eventually(fn -> match?({128, _bytes}, Admission.usage(inbound)) end)

    # Two handoffs may wait for the peer. The third claim is refused, and
    # its timestamp is not recorded.
    for n <- 2..3 do
      advance(context.clock, 20)
      send_datagrams(context, [genuine(context, n)])
      assert %{initiations_accepted: ^n} = counters(context.interface, &(&1.initiations_accepted == n))
    end

    assert Admission.usage(handoffs) == {2, 0}

    advance(context.clock, 20)
    frame = genuine(context, 4)
    send_datagrams(context, [frame])
    assert %{initiations_unavailable: 1, initiations_accepted: 3} = settled(context)

    # Once the peer takes its handoffs, the same initiation is accepted.
    :ok = :sys.resume(peer)
    assert %{peer: ^peer} = responded(context, timestamp(3))
    assert Admission.usage(handoffs) == {0, 0}
    send_datagrams(context, [frame])
    assert %{peer: ^peer} = responded(context, timestamp(4))
  end

  # Killing the peer logs its exit.
  @tag :capture_log
  test "retired and dead-peer indices drop at the interface, and tombstones expire after 180 seconds", context do
    send_datagrams(context, [genuine(context, 1)])
    %{local_index: first, peer: peer} = responded(context, timestamp(1))

    # A newer handshake replaces the unconfirmed one and retires its index.
    advance(context.clock, 20)
    send_datagrams(context, [genuine(context, 2)])
    %{local_index: second} = responded(context, timestamp(2))
    refute second == first
    assert lookup(context, first) == :retired

    send_datagrams(context, [transport(first), transport(second)])
    assert %{inbound_routed: 1, unknown_index: 1} = counters(context.interface, &(&1.datagrams == 4))

    # Once the interface sees the peer exit, its index drops too.
    kill(peer)
    assert eventually(fn -> lookup(context, second) == :retired end)
    assert is_reference(interface_state(context).expiry_timer)

    send_datagrams(context, [transport(second)])
    assert %{inbound_routed: 1, unknown_index: 2} = counters(context.interface, &(&1.datagrams == 5))

    # Both were retired at the same moment and stay tombstones for 180 s.
    advance(context.clock, 179_999)
    send(context.children.interface, :expire_indices)
    assert lookup(context, first) == :retired
    assert lookup(context, second) == :retired

    advance(context.clock, 1)
    send(context.children.interface, :expire_indices)
    assert lookup(context, first) == :unknown
    assert lookup(context, second) == :unknown
    assert interface_state(context).expiry_timer == nil

    send_datagrams(context, [transport(second)])
    assert %{inbound_routed: 1, unknown_index: 3} = counters(context.interface, &(&1.datagrams == 6))
  end

  # Killing the peer logs its exit.
  @tag :capture_log
  test "messages for a live index are bounded by the peer's inbound queue", context do
    send_datagrams(context, [genuine(context, 1)])
    %{local_index: index, peer: peer} = responded(context, timestamp(1))
    :ok = :sys.suspend(peer)

    send_datagrams(context, List.duplicate(transport(index), 200))

    # UDP may lose some of the burst, so check against what arrived.
    counters = settled(context)
    assert counters.datagrams > 128
    assert counters.inbound_routed == 128
    assert counters.inbound_peer_dropped == counters.datagrams - 1 - 128

    # What the peer never took counts as dropped once it exits.
    kill(peer)
    dropped = counters.inbound_peer_dropped + 128
    assert %{inbound_peer_dropped: ^dropped} = counters(context.interface, &(&1.inbound_peer_dropped == dropped))
  end

  test "a flood of genuine and forged initiations does bounded work and starts one peer", context do
    interface = context.children.interface
    supervisor = context.children.handshake_supervisor
    stranger = keypair()

    datagrams =
      for n <- 1..300 do
        case rem(n, 3) do
          0 -> genuine(context, n)
          1 -> noise_initiation(context.public_key, stranger, timestamp(n))
          2 -> initiation(context.public_key)
        end
      end

    sampler = Task.async(fn -> sample(interface, supervisor, %{mailbox: 0, workers: 0}) end)
    send_datagrams(context, datagrams)
    counters = settled(context)
    send(sampler.pid, :stop)
    maxima = Task.await(sampler)

    # Noise runs in at most 8 workers, and the interface keeps draining its
    # socket meanwhile: 32 datagrams per re-arm and the workers' exits.
    assert maxima.workers <= 8
    assert maxima.mailbox <= 48

    # Every datagram that arrived is accounted for. Once 8 wait, the
    # interface is under load, and with its clock stopped it stays so: every
    # initiation after that gets a cookie reply instead. Only one genuine
    # initiation is accepted.
    assert counters.cookie_replies_sent > 0
    assert counters.datagrams == counters.initiations + counters.initiations_dropped + counters.cookie_replies_sent

    assert counters.initiations ==
             counters.initiations_failed + counters.initiations_unknown_peer + counters.initiations_replayed +
               counters.initiations_rate_limited + counters.initiations_unavailable + counters.initiations_accepted

    assert counters.initiations_accepted == 1
    assert [_one] = peer_children(context)
    assert DynamicSupervisor.count_children(supervisor).active == 0
  end

  describe "under load" do
    test "a loaded queue requires MAC2, answering an initiation without it with a cookie reply", context do
      stand_ins = saturate(context, 8)
      {other_key, _private_key} = keypair()
      frame = genuine(context, 1, 77)

      # A MAC1 for another key still gets nothing at all.
      send_datagrams(context, [initiation(other_key), frame])
      reply = cookie_reply_to(context.client, 77)

      assert %{invalid_mac1: 1, cookie_replies_sent: 1, initiations: 0} =
               counters(context.interface, &(&1.cookie_replies_sent == 1))

      assert :gen_udp.recv(context.client, 0, 100) == {:error, :timeout}
      assert interface_state(context).handshakes.queued == 8

      # The cookie decrypts with the interface's public key and the
      # initiation's MAC1. Under it the same initiation waits for a worker,
      # and is accepted once one is free.
      cookie = cookie(reply, context.public_key, frame)
      send_datagrams(context, [with_mac2(frame, context.public_key, cookie)])
      assert eventually(fn -> interface_state(context).handshakes.queued == 9 end)

      for stand_in <- stand_ins, do: send(stand_in, :stop)
      assert %{remote_index: 77} = responded(context, timestamp(1))

      assert %{initiations: 9, initiations_failed: 8, initiations_accepted: 1, cookie_replies_sent: 1} =
               settled(context)
    end

    test "the load lasts for a second after the queue drains", context do
      stand_ins = saturate(context, 8)
      send_datagrams(context, [genuine(context, 1, 1)])
      cookie_reply_to(context.client, 1)

      # The queue drains, with the interface's clock stopped.
      for stand_in <- stand_ins, do: send(stand_in, :stop)
      settled(context)

      advance(context.clock, 999)
      send_datagrams(context, [genuine(context, 2, 2)])
      cookie_reply_to(context.client, 2)

      advance(context.clock, 1)
      send_datagrams(context, [genuine(context, 3, 3)])
      assert %{remote_index: 3} = responded(context, timestamp(3))
      assert %{cookie_replies_sent: 2, initiations_accepted: 1} = settled(context)
    end

    test "the load lasts for a second after the queue drains, however long it was loaded", context do
      # No datagram arrives for two seconds while the queue is loaded.
      stand_ins = saturate(context, 8)
      advance(context.clock, 2_000)
      for stand_in <- stand_ins, do: send(stand_in, :stop)
      settled(context)

      send_datagrams(context, [genuine(context, 1, 1)])
      cookie_reply_to(context.client, 1)

      advance(context.clock, 1_000)
      send_datagrams(context, [genuine(context, 2, 2)])
      assert %{remote_index: 2} = responded(context, timestamp(2))
      assert %{cookie_replies_sent: 1, initiations_accepted: 1} = settled(context)
    end

    test "a cookie is bound to the source address and lasts until its secret is 120 seconds old", context do
      under_load(context)
      frame = genuine(context, 1, 1)
      send_datagrams(context, [frame])
      cookie = context.client |> cookie_reply_to(1) |> cookie(context.public_key, frame)

      # From another port, the same MAC2 earns only a cookie of its own.
      {:ok, other} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}, active: false])
      :ok = :gen_udp.send(other, {127, 0, 0, 1}, context.port, with_mac2(frame, context.public_key, cookie))
      refute other |> cookie_reply_to(1) |> cookie(context.public_key, frame) == cookie
      assert %{cookie_replies_sent: 2, initiations: 0} = counters(context.interface, &(&1.cookie_replies_sent == 2))

      send_datagrams(context, [with_mac2(frame, context.public_key, cookie)])
      assert responded(context, timestamp(1))

      # Its cookies pass while the secret is younger than 120 seconds...
      advance(context.clock, 119_980)
      under_load(context)
      send_datagrams(context, [with_mac2(genuine(context, 2, 2), context.public_key, cookie)])
      assert responded(context, timestamp(2))

      # ...and then it is replaced, and the old cookie earns a new one.
      advance(context.clock, 20)
      under_load(context)
      frame = genuine(context, 3, 3)
      send_datagrams(context, [with_mac2(frame, context.public_key, cookie)])
      fresh = context.client |> cookie_reply_to(3) |> cookie(context.public_key, frame)
      refute fresh == cookie

      send_datagrams(context, [with_mac2(frame, context.public_key, fresh)])
      assert responded(context, timestamp(3))
      assert %{cookie_replies_sent: 3, initiations_accepted: 3} = settled(context)
    end

    test "initiations with a valid MAC2 are limited to bursts of 5 from each source address", context do
      under_load(context)
      frame = genuine(context, 1, 1)
      send_datagrams(context, [frame])
      cookie = context.client |> cookie_reply_to(1) |> cookie(context.public_key, frame)

      send_datagrams(context, for(n <- 1..8, do: with_mac2(genuine(context, n, n), context.public_key, cookie)))
      assert %{initiations: 5, handshakes_rate_limited: 3} = settled(context)

      # Every 50 ms earns one more.
      advance(context.clock, 50)
      send_datagrams(context, for(n <- 9..10, do: with_mac2(genuine(context, n, n), context.public_key, cookie)))
      assert %{initiations: 6, handshakes_rate_limited: 4, cookie_replies_sent: 1} = settled(context)
    end

    test "a response needs a MAC2 too, and one without gets a cookie reply to its sender", context do
      under_load(context)
      covered = <<2, 0, 0, 0, 5::little-32, 6::little-32, :crypto.strong_rand_bytes(48)::binary>>
      response = Packet.put_mac1(covered <> <<0::256>>, Packet.mac1_key(context.public_key))

      send_datagrams(context, [response])
      cookie = context.client |> cookie_reply_to(5) |> cookie(context.public_key, response)
      assert %{cookie_replies_sent: 1, unknown_index: 0} = counters(context.interface, &(&1.cookie_replies_sent == 1))

      # With MAC2 it goes on to its receiver index, which no peer holds.
      send_datagrams(context, [with_mac2(response, context.public_key, cookie)])
      assert %{unknown_index: 1, cookie_replies_sent: 1} = counters(context.interface, &(&1.unknown_index == 1))
    end

    test "transport under existing keys keeps flowing while a flood saturates the workers", context do
      # The test initiates a session, which the peer responds to, and
      # confirms it.
      {frame, session} = initiate_to(context.public_key, context.initiator, timestamp(1), 1)
      send_datagrams(context, [frame])
      assert {:ok, {{127, 0, 0, 1}, _port, response}} = :gen_udp.recv(context.client, 0, 1_000)
      assert <<2, 0, 0, 0, index::little-32, 1::little-32, _rest::binary>> = response
      assert complete(session, response) == :ok
      send_datagrams(context, [transport_frame(session, index)])
      assert %{keys_confirmed: 1} = counters(context.interface, &(&1.keys_confirmed == 1))

      # Genuine and forged initiations, with a keepalive every 30 datagrams.
      stand_ins = saturate(context, 8)
      stranger = keypair()

      flood =
        for n <- 1..300 do
          cond do
            rem(n, 30) == 0 -> transport_frame(session, index)
            rem(n, 2) == 0 -> noise_initiation(context.public_key, stranger, timestamp(n))
            true -> initiation(context.public_key)
          end
        end

      send_datagrams(context, flood)
      assert %{keepalives_received: 11} = counters(context.interface, &(&1.keepalives_received == 11))

      # No initiation in the flood reached a worker; each got a cookie reply.
      counters = quiet(context)
      assert counters.initiations == 1
      assert counters.cookie_replies_sent == counters.datagrams - 12
      assert counters.transport_invalid == 0
      assert DynamicSupervisor.count_children(context.children.handshake_supervisor).active == 0

      for stand_in <- stand_ins, do: send(stand_in, :stop)
    end
  end

  defp sample(interface, supervisor, maxima) do
    receive do
      :stop -> maxima
    after
      0 ->
        {:message_queue_len, mailbox} = Process.info(interface, :message_queue_len)
        %{active: workers} = DynamicSupervisor.count_children(supervisor)
        sample(interface, supervisor, %{mailbox: max(maxima.mailbox, mailbox), workers: max(maxima.workers, workers)})
    end
  end
end
