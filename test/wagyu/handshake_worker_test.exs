defmodule Wagyu.HandshakeWorkerTest do
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.Config
  alias Wagyu.HandshakeWorker
  alias Wagyu.Noise
  alias Wagyu.Packet

  @source {{127, 0, 0, 1}, 51_820}
  @zero_psk <<0::256>>

  setup do
    {:ok, identity} = Config.new(private_key: elem(keypair(), 1))
    %{identity: identity, initiator: keypair()}
  end

  # A claim that reports each call to the test process and answers `result`.
  defp claim(result) do
    test = self()

    fn remote_key, timestamp ->
      send(test, {:claim, remote_key, timestamp})
      result
    end
  end

  # Responder sessions for `respond/5`'s second read, made for `identity`.
  # Each one is reported to the test process.
  defp responder(identity) do
    test = self()

    fn psk ->
      session = Noise.responder(identity, psk)
      send(test, {:responder, psk, session})
      session
    end
  end

  defp peer_config(psk), do: %Config.Peer{public_key: elem(keypair(), 0), preshared_key: psk}

  defp respond(context, session, frame, claim),
    do: HandshakeWorker.respond(session, frame, @source, claim, responder(context.identity))

  # A stand-in peer. It reports every message it receives, accepts a ticket
  # in its own process when told to, and exits with the test.
  defp target do
    test = self()

    spawn(fn ->
      monitor = Process.monitor(test)
      target_loop(test, monitor)
    end)
  end

  defp target_loop(test, monitor) do
    receive do
      {:DOWN, ^monitor, :process, _test, _reason} -> exit(:normal)
      {:accept, ticket} -> send(test, {:target_accepted, accept(ticket)})
      {:respond, ticket, mac1_key} -> send(test, {:target_responded, write_response(ticket, mac1_key)})
      message -> send(test, {:target_received, message})
    end

    target_loop(test, monitor)
  end

  defp accept(ticket) do
    {:ok, Decibel.handshake_complete?(Decibel.accept_handoff(ticket))}
  rescue
    error in Decibel.HandoffError -> {:error, error.reason}
  end

  # Accepts a ticket and writes the response to sender index 77 from it.
  defp write_response(ticket, mac1_key) do
    {:ok, frame} = ticket |> Decibel.accept_handoff() |> Noise.write_response(1, 77, mac1_key)
    frame
  end

  defp kill(pid) do
    monitor = Process.monitor(pid)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :killed}
  end

  test "hands an authenticated initiation to the claimed peer, which alone accepts it once", context do
    {initiator_key, _private_key} = context.initiator
    frame = noise_initiation(context.identity.public_key, context.initiator, timestamp(1), 77)
    session = Noise.responder(context.identity)
    peer = target()

    assert respond(context, session, frame, claim({:ok, peer, peer_config(@zero_psk)})) == {:ok, peer}

    expected_timestamp = timestamp(1)
    assert_received {:claim, ^initiator_key, ^expected_timestamp}

    assert_receive {:target_received,
                    {:wg_handoff, ticket, %{sender_index: 77, timestamp: ^expected_timestamp, source: @source}}}

    # The handoff closed the worker's handle, and only the peer can accept.
    assert closed?(session)
    assert accept(ticket) == {:error, :not_target}

    send(peer, {:accept, ticket})
    assert_receive {:target_accepted, {:ok, false}}

    send(peer, {:accept, ticket})
    assert_receive {:target_accepted, {:error, :unavailable}}
  end

  test "a failed authentication claims nothing, sends nothing and closes the session", context do
    {other_key, _private_key} = keypair()
    genuine = noise_initiation(context.identity.public_key, context.initiator, timestamp(1))
    <<header::binary-8, ephemeral::binary-32, rest::binary>> = genuine
    flipped = :crypto.exor(ephemeral, <<1, 0::248>>)

    frames = [
      # Arbitrary Noise fields.
      initiation(context.identity.public_key),
      # A genuine initiation for another responder.
      noise_initiation(other_key, context.initiator, timestamp(1)),
      # A genuine initiation with one bit of its ephemeral key changed.
      <<header::binary, flipped::binary, rest::binary>>,
      # An all-zero ephemeral key, which X25519 rejects.
      <<header::binary, 0::256, rest::binary>>
    ]

    peer = target()

    for frame <- frames do
      session = Noise.responder(context.identity)
      claim = claim({:ok, peer, peer_config(:binary.copy(<<7>>, 32))})
      assert respond(context, session, frame, claim) == {:error, :authentication_failed}
      assert closed?(session)
    end

    # Nor does it read again with the peer's preshared key.
    refute_received {:claim, _key, _timestamp}
    refute_received {:responder, _psk, _session}
    refute_receive {:target_received, _message}, 50
  end

  test "a rejected claim sends nothing and closes the session", context do
    for reason <- [:unknown_peer, :replayed, :rate_limited, :unavailable] do
      frame = noise_initiation(context.identity.public_key, context.initiator, timestamp(1))
      session = Noise.responder(context.identity)

      assert respond(context, session, frame, claim({:error, reason})) == {:error, reason}
      assert_received {:claim, _key, _timestamp}
      assert closed?(session)
    end

    # The claim's reports were the only messages.
    refute_received _message
  end

  test "a peer that exits before the handoff gets nothing and the session is closed", context do
    peer = target()
    kill(peer)
    frame = noise_initiation(context.identity.public_key, context.initiator, timestamp(1))
    session = Noise.responder(context.identity)

    assert respond(context, session, frame, claim({:ok, peer, peer_config(@zero_psk)})) == {:error, :handoff_failed}
    assert closed?(session)

    # With a preshared key, the session of the second read is closed too.
    session = Noise.responder(context.identity)

    assert respond(context, session, frame, claim({:ok, peer, peer_config(:binary.copy(<<7>>, 32))})) ==
             {:error, :handoff_failed}

    assert_received {:responder, _psk, rekeyed}
    assert closed?(session) and closed?(rekeyed)
  end

  test "a ticket its peer never accepts is discarded when that peer exits", context do
    frame = noise_initiation(context.identity.public_key, context.initiator, timestamp(1))
    session = Noise.responder(context.identity)
    peer = target()

    assert {:ok, ^peer} = respond(context, session, frame, claim({:ok, peer, peer_config(@zero_psk)}))
    assert_receive {:target_received, {:wg_handoff, ticket, _metadata}}

    # Nothing is waiting on the peer: the worker has nothing left, and the
    # ticket stays claimable only by the peer, which nobody kills.
    assert closed?(session)
    assert accept(ticket) == {:error, :not_target}
    assert Process.alive?(peer)

    kill(peer)
    assert eventually(fn -> accept(ticket) == {:error, :unavailable} end)
  end

  describe "a peer with a preshared key" do
    setup context do
      Map.merge(context, %{psk: :binary.copy(<<7>>, 32), mac1_key: Packet.mac1_key(elem(context.initiator, 0))})
    end

    # Hands an initiation made with `psk` to a peer whose key is `peer_psk`,
    # and returns the response the peer writes and the initiator's session,
    # waiting for it.
    defp exchange(context, psk, peer_psk) do
      {frame, initiator} = initiate_to(context.identity.public_key, context.initiator, timestamp(1), 77, psk)
      session = Noise.responder(context.identity)
      peer = target()

      assert respond(context, session, frame, claim({:ok, peer, peer_config(peer_psk)})) == {:ok, peer}
      assert_receive {:target_received, {:wg_handoff, ticket, %{sender_index: 77}}}
      send(peer, {:respond, ticket, context.mac1_key})
      assert_receive {:target_responded, response}

      # The session of the first read, without the key, was closed rather
      # than handed off.
      assert_received {:responder, ^peer_psk, _rekeyed}
      assert closed?(session)
      {response, initiator}
    end

    test "gets a session read again with its key, which completes with its initiator", context do
      {response, initiator} = exchange(context, context.psk, context.psk)
      assert complete(initiator, response) == :ok
    end

    test "an initiator with another key, or none, rejects the response", context do
      for initiator_psk <- [:binary.copy(<<8>>, 32), @zero_psk] do
        {response, initiator} = exchange(context, initiator_psk, context.psk)
        assert complete(initiator, response) == :error
      end
    end

    test "an initiator with a key rejects the response of a peer without one", context do
      {frame, initiator} = initiate_to(context.identity.public_key, context.initiator, timestamp(1), 77, context.psk)
      peer = target()

      assert respond(context, Noise.responder(context.identity), frame, claim({:ok, peer, peer_config(@zero_psk)})) ==
               {:ok, peer}

      assert_receive {:target_received, {:wg_handoff, ticket, _metadata}}
      send(peer, {:respond, ticket, context.mac1_key})
      assert_receive {:target_responded, response}

      # A peer without a key reads once.
      refute_received {:responder, _psk, _session}
      assert complete(initiator, response) == :error
    end

    test "a second read that fails hands off nothing and releases the claimed handoff", context do
      {:ok, other} = Config.new(private_key: elem(keypair(), 1))
      frame = noise_initiation(context.identity.public_key, context.initiator, timestamp(1), 77, context.psk)
      session = Noise.responder(context.identity)
      peer = target()

      # A responder for another interface cannot read the initiation.
      assert HandshakeWorker.respond(
               session,
               frame,
               @source,
               claim({:ok, peer, peer_config(context.psk)}),
               responder(other)
             ) ==
               {:error, :preshared_key_failed}

      assert_received {:responder, _psk, rekeyed}
      assert closed?(session) and closed?(rekeyed)
      assert_receive {:target_received, :wg_handoff_abandoned}
      refute_receive {:target_received, _message}, 50
    end
  end

  describe "a worker process" do
    # The test process stands in for the interface, answering claims, and
    # traps exits to see how each worker ends.
    setup context do
      Process.flag(:trap_exit, true)
      root = make_ref()
      :ok = Wagyu.Registry.register(root, :interface, %{})
      Map.put(context, :root, root)
    end

    defp start_worker(context, frame) do
      {:ok, worker} = HandshakeWorker.start_link(context.identity, %{root: context.root, frame: frame, source: @source})
      worker
    end

    test "claims through its interface, hands off and exits normally", context do
      {initiator_key, _private_key} = context.initiator
      peer = target()
      worker = start_worker(context, noise_initiation(context.identity.public_key, context.initiator, timestamp(3)))

      expected_timestamp = timestamp(3)
      assert_receive {:"$gen_call", from, {:claim_peer, ^initiator_key, ^expected_timestamp}}
      GenServer.reply(from, {:ok, peer, peer_config(@zero_psk)})

      assert_receive {:target_received, {:wg_handoff, _ticket, %{timestamp: ^expected_timestamp}}}
      assert_receive {:EXIT, ^worker, :normal}
    end

    test "reads again with its peer's preshared key before handing off", context do
      {initiator_key, _private_key} = context.initiator
      psk = :binary.copy(<<7>>, 32)
      peer = target()
      {frame, initiator} = initiate_to(context.identity.public_key, context.initiator, timestamp(3), 77, psk)
      worker = start_worker(context, frame)

      assert_receive {:"$gen_call", from, {:claim_peer, ^initiator_key, _timestamp}}
      GenServer.reply(from, {:ok, peer, peer_config(psk)})

      assert_receive {:target_received, {:wg_handoff, ticket, _metadata}}
      assert_receive {:EXIT, ^worker, :normal}
      send(peer, {:respond, ticket, Packet.mac1_key(initiator_key)})
      assert_receive {:target_responded, response}
      assert complete(initiator, response) == :ok
    end

    test "exits normally when its claim is rejected", context do
      worker = start_worker(context, noise_initiation(context.identity.public_key, context.initiator, timestamp(3)))

      assert_receive {:"$gen_call", from, {:claim_peer, _key, _timestamp}}
      GenServer.reply(from, {:error, :replayed})

      assert_receive {:EXIT, ^worker, :normal}
    end

    test "exits with a shutdown reason, having claimed nothing, when authentication fails", context do
      worker = start_worker(context, initiation(context.identity.public_key))

      assert_receive {:EXIT, ^worker, {:shutdown, :authentication_failed}}
      refute_received {:"$gen_call", _from, _request}
    end
  end
end
