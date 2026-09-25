defmodule Wagyu.PresharedKeyTest do
  # Handshakes through a running interface with peers that have preshared
  # keys, distinct from each other, and a peer that has none. The test
  # plays each remote party on its own UDP socket. The interface runs on a
  # fake clock.
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.Packet
  alias Wagyu.Packet.{Initiation, Response}

  @zero_psk <<0::256>>

  setup do
    {public_key, private_key} = keypair()

    remotes =
      for {id, psk, subnet} <- [{:a, :binary.copy(<<7>>, 32), 1}, {:b, :binary.copy(<<8>>, 32), 2}, {:none, nil, 3}],
          into: %{} do
        {:ok, socket} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}, active: false])
        {:ok, port} = :inet.port(socket)
        {remote_key, _private_key} = key_pair = keypair()

        peer = %{
          public_key: remote_key,
          endpoint: %{address: {127, 0, 0, 1}, port: port},
          allowed_ips: [{{10, 13, subnet, 0}, 24}]
        }

        peer = if psk, do: Map.put(peer, :preshared_key, psk), else: peer

        {id,
         %{
           socket: socket,
           key_pair: key_pair,
           key: remote_key,
           psk: psk || @zero_psk,
           destination: {10, 13, subnet, 9},
           peer: peer
         }}
      end

    options = options(private_key: private_key, peers: Enum.map([:a, :b, :none], &remotes[&1].peer))
    interface = start_supervised!({Wagyu, options})
    %{interface: pid} = children = children(interface)
    clock = fake_clock(pid)
    {:ok, %{listen: %{port: port}}} = Wagyu.info(interface)
    {:ok, stack} = Wagyu.stack(interface)

    %{
      interface: interface,
      children: children,
      clock: clock,
      public_key: public_key,
      port: port,
      udp: open_udp(stack),
      remotes: remotes
    }
  end

  defp send_to_interface(context, remote, frame),
    do: :ok = :gen_udp.send(remote.socket, {127, 0, 0, 1}, context.port, frame)

  defp recv(remote) do
    {:ok, {{127, 0, 0, 1}, _port, frame}} = :gen_udp.recv(remote.socket, 0, 1_000)
    frame
  end

  # The remote party initiates with `psk` and returns the response and its
  # session, waiting for it.
  defp initiate(context, remote, psk, n \\ 1) do
    {frame, session} = initiate_to(context.public_key, remote.key_pair, timestamp(n), random_index(), psk)
    send_to_interface(context, remote, frame)
    response = recv(remote)
    assert {:ok, %Response{}} = Packet.decode(response)
    {response, session}
  end

  defp peer_state(context, remote) do
    %{pid: pid} = Map.fetch!(:sys.get_state(context.children.interface).peers, remote.key)
    :sys.get_state(pid)
  end

  describe "responding" do
    test "peers with distinct keys, and one without, complete concurrent handshakes", context do
      remotes = Map.values(context.remotes)

      initiations =
        for remote <- remotes do
          {frame, session} = initiate_to(context.public_key, remote.key_pair, timestamp(1), random_index(), remote.psk)
          {remote, frame, session}
        end

      # Every initiation arrives before any response is read.
      for {remote, frame, _session} <- initiations, do: send_to_interface(context, remote, frame)

      for {remote, _frame, session} <- initiations do
        response = recv(remote)
        assert complete(session, response) == :ok

        # A keepalive under the new key confirms it.
        {:ok, %Response{sender_index: index}} = Packet.decode(response)
        send_to_interface(context, remote, transport_frame(session, index))
      end

      assert %{initiations_accepted: 3, responses_sent: 3, keys_confirmed: 3, transport_invalid: 0} =
               counters(context.interface, &(&1.keys_confirmed == 3))
    end

    test "a wrong or missing key, or one the peer lacks, leaves no usable key on either side", context do
      %{a: a, b: b, none: none} = context.remotes

      for {remote, psk} <- [{a, b.psk}, {b, @zero_psk}, {none, a.psk}] do
        {response, session} = initiate(context, remote, psk)

        # The initiator rejects the response, so it has no key to send
        # with, and the responder's key waits, unconfirmed, in `:next`.
        assert complete(session, response) == :error
        assert %{next: %{}, current: nil} = peer_state(context, remote)

        # A packet for the peer is not sent under that key. It waits for a
        # handshake of the peer's own, which is not due within 5 seconds of
        # its response.
        :ok = SmolNet.sendto(context.udp, "hello", %{family: :inet, addr: remote.destination, port: 9})
        assert eventually(fn -> :queue.len(peer_state(context, remote).staged) == 1 end)
        assert {:error, :timeout} = :gen_udp.recv(remote.socket, 0, 50)
      end

      assert %{responses_sent: 3, keys_confirmed: 0, transport_sent: 0} = counters(context.interface)
    end

    test "a forged initiation to a peer with a key starts nothing", context do
      send_to_interface(context, context.remotes.a, initiation(context.public_key))

      assert %{initiations_failed: 1, initiations_accepted: 0, responses_sent: 0} =
               counters(context.interface, &(&1.initiations_failed == 1))

      assert :sys.get_state(context.children.interface).peers == %{}
    end
  end

  describe "initiating" do
    # Sends a packet to `remote`'s AllowedIPs and returns the initiation the
    # interface sends it.
    defp demand(context, remote) do
      :ok = SmolNet.sendto(context.udp, "hello", %{family: :inet, addr: remote.destination, port: 9})
      initiation = recv(remote)
      assert {:ok, %Initiation{}} = Packet.decode(initiation)
      initiation
    end

    test "each peer's initiation is answered with its own key", context do
      for remote <- Map.values(context.remotes) do
        initiation = demand(context, remote)
        {response, session, _read} = respond_to(initiation, remote.key_pair, random_index(), remote.psk)
        send_to_interface(context, remote, response)

        # The packet that waited for the key comes under it.
        assert {:ok, packet} = open_transport(session, recv(remote))
        assert byte_size(packet) > 0
      end

      assert %{initiations_sent: 3, responses_accepted: 3, responses_invalid: 0} =
               counters(context.interface, &(&1.responses_accepted == 3))
    end

    test "a response made with a wrong or missing key is refused", context do
      %{a: a, b: b, none: none} = context.remotes

      for {remote, psk} <- [{a, b.psk}, {b, @zero_psk}, {none, a.psk}] do
        initiation = demand(context, remote)
        {response, _session, _read} = respond_to(initiation, remote.key_pair, random_index(), psk)
        send_to_interface(context, remote, response)

        assert eventually(fn -> peer_state(context, remote).initiation != nil end)
        assert %{current: nil, next: nil} = peer_state(context, remote)
      end

      assert %{responses_accepted: 0, responses_invalid: 3, transport_sent: 0} =
               counters(context.interface, &(&1.responses_invalid == 3))
    end
  end
end
