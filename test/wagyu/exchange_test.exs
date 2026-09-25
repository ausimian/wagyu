defmodule Wagyu.ExchangeTest do
  # Two Wagyu interfaces, each the other's configured peer, completing
  # handshakes over loopback UDP. The interfaces run on fake clocks.
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.Noise

  setup do
    {a_key, a_private} = keypair()
    {b_key, b_private} = keypair()
    [a_port, b_port] = [free_port(), free_port()]

    a =
      start_side(:a, a_private, a_port, {{10, 13, 0, 2}, {10, 13, 0, 1}}, %{
        public_key: b_key,
        endpoint: %{address: {127, 0, 0, 1}, port: b_port},
        allowed_ips: [{{0, 0, 0, 0}, 0}]
      })

    b =
      start_side(:b, b_private, b_port, {{10, 13, 0, 1}, {10, 13, 0, 2}}, %{
        public_key: a_key,
        endpoint: %{address: {127, 0, 0, 1}, port: a_port},
        allowed_ips: [{{0, 0, 0, 0}, 0}]
      })

    %{a: Map.put(a, :peer_key, b_key), b: Map.put(b, :peer_key, a_key)}
  end

  defp start_side(id, private_key, port, {address, gateway}, peer) do
    options =
      options(
        private_key: private_key,
        listen: %{address: {127, 0, 0, 1}, port: port},
        stack: [addresses: [{address, 32}], routes: [{{0, 0, 0, 0}, 0, gateway}], mtu: 1280],
        peers: [peer]
      )

    interface = start_supervised!(Supervisor.child_spec({Wagyu, options}, id: id))
    children = children(interface)
    {:ok, stack} = Wagyu.stack(interface)
    {:ok, udp} = SmolNet.open(:inet, :dgram, :udp, stack: stack)
    :ok = SmolNet.bind(udp, %{family: :inet, addr: address, port: 0})

    %{
      interface: interface,
      children: children,
      clock: fake_clock(children.interface),
      udp: udp,
      gateway: gateway,
      port: port
    }
  end

  # An outbound packet to the other side's tunnel address.
  defp demand(side), do: :ok = SmolNet.sendto(side.udp, "hello", %{family: :inet, addr: side.gateway, port: 9})

  defp peer(%{peer_key: key} = side) do
    case :sys.get_state(side.children.interface).peers do
      %{^key => %{pid: pid}} -> pid
      _not_running -> nil
    end
  end

  # The handshake hash and indices of each key pair the side's peer holds.
  defp key_pairs(side) do
    in_process(peer(side), fn state ->
      for slot <- [:next, :current, :previous], key_pair = Map.fetch!(state, slot), key_pair != nil, into: %{} do
        {slot, {Decibel.handshake_hash(key_pair.session), key_pair.local_index, key_pair.remote_index}}
      end
    end)
  end

  defp established?(side), do: peer(side) != nil and Map.has_key?(key_pairs(side), :current)

  # Whether `a`'s current key pair is the same handshake as one of `b`'s,
  # seen from the other end.
  defp matches?(a, b, slots) do
    {hash, local, remote} = Map.fetch!(key_pairs(a), :current)
    b = key_pairs(b)
    Enum.any?(slots, &(Map.get(b, &1) == {hash, remote, local}))
  end

  # Sends a message under `from`'s current key to `to`, which authenticates
  # it and then drops it, since it is not an IP packet.
  defp transport_to(from, to) do
    frame =
      in_process(peer(from), fn %{current: key_pair} ->
        {:ok, frame} = Noise.seal(key_pair.session, key_pair.remote_index, "data")
        frame
      end)

    {:ok, socket} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}])
    %{transport_malformed: malformed} = counters(to.interface)
    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, to.port, frame)
    assert counters(to.interface, &(&1.transport_malformed == malformed + 1))
  end

  defp peer_count(side), do: DynamicSupervisor.count_children(side.children.peer_supervisor).active

  test "a handshake derives matching transport sessions on both sides", %{a: a, b: b} do
    demand(a)
    assert eventually(fn -> established?(a) and established?(b) end)

    # A initiated and B responded; the packet that started it confirmed the
    # key to B.
    assert matches?(a, b, [:current])
    assert %{initiations_sent: 1, responses_accepted: 1, transport_sent: 1} = counters(a.interface)
    assert %{responses_sent: 1, keys_confirmed: 1} = counters(b.interface)

    # Each side's sending key is the other's receiving key.
    transport_to(a, b)
    transport_to(b, a)
    assert %{transport_invalid: 0} = counters(a.interface)
    assert %{transport_invalid: 0} = counters(b.interface)
  end

  test "rekeys from either side reuse both peer processes", %{a: a, b: b} do
    demand(a)
    assert eventually(fn -> established?(a) and established?(b) end)
    {a_peer, b_peer} = {peer(a), peer(b)}

    for {initiator, responder, n} <- [{b, a, 2}, {a, b, 3}] do
      # REKEY_TIMEOUT has passed since the initiator's last handshake
      # message, and 20 ms since the responder last accepted an initiation.
      advance(fake_clock(peer(initiator), System.monotonic_time(:millisecond)), 5_000)
      advance(responder.clock, 20)
      send(peer(initiator), :wg_initiate)

      assert eventually(fn ->
               %{keys_confirmed: confirmed} = counters(responder.interface)
               confirmed == n - 1 and matches?(initiator, responder, [:current])
             end)

      # The old key pair is each side's previous one.
      assert %{previous: _previous} = key_pairs(initiator)
      assert %{previous: _previous} = key_pairs(responder)
    end

    assert {peer(a), peer(b)} == {a_peer, b_peer}
    assert peer_count(a) == 1 and peer_count(b) == 1
  end

  test "simultaneous initiations converge without another peer process", %{a: a, b: b} do
    demand(a)
    demand(b)

    # Each side completes its own initiation and responds to the other's,
    # so each sends under its own handshake and receives under both.
    assert eventually(fn -> established?(a) and established?(b) end)
    assert eventually(fn -> matches?(a, b, [:current, :previous]) and matches?(b, a, [:current, :previous]) end)

    transport_to(a, b)
    transport_to(b, a)

    for side <- [a, b] do
      assert %{transport_invalid: 0, responses_invalid: 0} = counters(side.interface)
      assert peer_count(side) == 1
    end
  end
end
