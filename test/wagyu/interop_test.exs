defmodule Wagyu.InteropTest do
  # Interoperability with wireguard-go, run by `wgpeer` (test/interop) on
  # gVisor's userspace network stack. Two Wagyu interfaces cannot catch a
  # mistake both make the same way, such as a wrong MAC1 key or TAI64N base;
  # wireguard-go can. These tests need Go (see test_helper.exs).
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.WgPeer

  @moduletag :interop

  # wireguard-go's netstack address and Wagyu's stack address.
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

  defp start_go(context, peer) do
    uapi =
      [private_key: context.go_private, listen_port: 0, public_key: context.wagyu_key] ++
        peer ++ [allowed_ip: "10.13.0.2/32"]

    WgPeer.start!(context.wgpeer, @go_address, uapi)
  end

  # Waits for wireguard-go to record a completed handshake with Wagyu, and
  # returns its view of the peer.
  defp go_handshake(device) do
    eventually(fn ->
      %{peers: [peer]} = WgPeer.get(device)
      if peer["last_handshake_time_sec"] != "0", do: peer
    end)
  end

  defp wagyu_peer(wagyu) do
    [{_id, pid, _type, _modules}] = DynamicSupervisor.which_children(wagyu.children.peer_supervisor)
    pid
  end

  test "wgpeer runs a configured wireguard-go device on a real UDP port", context do
    {device, port} = start_go(context, [])
    assert port in 1..65_535

    assert %{peers: [%{"public_key" => public_key, "last_handshake_time_sec" => "0"}]} = WgPeer.get(device)
    assert public_key == Base.encode16(context.wagyu_key, case: :lower)
  end

  test "Wagyu initiates, wireguard-go responds, and Wagyu's keepalive confirms the key", context do
    {device, go_port} = start_go(context, [])
    wagyu = start_wagyu(context, %{address: {127, 0, 0, 1}, port: go_port})

    # An outbound packet starts the handshake.
    {:ok, stack} = Wagyu.stack(wagyu.interface)
    {:ok, socket} = SmolNet.open(:inet, :dgram, :udp, stack: stack)
    :ok = SmolNet.bind(socket, %{family: :inet, addr: @wagyu_address, port: 0})
    :ok = SmolNet.sendto(socket, "hello", %{family: :inet, addr: @go_address, port: 9})

    # wireguard-go records the handshake only once a transport message
    # authenticates under the new key, which here is Wagyu's keepalive.
    peer = go_handshake(device)
    assert String.to_integer(peer["rx_bytes"]) > 0
    assert peer["endpoint"] == "127.0.0.1:#{wagyu.port}"

    assert %{initiations_sent: 1, responses_accepted: 1, keepalives_sent: 1, responses_invalid: 0} =
             counters(wagyu.interface)

    assert %{current: %{}, next: nil} = :sys.get_state(wagyu_peer(wagyu))
  end

  test "wireguard-go initiates, Wagyu responds, and wireguard-go's first packet confirms the key", context do
    # Wagyu has no endpoint for wireguard-go and learns it from the initiation.
    wagyu = start_wagyu(context, nil)
    {device, go_port} = start_go(context, endpoint: "127.0.0.1:#{wagyu.port}")

    # A packet from wireguard-go's netstack to Wagyu's address starts the
    # handshake, and wireguard-go sends it under the new key once Wagyu has
    # responded.
    :ok = WgPeer.send_udp(device, @wagyu_address, 9, "hello")

    assert %{responses_sent: 1, keys_confirmed: 1, transport_invalid: 0} =
             counters(wagyu.interface, &(&1.keys_confirmed == 1))

    assert %{current: %{}, next: nil, endpoint: endpoint} = :sys.get_state(wagyu_peer(wagyu))
    assert endpoint == {{127, 0, 0, 1}, go_port}
    assert go_handshake(device)
  end

  test "wgpeer vectors still prints the golden transcript", %{wgpeer: wgpeer} do
    assert WgPeer.vectors!(wgpeer) == Wagyu.GoldenVectors.hex()
  end
end
