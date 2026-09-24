defmodule Wagyu.InteropTest do
  # Interoperability with wireguard-go, run by `wgpeer` (test/interop) on
  # gVisor's userspace network stack. Two Wagyu interfaces cannot catch a
  # mistake both make the same way, such as a wrong MAC1 key or TAI64N base;
  # wireguard-go can. These tests need Go (see test_helper.exs).
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.WgPeer

  @moduletag :interop

  # wireguard-go's netstack address.
  @go_address {10, 13, 0, 1}

  setup_all do
    %{wgpeer: WgPeer.build!()}
  end

  setup %{wgpeer: wgpeer} do
    {go_key, go_private} = keypair()
    {wagyu_key, wagyu_private} = keypair()
    %{wgpeer: wgpeer, go_key: go_key, go_private: go_private, wagyu_key: wagyu_key, wagyu_private: wagyu_private}
  end

  defp start_go(context, peer) do
    uapi =
      [private_key: context.go_private, listen_port: 0, public_key: context.wagyu_key] ++
        peer ++ [allowed_ip: "10.13.0.2/32"]

    WgPeer.start!(context.wgpeer, @go_address, uapi)
  end

  test "wgpeer runs a configured wireguard-go device on a real UDP port", context do
    {device, port} = start_go(context, [])
    assert port in 1..65_535

    assert %{peers: [%{"public_key" => public_key, "last_handshake_time_sec" => "0"}]} = WgPeer.get(device)
    assert public_key == Base.encode16(context.wagyu_key, case: :lower)
  end

  test "wgpeer vectors still prints the golden transcript", %{wgpeer: wgpeer} do
    assert WgPeer.vectors!(wgpeer) == Wagyu.GoldenVectors.hex()
  end
end
