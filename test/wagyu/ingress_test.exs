defmodule Wagyu.IngressTest do
  # Traces calls in every process, so it runs alone.
  use ExUnit.Case, async: false

  import Wagyu.TestHelpers

  @ingress [{SmolNet, :ingress, 2}, {SmolNet.Stack, :ingress, 2}]

  setup do
    interface = start_supervised!({Wagyu, options()})
    {:ok, stack} = Wagyu.stack(interface)
    %{interface: interface, stack: stack}
  end

  defp trace_ingress do
    for mfa <- @ingress, do: :erlang.trace_pattern(mfa, true, [:global])
    :erlang.trace(:all, true, [:call, {:tracer, self()}])

    on_exit(fn ->
      :erlang.trace(:all, false, [:call])
      for mfa <- @ingress, do: :erlang.trace_pattern(mfa, false, [:global])
    end)
  end

  defp ingress_callers(callers \\ MapSet.new()) do
    receive do
      {:trace, pid, :call, {_module, :ingress, _args}} -> ingress_callers(MapSet.put(callers, pid))
    after
      200 -> callers
    end
  end

  test "decrypted packets reach application sockets, fed only by the link", %{interface: interface, stack: stack} do
    {:ok, socket} = SmolNet.open(:inet, :dgram, :udp, stack: stack)
    :ok = SmolNet.bind(socket, %{family: :inet, addr: {10, 13, 0, 2}, port: 5000})
    trace_ingress()

    # Stand in for a peer that has decrypted three packets from its tunnel.
    packets = for n <- 1..3, do: ipv4_udp({10, 13, 0, 1}, {10, 13, 0, 2}, 9999, 5000, "hello #{n}")
    assert Wagyu.Link.deliver(interface, packets) == 0

    for n <- 1..3 do
      assert {:ok, %{data: data, source: %{addr: {10, 13, 0, 1}, port: 9999}}} = SmolNet.recvfrom(socket, 0, 1_000)
      assert data == "hello #{n}"
    end

    # Exercise the other paths too: egress to a peer and inbound datagrams.
    send_egress(socket, 2)
    {:ok, %{listen: %{port: port}}} = Wagyu.info(interface)
    {:ok, client} = :gen_udp.open(0, ip: {127, 0, 0, 1})
    :ok = :gen_udp.send(client, {127, 0, 0, 1}, port, "not wireguard")

    assert %{ingress: 3, ingress_dropped: 0} =
             counters(interface, &(&1.ingress == 3 and &1.egress_routed == 2 and &1.datagrams == 1))

    assert ingress_callers() == MapSet.new([child(interface, :link)])
  end
end
