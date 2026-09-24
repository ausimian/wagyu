defmodule Wagyu.SupervisionTest do
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  # Killing an interface's processes logs their exits.
  @moduletag :capture_log

  setup do
    port = free_port()
    interface = start_supervised!({Wagyu, options(listen: %{address: {127, 0, 0, 1}, port: port})})
    {:ok, stack} = Wagyu.stack(interface)
    {:ok, client} = :gen_udp.open(0, ip: {127, 0, 0, 1})
    %{interface: interface, stack: stack, port: port, client: client, children: children(interface)}
  end

  # Waits until every role in `changed` has a new process and returns the
  # children.
  defp restarted(interface, old, changed) do
    eventually(fn ->
      children = children(interface)
      if Enum.all?(changed, &(children[&1] != old[&1])), do: children
    end)
  end

  defp kill(pid) do
    monitor = Process.monitor(pid)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :killed}
  end

  defp start_peer(interface, socket) do
    {:ok, %{counters: %{egress_routed: routed}}} = Wagyu.info(interface)
    send_egress(socket, 1)
    counters(interface, &(&1.egress_routed == routed + 1))
    [{_id, peer, _type, _modules}] = DynamicSupervisor.which_children(child(interface, :peer_supervisor))
    peer
  end

  defp assert_receives_datagrams(%{interface: interface, client: client, port: port}) do
    {:ok, %{counters: %{datagrams: received}}} = Wagyu.info(interface)
    :ok = :gen_udp.send(client, {127, 0, 0, 1}, port, "still listening")
    counters(interface, &(&1.datagrams == received + 1))
  end

  defp assert_stack_replaced(context, socket) do
    stack_monitor = SmolNet.monitor(context.stack)
    assert_receive {:DOWN, ^stack_monitor, :process, _object, _reason}

    children =
      restarted(context.interface, context.children, [:link, :interface, :handshake_supervisor, :peer_supervisor])

    assert {:ok, stack} = Wagyu.stack(context.interface)
    refute stack == context.stack
    assert {:error, _reason} = SmolNet.sockname(socket)

    send_egress(open_udp(stack), 1)
    assert %{egress: 1, egress_routed: 1} = counters(context.interface, &(&1.egress_routed == 1))
    assert_receives_datagrams(context)
    children
  end

  test "a link failure restarts the whole interface and invalidates old sockets", context do
    socket = open_udp(context.stack)
    peer = start_peer(context.interface, socket)

    kill(context.children.link)

    assert_stack_replaced(context, socket)
    refute Process.alive?(peer)
  end

  test "stopping the stack with SmolNet.stop_stack/1 restarts the whole interface", context do
    socket = open_udp(context.stack)

    assert :ok = SmolNet.stop_stack(context.stack)

    assert_stack_replaced(context, socket)
  end

  test "an interface failure keeps the link, the stack and open sockets", context do
    socket = open_udp(context.stack)
    peer = start_peer(context.interface, socket)

    kill(context.children.interface)

    children = restarted(context.interface, context.children, [:interface, :handshake_supervisor, :peer_supervisor])
    assert children.link == context.children.link
    assert Wagyu.stack(context.interface) == {:ok, context.stack}
    refute Process.alive?(peer)

    # The socket opened before the failure still sends, through the same
    # link, to the new interface, which starts a new peer.
    assert {:ok, _address} = SmolNet.sockname(socket)
    assert start_peer(context.interface, socket) != peer
    assert_receives_datagrams(context)
  end

  test "a peer supervisor failure removes its peers and keeps the interface", context do
    socket = open_udp(context.stack)
    peer = start_peer(context.interface, socket)

    kill(context.children.peer_supervisor)

    children = restarted(context.interface, context.children, [:peer_supervisor])
    assert Map.delete(children, :peer_supervisor) == Map.delete(context.children, :peer_supervisor)
    refute Process.alive?(peer)

    assert eventually(fn ->
             {:ok, %{peers: [%{running: running}]}} = Wagyu.info(context.interface)
             not running
           end)

    assert start_peer(context.interface, socket) != peer
  end

  test "a handshake supervisor failure restarts the workers and peers but keeps the interface", context do
    socket = open_udp(context.stack)
    peer = start_peer(context.interface, socket)

    kill(context.children.handshake_supervisor)

    children = restarted(context.interface, context.children, [:handshake_supervisor, :peer_supervisor])
    assert children.interface == context.children.interface
    refute Process.alive?(peer)
  end
end
