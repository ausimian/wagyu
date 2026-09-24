defmodule Wagyu.RegistryTest do
  # Restarts the registry that every interface uses, so it runs alone.
  use ExUnit.Case, async: false

  import Wagyu.TestHelpers

  # The interface's processes log their exits.
  @moduletag :capture_log

  test "an interface rebuilds and registers again when the registry restarts" do
    name = :wagyu_registry_test
    interface = start_supervised!({Wagyu, options(name: name)})
    old = children(interface)
    {:ok, stack} = Wagyu.stack(interface)
    stack_monitor = SmolNet.monitor(stack)

    # The partition owns the registry's tables, so its crash loses every
    # registration, and the registry restarts it empty.
    [{_id, partition, :worker, _modules}] = Supervisor.which_children(Wagyu.Registry)
    monitor = Process.monitor(partition)
    Process.exit(partition, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^partition, :killed}

    # The interface keeps its root and name, and everything under it is new.
    assert_receive {:DOWN, ^stack_monitor, :process, _object, _reason}

    new =
      eventually(fn ->
        if Enum.all?(Map.keys(old), &(child(interface, &1) not in [nil, old[&1]])), do: children(interface)
      end)

    assert Process.whereis(name) == interface
    assert Map.values(new) -- Map.values(old) == Map.values(new)

    assert {:ok, new_stack} = Wagyu.stack(name)
    refute new_stack == stack
    send_egress(open_udp(new_stack), 1)
    assert %{egress_routed: 1} = counters(name, &(&1.egress_routed == 1))
  end
end
