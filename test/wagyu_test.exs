defmodule WagyuTest do
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.Config

  defp unique_name, do: :"wagyu_test_#{System.unique_integer([:positive])}"

  # Every process an interface is running, and a monitor on its stack.
  defp processes(root) do
    children = children(root)
    {:ok, stack} = Wagyu.stack(root)
    peers = for {_id, pid, _type, _modules} <- DynamicSupervisor.which_children(children.peer_supervisor), do: pid
    {[root | Map.values(children)] ++ peers, SmolNet.monitor(stack)}
  end

  test "the application runs only the interface registry" do
    assert [{Wagyu.Registry, pid, :supervisor, _modules}] = Supervisor.which_children(Wagyu.Supervisor)
    assert Process.whereis(Wagyu.Registry) == pid
  end

  describe "start_link/1" do
    test "starts an interface with a bound UDP socket and a usable stack" do
      assert {:ok, interface} = Wagyu.start_link(options())
      assert {:ok, stack} = Wagyu.stack(interface)
      assert {:ok, info} = Wagyu.info(interface)

      assert info.listen.address == {127, 0, 0, 1}
      assert info.listen.port > 0
      assert {:error, :eaddrinuse} = :gen_udp.open(info.listen.port, ip: {127, 0, 0, 1})

      assert {:ok, socket} = SmolNet.open(:inet, :stream, :tcp, stack: stack)
      assert :ok = SmolNet.close(socket)
      assert :ok = Wagyu.stop(interface)
    end

    test "accepts a validated configuration" do
      {:ok, config} = Config.new(options())
      assert {:ok, interface} = Wagyu.start_link(config)
      assert :ok = Wagyu.stop(interface)
    end

    test "returns the configuration error for invalid options" do
      assert Wagyu.start_link([]) == {:error, {:invalid_option, [:private_key], :missing}}

      [peer] = options()[:peers]
      psk = :binary.copy(<<7>>, 31)

      assert Wagyu.start_link(options(peers: [Map.put(peer, :preshared_key, psk)])) ==
               {:error, {:invalid_option, [:peers, 0, :preshared_key], :invalid_length}}
    end

    test "fails to start when its UDP port is taken" do
      Process.flag(:trap_exit, true)
      {:ok, holder} = :gen_udp.open(0, ip: {127, 0, 0, 1})
      {:ok, port} = :inet.port(holder)

      assert {:error, {:shutdown, {:failed_to_start_child, Wagyu.Interface, :eaddrinuse}}} =
               Wagyu.start_link(options(listen: %{address: {127, 0, 0, 1}, port: port}))
    end

    test "starts its stack with the configured socket limit" do
      stack_options = Keyword.put(options()[:stack], :sockets, 65)
      {:ok, interface} = Wagyu.start_link(options(stack: stack_options))
      {:ok, stack} = Wagyu.stack(interface)

      assert {:ok, %{native: %{result: %{native_socket_capacity: 65}}}} = SmolNet.stack_info(stack)

      for _n <- 1..65, do: assert({:ok, _socket} = SmolNet.open(:inet, :dgram, :udp, stack: stack))
      assert {:error, :system_limit} = SmolNet.open(:inet, :dgram, :udp, stack: stack)
      assert :ok = Wagyu.stop(interface)
    end

    test "listens on IPv6" do
      [peer] = options()[:peers]
      peer = %{peer | endpoint: %{address: {0, 0, 0, 0, 0, 0, 0, 1}, port: 51_820}}
      listen = %{address: {0, 0, 0, 0, 0, 0, 0, 1}, port: 0}
      {:ok, interface} = Wagyu.start_link(options(listen: listen, peers: [peer]))

      {:ok, %{listen: %{port: port}}} = Wagyu.info(interface)
      {:ok, client} = :gen_udp.open(0, [:inet6, ip: {0, 0, 0, 0, 0, 0, 0, 1}])
      :ok = :gen_udp.send(client, {0, 0, 0, 0, 0, 0, 0, 1}, port, "not wireguard")

      assert %{datagrams: 1, invalid_datagrams: 1} = counters(interface, &(&1.datagrams == 1))
      assert :ok = Wagyu.stop(interface)
    end
  end

  describe "names" do
    test "a PID and its registered name identify the same interface" do
      name = unique_name()
      {:ok, interface} = Wagyu.start_link(options(name: name))

      assert Process.whereis(name) == interface
      assert {:ok, stack} = Wagyu.stack(name)
      assert Wagyu.stack(interface) == {:ok, stack}
      assert Wagyu.info(name) == Wagyu.info(interface)

      assert :ok = Wagyu.stop(name)
      refute Process.alive?(interface)
      assert Process.whereis(name) == nil
      assert Wagyu.stack(name) == {:error, :not_running}
      assert Wagyu.info(name) == {:error, :not_running}
      assert Wagyu.stop(name) == {:error, :not_running}
    end

    test "a registered name cannot be started twice" do
      name = unique_name()
      {:ok, interface} = Wagyu.start_link(options(name: name))

      assert Wagyu.start_link(options(name: name)) == {:error, {:already_started, interface}}
      assert Wagyu.stack(name) == Wagyu.stack(interface)
      assert :ok = Wagyu.stop(interface)
    end

    test "global and via names" do
      start_supervised!({Registry, keys: :unique, name: __MODULE__.Names})

      for name <- [{:global, {__MODULE__, make_ref()}}, {:via, Registry, {__MODULE__.Names, :wg0}}] do
        {:ok, interface} = Wagyu.start_link(options(name: name))
        assert GenServer.whereis(name) == interface
        assert {:ok, _stack} = Wagyu.stack(name)
        assert :ok = Wagyu.stop(name)
        assert GenServer.whereis(name) == nil
      end
    end

    # Killing the interface logs its children's exits.
    @tag :capture_log
    test "a crashed interface releases its name" do
      name = unique_name()
      spec = Supervisor.child_spec({Wagyu, options(name: name)}, restart: :temporary)
      interface = start_supervised!(spec)
      monitor = Process.monitor(interface)

      Process.exit(interface, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^interface, :killed}
      assert Process.whereis(name) == nil
      assert Wagyu.stack(name) == {:error, :not_running}

      assert {:ok, restarted} = Wagyu.start_link(options(name: name))
      assert :ok = Wagyu.stop(restarted)
    end

    test "a PID or name that is not an interface is not running" do
      assert Wagyu.stack(unique_name()) == {:error, :not_running}
      assert Wagyu.info(self()) == {:error, :not_running}
      assert Wagyu.stop(self()) == {:error, :not_running}
      assert Wagyu.stop(Wagyu.Supervisor) == {:error, :not_running}
      assert Process.alive?(self())
    end
  end

  describe "child_spec/1" do
    test "starts the interface under the caller's supervisor with the validated configuration" do
      name = unique_name()
      options = options(name: name)

      assert %{id: {Wagyu, ^name}, start: {Wagyu, :start_link, [%Config{} = config]}, type: :supervisor} =
               spec = Wagyu.child_spec(options)

      assert {:ok, config} == Config.new(options)
      refute inspect(spec, limit: :infinity) =~ inspect(options[:private_key], limit: :infinity)

      supervisor = start_supervised!(%{id: :user, start: {Supervisor, :start_link, [[spec], [strategy: :one_for_one]]}})
      assert [{{Wagyu, ^name}, interface, :supervisor, _modules}] = Supervisor.which_children(supervisor)
      assert Process.whereis(name) == interface
      assert {:ok, _stack} = Wagyu.stack(name)
    end

    test "is Wagyu for an unnamed interface" do
      assert %{id: Wagyu} = Wagyu.child_spec(options())
    end

    test "raises for invalid options without showing their values" do
      error = assert_raise ArgumentError, fn -> Wagyu.child_spec(private_key: "not a key") end
      assert error.message == "invalid Wagyu options: {:invalid_option, [:private_key], :invalid_length}"

      [peer] = options()[:peers]
      psk = :binary.copy(<<7>>, 31)

      error =
        assert_raise ArgumentError, fn -> Wagyu.child_spec(options(peers: [Map.put(peer, :preshared_key, psk)])) end

      assert error.message == "invalid Wagyu options: {:invalid_option, [:peers, 0, :preshared_key], :invalid_length}"
    end
  end

  describe "independent interfaces" do
    test "run side by side, and stopping one leaves the other running" do
      {:ok, first} = Wagyu.start_link(options())
      {:ok, second} = Wagyu.start_link(options())

      {:ok, first_stack} = Wagyu.stack(first)
      {:ok, second_stack} = Wagyu.stack(second)
      refute first_stack == second_stack

      {:ok, %{listen: %{port: first_port}}} = Wagyu.info(first)
      {:ok, %{listen: %{port: second_port}}} = Wagyu.info(second)
      refute first_port == second_port

      {:ok, client} = :gen_udp.open(0, ip: {127, 0, 0, 1})
      :ok = :gen_udp.send(client, {127, 0, 0, 1}, first_port, "one")
      :ok = :gen_udp.send(client, {127, 0, 0, 1}, second_port, "two")
      :ok = :gen_udp.send(client, {127, 0, 0, 1}, second_port, "three")
      assert %{datagrams: 1} = counters(first, &(&1.datagrams == 1))
      assert %{datagrams: 2} = counters(second, &(&1.datagrams == 2))

      assert :ok = Wagyu.stop(first)
      :ok = :gen_udp.send(client, {127, 0, 0, 1}, second_port, "four")
      assert %{datagrams: 3} = counters(second, &(&1.datagrams == 3))
      assert {:ok, socket} = SmolNet.open(:inet, :dgram, :udp, stack: second_stack)
      assert :ok = SmolNet.close(socket)
      assert :ok = Wagyu.stop(second)
    end

    test "stopping closes the socket, stops the stack and leaves no process behind" do
      port = free_port()
      options = options(listen: %{address: {127, 0, 0, 1}, port: port})

      for _round <- 1..2 do
        {:ok, interface} = Wagyu.start_link(options)
        {:ok, stack} = Wagyu.stack(interface)
        send_egress(open_udp(stack), 1)
        assert %{egress_routed: 1} = counters(interface, &(&1.egress_routed == 1))

        {pids, stack_monitor} = processes(interface)
        assert length(pids) == 6

        assert :ok = Wagyu.stop(interface)
        assert_receive {:DOWN, ^stack_monitor, :process, _object, _reason}
        assert Enum.filter(pids, &Process.alive?/1) == []

        for role <- [:link, :interface, :handshake_supervisor, :peer_supervisor],
            do: assert(Wagyu.Registry.lookup(interface, role) == :error)
      end

      {:ok, socket} = :gen_udp.open(port, ip: {127, 0, 0, 1})
      :ok = :gen_udp.close(socket)
    end
  end
end
