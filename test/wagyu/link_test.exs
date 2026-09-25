defmodule Wagyu.LinkTest do
  # Tests within a module run one at a time, so each can be the fake stack's
  # controller in turn.
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.Admission
  alias Wagyu.EgressCredit
  alias Wagyu.FakeSmolNet
  alias Wagyu.Link

  @stack_options [
    addresses: [{{10, 13, 0, 2}, 32}],
    routes: [{{0, 0, 0, 0}, 0, {10, 13, 0, 1}}],
    mtu: 1280,
    sockets: 256
  ]

  setup do
    Process.register(self(), FakeSmolNet)
    root = make_ref()

    link =
      start_supervised!(
        Supervisor.child_spec({Link, root: root, stack: @stack_options, smolnet: FakeSmolNet}, restart: :temporary)
      )

    assert_receive {:start_stack, ^link, options}
    {:ok, ^link, %{stack: %{stack: stack}}} = Wagyu.Registry.lookup(root, :link)
    %{root: root, link: link, options: options, stack: stack}
  end

  # Registers the test process as `root`'s interface, receiving egress.
  defp register_interface(root, max_packets \\ 256, max_bytes \\ 512 * 1024) do
    registration = %{egress: Admission.new(max_packets, max_bytes), credit: EgressCredit.new()}
    :ok = Wagyu.Registry.register(root, :interface, registration)
    registration
  end

  defp egress(link, options, packets) do
    {^link, ref} = options[:egress]
    send(link, {:smol_stack, ref, :egress, packets})
  end

  # Receives the link's next ingress call and answers it.
  defp answer_ingress(link, result_fun) do
    assert_receive {:ingress, ^link, ref, packets}
    send(link, {ref, result_fun.(packets)})
    packets
  end

  defp accept_all(packets), do: {:ok, length(packets)}

  defp packets(range, size \\ 20), do: Enum.map(range, &<<&1::32, 0::size((size - 4) * 8)>>)

  describe "starting" do
    test "starts its stack with Wagyu's egress, limits and link-down policy", %{link: link, options: options} do
      assert {^link, ref} = options[:egress]
      assert is_reference(ref)
      assert options[:limits] == %{input_packets: 32, bytes_copied: 65_536, sockets: 256}
      assert options[:link_down] == :stop
      assert options[:egress_credit] == {128, 256 * 1024}
      assert Keyword.take(options, [:addresses, :routes, :mtu]) == Keyword.delete(@stack_options, :sockets)
      refute Keyword.has_key?(options, :sockets)
    end

    test "leaves the socket limit to SmolNet when none is given" do
      options = [root: make_ref(), stack: [mtu: 1280], smolnet: FakeSmolNet]
      link = start_supervised!(Supervisor.child_spec({Link, options}, id: :default_sockets, restart: :temporary))

      assert_receive {:start_stack, ^link, options}
      assert options[:limits] == %{input_packets: 32, bytes_copied: 65_536}
    end

    test "exits with a start error when the stack will not start" do
      Process.flag(:trap_exit, true)
      assert {:error, :invalid_mtu} = Link.start_link(root: make_ref(), stack: [mtu: 100])
    end
  end

  describe "egress" do
    test "forwards ordered batches to the registered interface", %{root: root, link: link, options: options} do
      register_interface(root)
      egress(link, options, packets(1..3))
      egress(link, options, packets(4..5))

      assert_receive {:wg_egress, first}
      assert_receive {:wg_egress, second}
      assert first ++ second == packets(1..5)
      assert {:ok, %{egress: 5, egress_dropped: 0}} = Link.counters(root)
    end

    test "drops a batch while no interface is registered", %{root: root, link: link, options: options} do
      egress(link, options, packets(1..4))
      assert eventually(fn -> match?({:ok, %{egress: 4, egress_dropped: 4}}, Link.counters(root)) end)
      refute_received {:wg_egress, _packets}

      # Nothing holds what was dropped, so the stack gets its credit back.
      assert_receive {:grant_egress, ^link, 4, 80}
    end

    test "admits packets in order up to the interface's bound and drops the rest",
         %{root: root, link: link, options: options} do
      %{egress: queue} = register_interface(root, 3)
      egress(link, options, packets(1..5))

      assert_receive {:wg_egress, admitted}
      assert admitted == packets(1..3)
      assert eventually(fn -> match?({:ok, %{egress: 5, egress_dropped: 2}}, Link.counters(root)) end)
      assert Admission.usage(queue) == {3, 60}
      assert_receive {:grant_egress, ^link, 2, 40}

      # The interface releases the batch when it takes it; room reopens.
      Admission.release_all(queue, admitted)
      egress(link, options, packets(6..6))
      assert_receive {:wg_egress, [_packet]}
    end

    test "counts egress lost with an interface that exits before taking it",
         %{root: root, link: link, options: options} do
      test = self()

      # An interface that takes nothing from its mailbox.
      interface =
        spawn(fn ->
          :ok =
            Wagyu.Registry.register(root, :interface, %{
              egress: Admission.new(256, 512 * 1024),
              credit: EgressCredit.new()
            })

          send(test, :registered)
          receive(do: (:never -> :ok))
        end)

      assert_receive :registered
      egress(link, options, packets(1..3))
      _state = :sys.get_state(link)
      assert {:ok, %{egress: 3, egress_dropped: 0}} = Link.counters(root)
      refute_received {:grant_egress, ^link, _packets, _bytes}

      # The three it never took are counted as soon as it exits, and once
      # only: a batch for its replacement adds nothing. Their credit is
      # the stack's again.
      Process.exit(interface, :kill)
      assert eventually(fn -> match?({:ok, %{egress: 3, egress_dropped: 3}}, Link.counters(root)) end)
      assert_receive {:grant_egress, ^link, 3, 60}

      register_interface(root)
      egress(link, options, packets(4..4))
      assert_receive {:wg_egress, [_packet]}
      _state = :sys.get_state(link)
      assert {:ok, %{egress: 4, egress_dropped: 3}} = Link.counters(root)
    end

    test "grants credit back only as the interface retires what it holds",
         %{root: root, link: link, options: options} do
      %{credit: credit} = register_interface(root)
      egress(link, options, packets(1..3))
      assert_receive {:wg_egress, batch}
      assert EgressCredit.outstanding(credit) == {3, 60}

      # The interface still holds all three.
      send(link, :wg_egress_retired)
      _state = :sys.get_state(link)
      refute_received {:grant_egress, ^link, _packets, _bytes}

      EgressCredit.retire_all(credit, Enum.take(batch, 2))
      {:ok, target} = Link.lookup(root)
      Link.retired(target)
      assert_receive {:grant_egress, ^link, 2, 40}

      # Credit is granted once: a second notice finds nothing new.
      Link.retired(target)
      _state = :sys.get_state(link)
      refute_received {:grant_egress, ^link, _packets, _bytes}
    end

    test "a credit notice does not end a run of queued plaintext", %{root: root, link: link} do
      register_interface(root)
      {:ok, target} = Link.lookup(root)

      # Hold the link in an ingress call while plaintext and a notice queue
      # behind it.
      assert Link.deliver(root, packets(0..0)) == 0
      assert_receive {:ingress, ^link, ref, [_first]}
      assert Link.deliver(root, packets(1..2)) == 0
      Link.retired(target)
      assert Link.deliver(root, packets(3..4)) == 0
      send(link, {ref, {:ok, 1}})

      assert answer_ingress(link, &accept_all/1) == packets(1..4)
    end

    test "ignores egress for another link reference", %{root: root, link: link} do
      register_interface(root)
      send(link, {:smol_stack, make_ref(), :egress, packets(1..1)})
      _state = :sys.get_state(link)
      assert {:ok, %{egress: 0}} = Link.counters(root)
      refute_received {:wg_egress, _packets}
    end
  end

  describe "ingress" do
    test "coalesces queued lists into ordered batches of at most 32 packets", %{root: root, link: link} do
      # The first packet goes in alone and holds the link in its ingress
      # call while the rest queue up behind it.
      assert Link.deliver(root, packets(0..0)) == 0
      assert_receive {:ingress, ^link, ref, [_first]}

      for n <- 0..9, do: assert(Link.deliver(root, packets((n * 10 + 1)..(n * 10 + 10))) == 0)
      send(link, {ref, {:ok, 1}})

      batches = for _batch <- 1..4, do: answer_ingress(link, &accept_all/1)
      assert Enum.map(batches, &length/1) == [32, 32, 32, 4]
      assert Enum.concat(batches) == packets(1..100)
      refute_receive {:ingress, ^link, _ref, _packets}
      assert eventually(fn -> match?({:ok, %{ingress: 101, ingress_dropped: 0}}, Link.counters(root)) end)
    end

    test "keeps each batch within the stack's byte limit", %{root: root, link: link} do
      assert Link.deliver(root, packets(1..30, 3000)) == 0

      assert length(answer_ingress(link, &accept_all/1)) == 21
      assert length(answer_ingress(link, &accept_all/1)) == 9
    end

    test "counts refused and partially accepted batches as drops", %{root: root, link: link} do
      for result <- [{:error, :busy}, {:error, :batch_too_large}, {:error, :invalid_ingress}, {:ok, 1}] do
        assert Link.deliver(root, packets(1..3)) == 0
        answer_ingress(link, fn _packets -> result end)
      end

      assert eventually(fn -> match?({:ok, %{ingress: 1, ingress_dropped: 11}}, Link.counters(root)) end)
      assert Process.alive?(link)
    end

    test "retries a batch holding an invalid packet one packet at a time", %{root: root, link: link} do
      [_first, bad, _third] = batch = packets(1..3)
      assert Link.deliver(root, batch) == 0
      answer_ingress(link, fn _packets -> {:error, :invalid_packet} end)

      for packet <- batch do
        result = if packet == bad, do: {:error, :invalid_packet}, else: {:ok, 1}
        assert [^packet] = answer_ingress(link, fn _packets -> result end)
      end

      assert eventually(fn -> match?({:ok, %{ingress: 2, ingress_dropped: 1}}, Link.counters(root)) end)
    end

    test "refuses plaintext beyond its queue and counts it", %{root: root, link: link} do
      # Hold the link in an ingress call so that nothing is dequeued.
      assert Link.deliver(root, packets(0..0)) == 0
      assert_receive {:ingress, ^link, ref, _packets}

      assert Link.deliver(root, packets(1..300)) == 44
      assert {:ok, %{ingress_dropped: 44}} = Link.counters(root)

      send(link, {ref, {:ok, 1}})
      for _batch <- 1..8, do: answer_ingress(link, &accept_all/1)
      assert eventually(fn -> match?({:ok, %{ingress: 257}}, Link.counters(root)) end)
    end

    for reason <- [:closed, :link_down] do
      test "exits when ingress reports #{reason}", %{root: root, link: link} do
        monitor = Process.monitor(link)
        assert Link.deliver(root, packets(1..1)) == 0
        answer_ingress(link, fn _packets -> {:error, unquote(reason)} end)

        assert_receive {:DOWN, ^monitor, :process, ^link, {:shutdown, {:ingress, unquote(reason)}}}
        assert_receive {:stop_stack, ^link}
      end
    end
  end

  test "exits when its stack stops", %{link: link, stack: stack} do
    monitor = Process.monitor(link)
    # A monitor takes effect when the link handles it, and signals from
    # different senders are unordered, so make sure it is in place before
    # the stack's exit can reach the link.
    _state = :sys.get_state(link)
    Process.exit(stack, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^link, {:shutdown, :stack_down}}
  end

  test "stops its stack when it stops", %{link: link, stack: stack} do
    stack_monitor = Process.monitor(stack)
    :ok = GenServer.stop(link, :shutdown)
    assert_receive {:stop_stack, ^link}
    assert_receive {:DOWN, ^stack_monitor, :process, ^stack, _reason}
  end
end
