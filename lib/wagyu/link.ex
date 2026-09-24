defmodule Wagyu.Link do
  @moduledoc false

  # The interface's SmolNet link. It starts, owns and monitors one stack, and
  # it is the stack's only ingress feeder.
  #
  # Egress. The stack sends `{:smol_stack, ref, :egress, packets}` without
  # backpressure, so the link never blocks on it: it hands each ordered batch
  # to the current interface, which it finds through the registry rather
  # than a PID captured at start. Packets are admitted in order against the
  # interface's bound, and whatever does not fit, or the whole batch while no
  # interface is registered, is dropped and counted.
  #
  # This is the one queue that admission cannot bound, since the stack sends
  # before anything can refuse. What bounds it in practice is that each batch
  # comes from one step of the stack's own work, at most 32 packets, driven
  # by application socket calls or the stack's timer, and that handling a
  # batch here costs far less than producing it. The link is held up only
  # during its own ingress calls, one at a time. A hard bound would need
  # egress credit from SmolNet.
  #
  # Ingress. Peers admit decrypted packets against the link's own bound with
  # `deliver/2`, which sends `{:wg_plaintext, packets}`. The link coalesces
  # consecutive queued lists into batches within the stack's `:input_packets`
  # and `:bytes_copied` limits and makes one `SmolNet.ingress/2` call at a
  # time. The stack admits a batch atomically, so a batch it refuses for an
  # invalid or oversized packet is retried one packet at a time, and one bad
  # packet cannot drop its neighbours. `:busy`, partial acceptance,
  # `:batch_too_large` and `:invalid_ingress` are counted drops. `:closed` and
  # `:link_down` mean the stack is gone, and the link exits.
  #
  # The link exits when its stack stops for any reason, including an
  # application calling `SmolNet.stop_stack/1`, and stops its stack when it
  # exits, so the root supervisor always rebuilds the two together.

  use GenServer

  alias Wagyu.Admission

  @ingress_packets 32
  # SmolNet's default, set explicitly because batches are sized against it.
  @ingress_bytes 65_536
  # The plaintext that peers may have queued for ingress at once.
  @queue_packets 256
  @queue_bytes 512 * 1024

  @counters [egress: 1, egress_dropped: 2, ingress: 3, ingress_dropped: 4]

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options), do: GenServer.start_link(__MODULE__, options)

  @doc """
  Admits decrypted packets for ingress into `root`'s stack and sends them to
  its link, in order. Returns how many were refused because the link's queue
  was full or no link is running; the link counts them as ingress drops.
  """
  @spec deliver(term(), [binary()]) :: non_neg_integer()
  def deliver(root, packets) do
    case Wagyu.Registry.lookup(root, :link) do
      {:ok, link, %{queue: queue, counters: counters}} ->
        {admitted, refused} = Admission.admit_prefix(queue, packets)
        if admitted != [], do: send(link, {:wg_plaintext, admitted})
        count(counters, :ingress_dropped, refused)
        refused

      :error ->
        length(packets)
    end
  end

  @doc "Returns the link's counters, or `:error` while no link is running."
  @spec counters(term()) :: {:ok, %{atom() => non_neg_integer()}} | :error
  def counters(root) do
    case Wagyu.Registry.lookup(root, :link) do
      {:ok, _link, %{counters: counters}} ->
        {:ok, Map.new(@counters, fn {name, index} -> {name, :counters.get(counters, index)} end)}

      :error ->
        :error
    end
  end

  @impl true
  def init(options) do
    # Trap exits so that terminate/2 stops the stack on shutdown.
    Process.flag(:trap_exit, true)

    root = Keyword.fetch!(options, :root)
    smolnet = Keyword.get(options, :smolnet, SmolNet)
    ref = make_ref()

    stack_options =
      Keyword.fetch!(options, :stack) ++
        [
          egress: {self(), ref},
          limits: %{input_packets: @ingress_packets, bytes_copied: @ingress_bytes},
          link_down: :stop
        ]

    case smolnet.start_stack(stack_options) do
      {:ok, stack} ->
        monitor = smolnet.monitor(stack)
        queue = Admission.new(@queue_packets, @queue_bytes)
        counters = :counters.new(length(@counters), [:write_concurrency])
        :ok = Wagyu.Registry.register(root, :link, %{stack: stack, queue: queue, counters: counters})

        {:ok,
         %{
           root: root,
           smolnet: smolnet,
           ref: ref,
           stack: stack,
           monitor: monitor,
           queue: queue,
           counters: counters,
           pending: [],
           pending_count: 0,
           pending_bytes: 0
         }}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def handle_info({:wg_plaintext, packets}, state) do
    Admission.release_all(state.queue, packets)
    state |> enqueue(packets) |> noreply()
  end

  # Any other message ends a run of queued plaintext, so the batch goes in
  # first.
  def handle_info(message, state) do
    with {:ok, state} <- flush(state) do
      handle(message, state)
    end
  end

  @impl true
  def terminate(_reason, state) do
    state.smolnet.stop_stack(state.stack)
  catch
    :exit, _reason -> :ok
  end

  defp handle(:timeout, state), do: {:noreply, state}

  defp handle({:smol_stack, ref, :egress, packets}, %{ref: ref} = state) do
    count(state.counters, :egress, length(packets))
    count(state.counters, :egress_dropped, Wagyu.Interface.deliver(state.root, packets))
    {:noreply, state}
  end

  defp handle({:DOWN, monitor, :process, _object, _reason}, %{monitor: monitor} = state),
    do: {:stop, {:shutdown, :stack_down}, state}

  defp handle(_message, state), do: {:noreply, state}

  # Adds packets to the pending batch, sending the batch whenever the next
  # packet would take it past the stack's limits.
  defp enqueue(state, packets) do
    Enum.reduce_while(packets, {:ok, state}, fn packet, {:ok, state} ->
      case make_room(state, byte_size(packet)) do
        {:ok, state} ->
          {:cont,
           {:ok,
            %{
              state
              | pending: [packet | state.pending],
                pending_count: state.pending_count + 1,
                pending_bytes: state.pending_bytes + byte_size(packet)
            }}}

        stop ->
          {:halt, stop}
      end
    end)
  end

  defp make_room(state, size)
       when state.pending_count < @ingress_packets and state.pending_bytes + size <= @ingress_bytes,
       do: {:ok, state}

  defp make_room(state, _size), do: flush(state)

  defp flush(%{pending_count: 0} = state), do: {:ok, state}

  defp flush(state) do
    batch = Enum.reverse(state.pending)
    ingress(%{state | pending: [], pending_count: 0, pending_bytes: 0}, batch)
  end

  defp ingress(state, batch) do
    count = length(batch)

    case state.smolnet.ingress(state.stack, batch) do
      {:ok, ^count} ->
        count(state.counters, :ingress, count)
        {:ok, state}

      {:ok, accepted} when is_integer(accepted) and accepted >= 0 and accepted < count ->
        count(state.counters, :ingress, accepted)
        count(state.counters, :ingress_dropped, count - accepted)
        {:ok, state}

      {:error, reason} when reason in [:closed, :link_down] ->
        count(state.counters, :ingress_dropped, count)
        {:stop, {:shutdown, {:ingress, reason}}, state}

      {:error, reason} when reason in [:invalid_packet, :packet_too_large] and count > 1 ->
        ingress_each(state, batch)

      _refused ->
        count(state.counters, :ingress_dropped, count)
        {:ok, state}
    end
  end

  defp ingress_each(state, batch) do
    Enum.reduce_while(batch, {:ok, state}, fn packet, {:ok, state} ->
      case ingress(state, [packet]) do
        {:ok, state} -> {:cont, {:ok, state}}
        stop -> {:halt, stop}
      end
    end)
  end

  # Waits for the mailbox to empty (a zero timeout) before sending a partial
  # batch, so that lists queued back to back share one ingress call.
  defp noreply({:ok, %{pending_count: 0} = state}), do: {:noreply, state}
  defp noreply({:ok, state}), do: {:noreply, state, 0}
  defp noreply({:stop, _reason, _state} = stop), do: stop

  defp count(_counters, _name, 0), do: :ok
  defp count(counters, name, increment), do: :counters.add(counters, Keyword.fetch!(@counters, name), increment)
end
