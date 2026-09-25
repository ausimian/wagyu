defmodule Wagyu.Link do
  @moduledoc false

  # The interface's SmolNet link. It starts, owns and monitors one stack, and
  # it is the stack's only ingress feeder.
  #
  # Egress. The stack sends `{:smol_stack, ref, :egress, packets}`, and the
  # link never blocks on it: it hands each ordered batch to the current
  # interface, which it finds through the registry rather than a PID
  # captured at start. Packets are admitted in order against the
  # interface's bound, and whatever does not fit, or the whole batch while no
  # interface is registered, is dropped and counted.
  #
  # The stack sends only what egress credit covers: it starts with
  # `@egress_credit_packets` packets and `@egress_credit_bytes` bytes, and
  # the link grants credit back only once packets have left the interface.
  # The interface counts the packets it holds, in its own mailbox or a
  # peer's, in a `Wagyu.EgressCredit` it registers, and it and the peers
  # send `:wg_egress_retired` once they have sent, staged or dropped some.
  # The link then grants whatever neither the stack, its batches on their
  # way here, nor the interface holds. So the link's mailbox holds at most
  # that credit of egress, no interface queue it feeds can overflow, and
  # what the stack cannot send stays in its sockets, where TCP slows down
  # as it would for a slow network instead of losing segments.
  #
  # A new interface registers a new count. When the one the link delivers
  # to exits, it took its peers and whatever they held with it, so the link
  # stops reading its count and grants that credit again.
  #
  # Ingress. Peers admit decrypted packets against the link's own bound with
  # `deliver/2`, or `deliver_to/2` with the target a peer looked up once
  # (`lookup/1`), which sends `{:wg_plaintext, packets}`. The link coalesces
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
  # exits, so the root supervisor always rebuilds the two together. It also
  # exits when the registry does, so that a restarted registry is repopulated
  # rather than leaving the interface unreachable.

  use GenServer

  alias Wagyu.Admission
  alias Wagyu.EgressCredit

  @ingress_packets 32
  # SmolNet's default, set explicitly because batches are sized against it.
  @ingress_bytes 65_536
  # The plaintext that peers may have queued for ingress at once.
  @queue_packets 256
  @queue_bytes 512 * 1024
  # The egress the stack may have sent that has yet to leave the interface.
  # It is within the interface's and each peer's outbound bounds, so neither
  # refuses egress for want of room.
  @egress_credit_packets 128
  @egress_credit_bytes 256 * 1024

  @counters [egress: 1, egress_dropped: 2, ingress: 3, ingress_dropped: 4]

  @typedoc "What a sender needs to deliver to a link: its process, queue and counters."
  @type target :: %{pid: pid(), queue: Admission.t(), counters: :counters.counters_ref()}

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options), do: GenServer.start_link(__MODULE__, options)

  @doc """
  Admits decrypted packets for ingress into `root`'s stack and sends them to
  its link, in order. Returns how many were refused because the link's queue
  was full or no link is running; the link counts them as ingress drops,
  except while none is running.
  """
  @spec deliver(term(), [binary()]) :: non_neg_integer()
  def deliver(root, packets) do
    case lookup(root) do
      {:ok, target} -> deliver_to(target, packets)
      :error -> length(packets)
    end
  end

  @doc "Returns the target for `deliver_to/2` of `root`'s running link, or `:error`."
  @spec lookup(term()) :: {:ok, target()} | :error
  def lookup(root) do
    case Wagyu.Registry.lookup(root, :link) do
      {:ok, link, %{queue: queue, counters: counters}} -> {:ok, %{pid: link, queue: queue, counters: counters}}
      :error -> :error
    end
  end

  @doc """
  Delivers as `deliver/2` does, to a link found with `lookup/1`. The caller
  should monitor it: packets sent to a link that has exited are lost.
  """
  @spec deliver_to(target(), [binary()]) :: non_neg_integer()
  def deliver_to(%{pid: link, queue: queue, counters: counters}, packets) do
    {admitted, refused} = Admission.admit_prefix(queue, packets)
    if admitted != [], do: send(link, {:wg_plaintext, admitted})
    count(counters, :ingress_dropped, refused)
    refused
  end

  @doc """
  Tells a link found with `lookup/1` that egress it handed on has been sent,
  staged or dropped, so that it can grant the stack that credit again.
  """
  @spec retired(target()) :: :ok
  def retired(%{pid: link}) do
    send(link, :wg_egress_retired)
    :ok
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
          egress_credit: {@egress_credit_packets, @egress_credit_bytes},
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
           pending_bytes: 0,
           # The credit the stack holds, together with its batches on their
           # way here.
           held: {@egress_credit_packets, @egress_credit_bytes},
           interface: nil
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

  # Credit does not end a run of queued plaintext.
  def handle_info(:wg_egress_retired, state), do: state |> top_up() |> noreply()

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
    {held_packets, held_bytes} = state.held
    state = %{state | held: {held_packets - length(packets), held_bytes - Admission.bytes(packets)}}
    {refused, interface} = Wagyu.Interface.deliver(state.root, packets)
    count(state.counters, :egress_dropped, refused)
    state |> track_interface(interface) |> top_up() |> noreply()
  end

  defp handle({:DOWN, monitor, :process, _object, _reason}, %{monitor: monitor} = state),
    do: {:stop, {:shutdown, :stack_down}, state}

  defp handle({:DOWN, monitor, :process, _object, _reason}, %{interface: {_pid, _egress, _credit, monitor}} = state),
    do: state |> reconcile() |> top_up() |> noreply()

  # Besides its parent, which GenServer handles, only the registry is linked
  # to the link: registering links to it. If the registry exits, it takes
  # every registration of this interface with it, so the link exits and the
  # root rebuilds the interface, whose processes register again.
  defp handle({:EXIT, _registry, reason}, state), do: {:stop, {:shutdown, {:registry_down, reason}}, state}

  defp handle(_message, state), do: {:noreply, state}

  # Packets admitted to an interface that exits before taking them are lost
  # with its mailbox. Its queue's count outlives it, so the link monitors
  # the interface it delivers to and, when that exits, counts whatever it
  # never took as dropped.
  defp track_interface(state, nil), do: state

  defp track_interface(%{interface: {pid, _egress, _credit, _monitor}} = state, {pid, _same_egress, _same_credit}),
    do: state

  defp track_interface(state, {pid, egress, credit}) do
    # A different interface registered only once the one before it had
    # exited, even if its :DOWN has yet to arrive.
    %{reconcile(state) | interface: {pid, egress, credit, Process.monitor(pid)}}
  end

  defp reconcile(%{interface: {_pid, egress, _credit, monitor}} = state) do
    Process.demonitor(monitor, [:flush])
    {lost, _bytes} = Admission.usage(egress)
    count(state.counters, :egress_dropped, lost)
    %{state | interface: nil}
  end

  defp reconcile(state), do: state

  # Grants the stack the credit that neither it nor the interface holds.
  # The interface's count is read after the retirements that prompted this,
  # and can only have fallen since, so the grant never exceeds what is free.
  defp top_up(state) do
    {held_packets, held_bytes} = state.held
    {taken_packets, taken_bytes} = taken(state)
    packets = max(@egress_credit_packets - held_packets - taken_packets, 0)
    bytes = max(@egress_credit_bytes - held_bytes - taken_bytes, 0)

    if packets == 0 and bytes == 0 do
      {:ok, state}
    else
      case state.smolnet.grant_egress(state.stack, packets, bytes) do
        :ok -> {:ok, %{state | held: {held_packets + packets, held_bytes + bytes}}}
        {:error, :closed} -> {:stop, {:shutdown, {:grant_egress, :closed}}, state}
      end
    end
  end

  defp taken(%{interface: {_pid, _egress, credit, _monitor}}), do: EgressCredit.settle(credit)
  defp taken(_state), do: {0, 0}

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
