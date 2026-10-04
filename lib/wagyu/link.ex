defmodule Wagyu.Link do
  @moduledoc false

  # The SmolNet link of the interface. It starts, owns and monitors one
  # stack. It is the only process that gives ingress to the stack.
  #
  # Egress. The stack sends `{:smol_stack, ref, :egress, packets}`. The link
  # never blocks on these messages. It gives each ordered batch to the
  # current interface, which it finds through the registry, not through a
  # PID captured at start. Packets are admitted in sequence against the
  # bound of the interface. The link drops and counts the packets that do
  # not fit. While no interface is registered, it drops and counts the
  # complete batch.
  #
  # The stack sends only the egress that its credit covers. It starts with
  # `@egress_credit_packets` packets and `@egress_credit_bytes` bytes. The
  # link grants credit back only after packets leave the interface. The
  # interface counts the packets that it holds, in its mailbox or in the
  # queue of a peer. It keeps this count in a `Wagyu.EgressCredit` that it
  # registers. When some packets are sent, staged or dropped, the interface
  # sends `:wg_egress_retired`.
  #
  # The link then grants all credit that the stack, its batches in transit
  # to the link, and the interface do not hold. As a result:
  #
  #   * The mailbox of the link holds a maximum of that credit of egress.
  #   * No interface queue that the link supplies can overflow.
  #   * Data that the stack cannot send stays in its sockets. There, TCP
  #     slows down, as it does for a slow network, and it does not lose
  #     segments.
  #
  # A new interface registers a new count. When the interface that the link
  # supplies exits, its peers and all packets that they held also go. Thus
  # the link no longer reads the count of that interface, and it grants that
  # credit again.
  #
  # Ingress. Peers admit decrypted packets against the bound of the link
  # with `deliver/2`. Alternatively, a peer uses `deliver_to/2` with a
  # target that it found one time with `lookup/1`. Both functions send
  # `{:wg_plaintext, packets}`. The link joins consecutive queued lists into
  # batches within the `:input_packets` and `:bytes_copied` limits of the
  # stack. It makes one `SmolNet.ingress/2` call at a time.
  #
  # The stack admits a batch atomically. If the stack refuses a batch
  # because of an invalid or oversized packet, the link tries the batch
  # again one packet at a time. Thus one bad packet cannot cause the loss of
  # the packets near it. The link counts `:busy`, partial acceptance,
  # `:batch_too_large` and `:invalid_ingress` as drops. `:closed` and
  # `:link_down` mean that the stack is gone, and then the link exits.
  #
  # The link exits when its stack stops for any reason, also when an
  # application calls `SmolNet.stop_stack/1`. The link also stops its
  # stack when the link exits. Thus the root supervisor always starts the
  # two again together. The link also exits when the registry exits. This
  # fills a restarted registry with registrations again. Without this exit,
  # no process could reach the interface.

  use GenServer

  alias Wagyu.Admission
  alias Wagyu.EgressCredit

  @ingress_packets 32
  # The SmolNet default. It is set explicitly, because the batch sizes
  # depend on it.
  @ingress_bytes 65_536
  # The maximum plaintext that peers can have in the ingress queue at one
  # time.
  @queue_packets 256
  @queue_bytes 512 * 1024
  # The maximum egress from the stack that is not yet out of the interface.
  # This value is in the outbound bounds of the interface and of each peer.
  # Thus neither of them refuses egress because it has no space.
  @egress_credit_packets 128
  @egress_credit_bytes 256 * 1024

  @counters [egress: 1, egress_dropped: 2, ingress: 3, ingress_dropped: 4]

  @typedoc "The data that a sender needs to deliver to a link: its process, queue and counters."
  @type target :: %{pid: pid(), queue: Admission.t(), counters: :counters.counters_ref()}

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options), do: GenServer.start_link(__MODULE__, options)

  @doc """
  Admits decrypted packets for ingress into the stack of `root`, and sends
  them to its link in sequence. Returns the number of packets refused
  because the queue of the link was full or no link runs. The link counts
  these packets as ingress drops, but not when no link runs.
  """
  @spec deliver(term(), [binary()]) :: non_neg_integer()
  def deliver(root, packets) do
    case lookup(root) do
      {:ok, target} -> deliver_to(target, packets)
      :error -> length(packets)
    end
  end

  @doc "Returns the target for `deliver_to/2` of the running link of `root`, or `:error`."
  @spec lookup(term()) :: {:ok, target()} | :error
  def lookup(root) do
    case Wagyu.Registry.lookup(root, :link) do
      {:ok, link, %{queue: queue, counters: counters}} -> {:ok, %{pid: link, queue: queue, counters: counters}}
      :error -> :error
    end
  end

  @doc """
  Delivers the same as `deliver/2`, to a link found with `lookup/1`.
  Monitor the link, because packets sent to a link that exited are lost.
  """
  @spec deliver_to(target(), [binary()]) :: non_neg_integer()
  def deliver_to(%{pid: link, queue: queue, counters: counters}, packets) do
    {admitted, refused} = Admission.admit_prefix(queue, packets)
    if admitted != [], do: send(link, {:wg_plaintext, admitted})
    count(counters, :ingress_dropped, refused)
    refused
  end

  @doc """
  Tells a link found with `lookup/1` that some egress that it gave to the
  interface is now sent, staged or dropped. The link can then grant that
  credit to the stack again.
  """
  @spec retired(target()) :: :ok
  def retired(%{pid: link}) do
    send(link, :wg_egress_retired)
    :ok
  end

  @doc "Returns the counters of the link, or `:error` while no link runs."
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
    # The configured socket limit is one of the SmolNet limits. The link sets
    # it together with its own limits.
    {limits, stack} = Keyword.split(Keyword.fetch!(options, :stack), [:sockets])

    stack_options =
      stack ++
        [
          egress: {self(), ref},
          egress_credit: {@egress_credit_packets, @egress_credit_bytes},
          limits: Map.merge(Map.new(limits), %{input_packets: @ingress_packets, bytes_copied: @ingress_bytes}),
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
           # The credit that the stack holds, together with its batches in
           # transit to the link.
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

  # All other messages end a run of queued plaintext. Thus the batch goes
  # to the stack first.
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

  # Only two processes have an Erlang link to this process: its parent,
  # which GenServer handles, and the registry. A registration creates the
  # Erlang link to the registry. If the registry exits, all registrations of
  # this interface go with it. Thus the link exits, and the root starts the
  # interface again. Then the processes of the interface register again.
  defp handle({:EXIT, _registry, reason}, state), do: {:stop, {:shutdown, {:registry_down, reason}}, state}

  defp handle(_message, state), do: {:noreply, state}

  # If an interface exits before it takes its admitted packets, the packets
  # are lost with its mailbox. The count of its queue stays after the
  # interface exits. Thus the link monitors the interface that it supplies.
  # When that interface exits, the link counts all packets that the
  # interface did not take as dropped.
  defp track_interface(state, nil), do: state

  defp track_interface(%{interface: {pid, _egress, _credit, _monitor}} = state, {pid, _same_egress, _same_credit}),
    do: state

  defp track_interface(state, {pid, egress, credit}) do
    # A different interface registered only after the previous interface
    # exited, even if the :DOWN message for it did not arrive yet.
    %{reconcile(state) | interface: {pid, egress, credit, Process.monitor(pid)}}
  end

  defp reconcile(%{interface: {_pid, egress, _credit, monitor}} = state) do
    Process.demonitor(monitor, [:flush])
    {lost, _bytes} = Admission.usage(egress)
    count(state.counters, :egress_dropped, lost)
    %{state | interface: nil}
  end

  defp reconcile(state), do: state

  # Grants to the stack the credit that the stack and the interface do not
  # hold. The link reads the count of the interface after the retirements
  # that caused this grant. After that read, the count can only decrease.
  # Thus the grant is never more than the free credit.
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

  defp taken(%{interface: {_pid, _egress, credit, _monitor}}), do: EgressCredit.outstanding(credit)
  defp taken(_state), do: {0, 0}

  # Adds packets to the pending batch. When the next packet makes the batch
  # larger than the limits of the stack, the function sends the batch
  # first.
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

  # Before it sends a partial batch, waits until the mailbox is empty (a
  # zero timeout). Thus lists that are queued one after the other share one
  # ingress call.
  defp noreply({:ok, %{pending_count: 0} = state}), do: {:noreply, state}
  defp noreply({:ok, state}), do: {:noreply, state, 0}
  defp noreply({:stop, _reason, _state} = stop), do: stop

  defp count(_counters, _name, 0), do: :ok
  defp count(counters, name, increment), do: :counters.add(counters, Keyword.fetch!(@counters, name), increment)
end
