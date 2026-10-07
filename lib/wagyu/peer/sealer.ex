defmodule Wagyu.Peer.Sealer do
  @moduledoc false

  # Each peer has one sealer. The sealer encrypts the outbound packets of its
  # peer, and gives the frames to the sender of the peer
  # (`Wagyu.Peer.Sender`). Thus sealing is not on the scheduler of the peer,
  # which opens the inbound frames.
  #
  # The interface sends each egress batch of the peer to the sealer as
  # `{:wg_outbound, packets}`, admitted against the peer's `:outbound`
  # bound. The packets stay admitted until the sender sends them, the same
  # as when the peer sealed them.
  #
  # Keys. The sealer sends only under the `:current` key pair of its peer.
  # When a key pair becomes `:current`, the peer moves the outbound half of
  # its Decibel session to the sealer (`Decibel.split/3`), and sends
  # `{:wg_key, ticket, key, confirm}`. The sealer accepts the ticket and
  # closes the outbound half of the key that it had. Then it sends the
  # packets that it staged. If it has none and `confirm` is true, it sends a
  # keepalive, which confirms a key that the peer initiated. When the peer
  # discards a key pair whose outbound half the sealer holds, it sends
  # `{:wg_discard, local_index}`, and the sealer closes that half.
  #
  # Decibel discards a ticket that is not accepted in 60 seconds, and then
  # the outbound half is gone. If the sealer cannot accept a ticket, it
  # closes the key that it had, and sends `{:wg_key_lost, local_index}`. The
  # peer then discards that key pair and starts a handshake.
  #
  # The sealer applies the same send rules as the peer did. It sends under a
  # key while the key is younger than REJECT_AFTER_TIME and its nonce is
  # below REJECT_AFTER_MESSAGES. Otherwise it stages the packet against the
  # peer's `:staging` bound. The sealer reads the same monotonic clock as
  # the peer. A test that replaces the clock of a peer (`fake_clock/2`) also
  # replaces the clock of its sealer.
  #
  # Events for the peer. The timers of the peer depend on what the sealer
  # sends, and the sealer can need a handshake. After each message, the
  # sealer sends the peer one `{:wg_sealed, events, trigger, index, number}`
  # if it has something to report:
  #
  #   * `events` holds `:transport_sent` if the sealer sent data and
  #     `:keepalives_sent` if it sent a keepalive.
  #   * `trigger` is `:demand` if a packet waits for a key, `:rekey` if the
  #     key must be replaced, or nil. These are the triggers of the peer's
  #     `initiate/2`.
  #   * `index` is the local index of the key that the sealer had, or nil.
  #     The peer ignores a trigger about a key that it already replaced or
  #     discarded.
  #   * `number` is the sequence number of the last packet that the sealer
  #     staged. When a handshake attempt fails, or the keys expire, the peer
  #     drops only the staged packets up to the last number that it saw.
  #
  # The peer applies the events in the order of its mailbox. Local messages
  # join the mailbox when they are sent, and the sealer sends its report in
  # the same message that gives the frames to the sender. Thus a report
  # almost always arrives before an answer to its frames. If the sealer is
  # preempted between the two sends for long enough, the peer can take an
  # authenticated answer first. Then the late `:transport_sent` arms the
  # new-handshake timer again, and the peer can start one handshake that it
  # did not need, 15 seconds later. wireguard-go has the same race between
  # its send and receive routines. Do not compare a report with the time
  # that the peer took a frame: during a download the peer has a backlog,
  # so most reports would look older than the last frame, and the peer
  # would lose its keepalive and new-handshake timers.
  #
  # The peer asks for a keepalive with `:wg_keepalive`, and drops the
  # staged packets with a call (`drop_staged/1`). The call lets the peer ask
  # the interface to forget it immediately after, with no staged packet
  # still admitted.
  #
  # The sealer, the sender and the peer are the children of one
  # `Wagyu.Peer.Group`, and they stop together. The group starts the peer
  # last. Thus the peer sends `{:wg_owner, peer}` from its `init/1`, and the
  # sealer takes no other message before this one. The sealer holds Decibel
  # sessions in its process dictionary, so it is marked sensitive.

  use GenServer, restart: :temporary

  alias Wagyu.Admission
  alias Wagyu.Interface
  alias Wagyu.Noise

  # WireGuard's constants, the same as in `Wagyu.Peer`.
  @rekey_after_time 120_000
  @reject_after_time 180_000
  @rekey_after_messages 0x1000000000000000
  @spec start_link(map()) :: GenServer.on_start()
  def start_link(args), do: GenServer.start_link(__MODULE__, args)

  @doc "Drops and counts the packets that wait for a key, up to the sequence number `number`."
  @spec drop_staged(pid(), non_neg_integer()) :: :ok
  def drop_staged(sealer, number) do
    GenServer.call(sealer, {:wg_drop_staged, number}, :infinity)
  catch
    # The group stops the sealer with the peer. If the sealer already
    # stopped, the interface counts its staged packets as dropped.
    :exit, _reason -> :ok
  end

  @impl true
  def init(%{root: root, public_key: public_key, sender: sender, counters: counters, mtu: mtu} = args) do
    Process.flag(:sensitive, true)

    state = %{
      root: root,
      public_key: public_key,
      sender: sender,
      counters: counters,
      outbound: args.outbound,
      staging: args.staging,
      mtu: mtu,
      owner: nil,
      endpoint: nil,
      # The configure number of the endpoint (see `{:wg_endpoint, ...}`).
      endpoint_configured: 0,
      key: nil,
      staged: :queue.new(),
      # The sequence number of the last packet that the sealer staged.
      staged_number: 0,
      events: [],
      trigger: nil,
      clock: fn -> System.monotonic_time(:millisecond) end
    }

    {:ok, state, {:continue, :owner}}
  end

  @impl true
  def handle_continue(:owner, state) do
    receive do
      {:wg_owner, owner} -> {:noreply, %{state | owner: owner}}
    end
  end

  @impl true
  def handle_info({:wg_outbound, packets}, state) do
    {state, released} = send_packets(state, packets)
    if released, do: Interface.outbound_taken(state.root, state.public_key, self())
    {:noreply, report(state)}
  end

  def handle_info({:wg_key, ticket, key, confirm}, state) do
    case accept(ticket) do
      {:ok, session} ->
        state = %{close_key(state) | key: Map.put(key, :session, session)}

        state =
          cond do
            not :queue.is_empty(state.staged) -> send_staged(state)
            confirm -> send_keepalive(state)
            true -> state
          end

        {:noreply, report(state)}

      :error ->
        send(state.owner, {:wg_key_lost, key.local_index})
        {:noreply, close_key(state)}
    end
  end

  def handle_info({:wg_discard, local_index}, %{key: %{local_index: local_index}} = state),
    do: {:noreply, close_key(state)}

  def handle_info({:wg_discard, _local_index}, state), do: {:noreply, state}

  # The peer sends each endpoint that it learns or reports. The interface
  # sends a new configured endpoint itself, so the sealer takes it before
  # the egress that the interface forwards after the change.
  #
  # Each update carries the number of configure messages that the peer had
  # taken, the same number that `Wagyu.Interface.endpoint_learned/4` uses.
  # The interface's update carries the number that the peer has after it
  # takes the change. The sealer ignores an update with a lower number than
  # the last one it took: the peer learned that endpoint before the change,
  # and reported it after the interface sent the new one.
  def handle_info({:wg_endpoint, endpoint, configured}, %{endpoint_configured: last} = state) when configured >= last,
    do: {:noreply, %{state | endpoint: endpoint, endpoint_configured: configured}}

  def handle_info({:wg_endpoint, _endpoint, _configured}, state), do: {:noreply, state}

  def handle_info(:wg_keepalive, state), do: {:noreply, state |> send_keepalive() |> report()}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  # Drops the packets up to `number`. The sealer can stage newer packets
  # before it takes this call. The peer has not seen their demand yet, so
  # they stay, and their demand starts a new handshake attempt.
  def handle_call({:wg_drop_staged, number}, _from, state) do
    {dropped, kept} = state.staged |> :queue.to_list() |> Enum.split_with(fn {n, _packet} -> n <= number end)
    packets = Enum.map(dropped, &elem(&1, 1))
    Admission.release(state.staging, length(packets), Admission.bytes(packets))
    count(state, :staged_dropped, length(packets))
    {:reply, :ok, %{state | staged: :queue.from_list(kept)}}
  end

  @impl true
  def format_status(status), do: Wagyu.Redact.format_status(status, [:key, :staged])

  # Sends the events of this message to the peer, as one message.
  defp report(%{events: [], trigger: nil} = state), do: state

  defp report(state) do
    send(state.owner, {:wg_sealed, Enum.uniq(state.events), state.trigger, key_index(state), state.staged_number})
    %{state | events: [], trigger: nil}
  end

  defp key_index(%{key: nil}), do: nil
  defp key_index(%{key: key}), do: key.local_index

  defp event(state, event), do: %{state | events: [event | state.events]}

  # `:demand` takes precedence over `:rekey`, as it extends the attempt.
  defp trigger(%{trigger: :demand} = state, _trigger), do: state
  defp trigger(state, trigger), do: %{state | trigger: trigger}

  # A batch goes out under one key at one moment, as it did in the peer.
  # Returns the state and whether the sealer released packets itself.
  defp send_packets(state, packets) do
    case usable(state) do
      nil -> {Enum.reduce(packets, state, &unsealed(&2, &1)), true}
      key -> seal_batch(state, key, packets, [])
    end
  end

  # Each packet stays admitted against one bound until the sender sends its
  # frame: the outbound bound for a packet from the interface, the staging
  # bound for a staged packet. The sealer tells the sender which bound the
  # frames hold, and the sender releases each packet when it sends its
  # frame (`Wagyu.Peer.Sender`).
  #
  # A packet that moves from the outbound bound to the staging bound is
  # admitted to staging before it is released from outbound. Thus the
  # interface never sees the queues of the peer empty while the sealer
  # holds a packet, and cannot release the peer then.
  #
  # Each frame goes with the size of its packet.
  defp seal_batch(state, key, [], frames), do: {sent_batch(state, key, frames, :outbound), false}

  defp seal_batch(state, key, [packet | rest], frames) do
    case Noise.seal(key.session, key.remote_index, pad(packet, state.mtu)) do
      {:ok, frame} ->
        seal_batch(state, key, rest, [{frame, byte_size(packet)} | frames])

      :error ->
        state = sent_batch(state, key, frames, :outbound)
        {Enum.reduce([packet | rest], state, &unsealed(&2, &1)), true}
    end
  end

  # Staged packets go in order under the new key. If the key cannot seal a
  # packet, that packet and the packets after it stay staged, in the same
  # order, and keep their admission and their sequence numbers.
  defp send_staged(state) do
    staged = :queue.to_list(state.staged)
    state = %{state | staged: :queue.new()}

    case usable(state) do
      nil -> restage(state, staged)
      key -> seal_staged(state, key, staged, [])
    end
  end

  defp seal_staged(state, key, [], frames), do: sent_batch(state, key, frames, :staging)

  defp seal_staged(state, key, [{_number, packet} | rest] = staged, frames) do
    case Noise.seal(key.session, key.remote_index, pad(packet, state.mtu)) do
      {:ok, frame} -> seal_staged(state, key, rest, [{frame, byte_size(packet)} | frames])
      :error -> state |> sent_batch(key, frames, :staging) |> restage(staged)
    end
  end

  defp restage(state, []), do: state
  defp restage(state, staged), do: trigger(%{state | staged: :queue.from_list(staged)}, :rekey)

  defp sent_batch(state, _key, [], _bound), do: state

  defp sent_batch(state, key, frames, bound) do
    state
    |> transmit(Enum.reverse(frames), :transport_sent, bound)
    |> rekey_after_sending(key)
  end

  # A packet from the interface that does not go in a batch.
  defp unsealed(state, packet) do
    with %{} = key <- usable(state),
         {:ok, frame} <- Noise.seal(key.session, key.remote_index, pad(packet, state.mtu)) do
      state
      |> transmit([{frame, byte_size(packet)}], :transport_sent, :outbound)
      |> rekey_after_sending(key)
    else
      _no_usable_key -> stage(state, packet)
    end
  end

  # A packet from the interface is admitted to staging, and only then
  # released from outbound. If staging is full, it is dropped. The order
  # matters: `Wagyu.Interface` reads the outbound bound before the staging
  # bound when it checks that the peer is idle, so it cannot see both at
  # zero while the sealer moves a packet.
  #
  # Each staged packet gets the next sequence number. The reports to the
  # peer carry the last number, so the peer can drop only the packets that
  # it knows of (`drop_staged/2`).
  defp stage(state, packet) do
    bytes = byte_size(packet)

    case Admission.admit(state.staging, 1, bytes) do
      :ok ->
        Admission.release(state.outbound, 1, bytes)
        number = state.staged_number + 1
        state = %{state | staged: :queue.in({number, packet}, state.staged), staged_number: number}
        trigger(state, :demand)

      :full ->
        Admission.release(state.outbound, 1, bytes)
        count(state, :staged_dropped, 1)
        trigger(state, :rekey)
    end
  end

  # The peer asks for a keepalive only when it has a usable key. If the
  # sealer finds the key unusable, the peer must initiate instead.
  defp send_keepalive(state) do
    with %{} = key <- usable(state),
         {:ok, frame} <- Noise.seal(key.session, key.remote_index, "") do
      state |> transmit([{frame, 0}], :keepalives_sent) |> rekey_after_sending(key)
    else
      _no_usable_key -> trigger(state, :rekey)
    end
  end

  # The sealer has a key only after the peer sent it an endpoint: the peer
  # learns the endpoint of a handshake before it moves a key to the sealer.
  # Thus the endpoint is never nil here.
  defp transmit(%{endpoint: {_address, _port} = endpoint} = state, frames, event, bound \\ :outbound) do
    send(state.sender, {:wg_send, endpoint, frames, event, bound})
    event(state, event)
  end

  defp usable(%{key: nil}), do: nil

  defp usable(%{key: key} = state) do
    if state.clock.() - key.created_at < @reject_after_time, do: key
  end

  # REKEY_AFTER_MESSAGES applies to all keys. REKEY_AFTER_TIME applies only
  # to a key that the peer initiated.
  defp rekey_after_sending(state, key) do
    if Decibel.nonce(key.session, :out) >= @rekey_after_messages or
         (key.initiator and state.clock.() - key.created_at >= @rekey_after_time),
       do: trigger(state, :rekey),
       else: state
  end

  # Zero padding to a multiple of 16 bytes, but not more than the MTU.
  defp pad(packet, mtu) do
    size = byte_size(packet)
    padded = min(size + rem(16 - rem(size, 16), 16), mtu)
    if padded > size, do: [packet, <<0::size((padded - size) * 8)>>], else: packet
  end

  # A ticket that expired, or that is not valid, raises.
  defp accept(ticket) do
    {:ok, Decibel.accept_handoff(ticket)}
  rescue
    Decibel.HandoffError -> :error
  end

  defp close_key(%{key: nil} = state), do: state

  defp close_key(%{key: key} = state) do
    :ok = Decibel.close(key.session)
    %{state | key: nil}
  end

  defp count(_state, _name, 0), do: :ok
  defp count(state, name, increment), do: :ok = Interface.count_peer_event(state.counters, name, increment)
end
