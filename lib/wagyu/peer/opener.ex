defmodule Wagyu.Peer.Opener do
  @moduledoc false

  # Each peer has one opener. The opener decrypts the inbound transport
  # messages of its peer, and gives the IP packets to the link. Thus opening
  # is not on the scheduler of the peer, which keeps the handshakes, the key
  # slots and the timers.
  #
  # The interface sends each transport message for an index of the peer to
  # the opener as `{:wg_frame, local_index, frame, source}`, admitted
  # against the peer's `:inbound` bound. Responses and cookie replies go to
  # the peer, against the same bound.
  #
  # Keys. When a handshake completes, the peer moves both directions of its
  # Decibel session to other processes (`Decibel.split/2`). The opener gets
  # the inbound half with `{:wg_key, ticket, key}`. `key` holds the local
  # index, the creation time and `pending`. A key is pending if this peer
  # responded to its handshake, and the initiator has not confirmed it yet.
  # The opener holds the inbound half of each key pair in the slots of the
  # peer. When the peer discards a key pair, it sends `{:wg_discard,
  # local_index}`, and the opener closes that half.
  #
  # Decibel discards a ticket that is not accepted in 60 seconds, and then
  # the inbound half is gone. If the opener cannot accept a ticket, it sends
  # `{:wg_key_lost, local_index}`. The peer then discards that key pair.
  #
  # The opener applies the same receive rules as the peer did. It refuses a
  # transport message before any cryptography if one of these conditions is
  # true:
  #
  #   * Its key is older than REJECT_AFTER_TIME.
  #   * Its counter is a duplicate.
  #   * Its counter is older than the key's 8128-counter replay window.
  #
  # The counter enters the window only after the message authenticates. An
  # empty plaintext is a keepalive. Any other plaintext must hold an IP
  # packet, and these conditions must be true:
  #
  #   * The longest AllowedIPs match for the packet's source is this peer.
  #     The interface gives each opener only the part of the table that
  #     decides this check (`Wagyu.AllowedIPs.source_filter/2`).
  #   * The packet's IP length fits in the plaintext. The opener trims the
  #     plaintext to this length to remove the padding.
  #
  # The opener admits such a packet against the link's own bound and sends
  # it to the link (`Wagyu.Link.deliver_to/2`). It counts and drops all
  # other plaintext.
  #
  # Configuration. When the interface sends the peer a configure message,
  # it sends the opener `{:wg_configured, configured, filter}` itself. The
  # message holds the source filter, and the number of configure messages
  # that the peer has after it takes its message. Frames that the interface
  # admitted before the change are in the mailbox before the message. Thus
  # the old filter applies to them, and the opener reports their source
  # with the old number.
  #
  # Batching. Decrypted packets wait in `state.plaintext` while more frames
  # are in the queue. They go to the link together when one of these
  # occurs:
  #
  #   * The mailbox is empty.
  #   * A different kind of message arrives.
  #   * The opener took 32 frames after the first of these packets started
  #     to wait, whether or not those frames carried packets.
  #
  # Thus a flood of frames that carry no packets cannot hold a packet back.
  # The opener looks up the link one time and monitors it, and does not
  # look it up for each packet. The frame of a waiting packet stays
  # admitted, so if the opener dies, the interface counts the packet as
  # dropped.
  #
  # Events for the peer. The timers of the peer depend on what the opener
  # receives, and the endpoint of the peer follows the source of its
  # traffic. When the opener sends packets to the link, or when it took a
  # frame and no packet waits, it sends the peer one `{:wg_opened, events,
  # source, confirmed, configured, authenticated_at}` if it has something
  # to report:
  #
  #   * `events` holds `:authenticated` if a message authenticated, and
  #     `:data` if a message carried a plaintext that was not empty.
  #   * `source` is the source of the last keepalive, or of the last data
  #     packet that passed the checks above, or nil.
  #   * `confirmed` holds the local index of each pending key under which a
  #     message authenticated for the first time. The peer then promotes the
  #     key pair from `:next` to `:current`.
  #   * `configured` is the configure number of the last configured message.
  #     Any other message ends a batch, so all frames of a report have this
  #     number. The peer does not learn `source` from a report with a lower
  #     number than its own: the interface admitted those frames before a
  #     change to the configuration.
  #   * `authenticated_at` is the time on `state.clock` at which the last
  #     message of the report authenticated.
  #
  # A report can reach the peer after a report of the sealer about a later
  # send. The peer arms its new-handshake timer when it learns of a send,
  # and cancels it when it learns that a message authenticated after that.
  # Thus it cancels the timer only for a report whose `authenticated_at` is
  # not before the time at which it armed the timer. The sealer does not
  # compare the time of a send with the time of the last frame, because
  # during a download most reports would look old (see
  # `Wagyu.Peer.Sealer`). This comparison is different: during a download,
  # a message authenticates within milliseconds after the peer arms the
  # timer, so the peer still cancels it. A late send report costs at most
  # one extra handshake, as in wireguard-go. A late receive report must not
  # cancel the timer, because then the peer can lose its retry.
  #
  # The opener, the sealer, the sender and the peer are the children of one
  # `Wagyu.Peer.Group`, and they stop together. The group starts the peer
  # last. Thus the peer sends `{:wg_owner, peer}` from its `init/1`, and the
  # opener takes no other message before this one. The opener holds Decibel
  # sessions in its process dictionary, so it is marked sensitive.
  #
  # Time comes from `state.clock`, in monotonic milliseconds, the same clock
  # as the peer. A test that replaces the clock of a peer (`fake_clock/2`)
  # also replaces the clock of its opener.

  use GenServer, restart: :temporary

  alias Decibel.ReplayWindow
  alias Wagyu.Admission
  alias Wagyu.AllowedIPs
  alias Wagyu.Interface
  alias Wagyu.IP
  alias Wagyu.Link
  alias Wagyu.Noise
  alias Wagyu.Packet
  alias Wagyu.Packet.Transport

  # REJECT_AFTER_TIME, the same as in `Wagyu.Peer`.
  @reject_after_time 180_000
  # The number of counters that a key pair remembers behind the highest
  # counter that it accepted, as in wireguard-go and Linux.
  @replay_window 8128
  # The maximum number of frames that the opener takes while decrypted
  # packets wait for the link. Thus it is also the maximum number of packets
  # that go to the link together: the link's own ingress batch.
  @deliver_frames 32
  # Decrypted packets that wait for the link, newest first. The map also
  # holds the bytes of the frames that carried them, which stay admitted
  # until the packets go. It also counts the frames that the opener took
  # after the first packet started to wait.
  @no_plaintext %{packets: [], count: 0, frame_bytes: 0, frames: 0}
  # The events that the opener has not reported to the peer yet.
  # `authenticated` is the time at which the last message authenticated, or
  # nil.
  @no_events %{authenticated: nil, data: false, source: nil, confirmed: []}

  @spec start_link(map()) :: GenServer.on_start()
  def start_link(args), do: GenServer.start_link(__MODULE__, args)

  @impl true
  def init(%{root: root, public_key: public_key, counters: counters, inbound: inbound, allowed_ips: allowed_ips}) do
    Process.flag(:sensitive, true)

    state = %{
      root: root,
      public_key: public_key,
      counters: counters,
      inbound: inbound,
      allowed_ips: allowed_ips,
      # The configure number of the last `{:wg_configured, ...}`.
      configured: 0,
      owner: nil,
      keys: %{},
      plaintext: @no_plaintext,
      events: @no_events,
      link: nil,
      inbound_dropped: 0,
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
  def handle_info({:wg_frame, index, frame, source}, state) do
    waiting = state.plaintext.count
    state = receive_frame(state, index, frame, source)

    # If the packet of a frame now waits for the link, the opener releases
    # the frame with the packet.
    state =
      if state.plaintext.count > waiting do
        update_in(state.plaintext.frame_bytes, &(&1 + byte_size(frame)))
      else
        Admission.release(state.inbound, 1, byte_size(frame))
        state
      end

    if state.plaintext.count == 0 do
      {:noreply, report(state)}
    else
      state = update_in(state.plaintext.frames, &(&1 + 1))

      # A zero timeout makes the opener wait for an empty mailbox before it
      # delivers. Thus frames that are queued back to back reach the link
      # together. The opener also counts every frame, so frames that carry
      # no packet cannot keep the mailbox busy and hold back a waiting
      # packet.
      if state.plaintext.frames >= @deliver_frames, do: {:noreply, settle(state)}, else: {:noreply, state, 0}
    end
  end

  # Any other message ends a run of frames, so their packets go first.
  def handle_info(message, state), do: handle(message, settle(state))

  @impl true
  # The keys hold session handles and replay windows. Neither holds Noise
  # state.
  def format_status(status), do: Wagyu.Redact.format_status(status, [:plaintext])

  defp handle({:wg_key, ticket, %{local_index: index} = key}, state) do
    case accept(ticket) do
      {:ok, session} ->
        state = close_key(state, index)
        key = Map.merge(key, %{session: session, replay: ReplayWindow.new(@replay_window)})
        {:noreply, put_in(state.keys[index], key)}

      :error ->
        send(state.owner, {:wg_key_lost, index})
        {:noreply, close_key(state, index)}
    end
  end

  defp handle({:wg_discard, index}, state), do: {:noreply, close_key(state, index)}

  defp handle({:wg_configured, configured, filter}, state),
    do: {:noreply, %{state | configured: configured, allowed_ips: filter}}

  # The mailbox became empty while packets waited for the link. `settle/1`
  # already sent them to the link.
  defp handle(:timeout, state), do: {:noreply, state}

  defp handle({:DOWN, monitor, :process, _link, _reason}, %{link: %{monitor: monitor}} = state),
    do: {:noreply, %{state | link: nil}}

  defp handle(_message, state), do: {:noreply, state}

  # Inbound frames

  # The interface sends only transport messages to the opener.
  defp receive_frame(state, index, frame, source) do
    case Packet.decode(frame) do
      {:ok, %Transport{} = transport} -> transport(state, index, transport, source)
      _unexpected -> dropped(state)
    end
  end

  # The opener checks the replay window before decryption, which is the
  # expensive step. The window moves only after the message authenticates,
  # so a forged counter cannot close the window on genuine counters.
  defp transport(state, index, %Transport{counter: counter} = transport, source) do
    with {:key, %{} = key} <- {:key, Map.get(state.keys, index)},
         {:fresh, true} <- {:fresh, fresh?(state, key)},
         {:replay, :ok} <- {:replay, ReplayWindow.check(key.replay, counter)},
         {:ok, plaintext} <- Noise.open(key.session, transport) do
      state = put_in(state.keys[index], %{key | replay: ReplayWindow.commit(key.replay, counter), pending: false})
      state = %{state | events: %{state.events | authenticated: state.clock.()}}
      state = if key.pending, do: update_in(state.events.confirmed, &[index | &1]), else: state
      receive_plaintext(state, plaintext, source)
    else
      {:fresh, false} -> state |> count(:transport_expired) |> dropped()
      {:replay, {:error, _duplicate_or_stale}} -> state |> count(:transport_replayed) |> dropped()
      _no_key_or_unauthenticated -> state |> count(:transport_invalid) |> dropped()
    end
  end

  defp receive_plaintext(state, "", source), do: state |> learn_endpoint(source) |> count(:keepalives_received)

  defp receive_plaintext(state, plaintext, source) do
    state = %{state | events: %{state.events | data: true}}

    with {:ip, {:ok, %{source: address, length: length}}} <- {:ip, IP.parse(plaintext)},
         {:allowed, true} <- {:allowed, AllowedIPs.allowed?(state.allowed_ips, address, state.public_key)} do
      %{packets: packets, count: waiting} = state.plaintext
      packets = [binary_part(plaintext, 0, length) | packets]
      %{learn_endpoint(state, source) | plaintext: %{state.plaintext | packets: packets, count: waiting + 1}}
    else
      {:ip, {:error, _reason}} -> state |> count(:transport_malformed) |> dropped()
      {:allowed, false} -> state |> count(:transport_source_denied) |> dropped()
    end
  end

  defp learn_endpoint(state, source), do: %{state | events: %{state.events | source: source}}

  # Sends the packets that wait for the link, and reports to the peer.
  defp settle(%{plaintext: %{count: 0}} = state), do: state
  defp settle(state), do: state |> deliver() |> report()

  # The link counts a packet that it refuses as an ingress drop. The opener
  # releases the frames only after their packets go, so if the opener dies
  # first, the interface counts them as dropped.
  defp deliver(state) do
    %{packets: packets, count: waiting, frame_bytes: frame_bytes} = state.plaintext

    {refused, state} =
      case link(state) do
        {:ok, link, state} -> {Link.deliver_to(link, Enum.reverse(packets)), state}
        :error -> {waiting, state}
      end

    Admission.release(state.inbound, waiting, frame_bytes)
    count(%{state | plaintext: @no_plaintext}, :transport_received, waiting - refused)
  end

  # The opener looks up the link when it first needs it, and monitors it
  # until it exits. A link that fails also restarts its peers. But the
  # monitor prevents a send to a link that stopped before the restart.
  defp link(%{link: nil} = state) do
    case Link.lookup(state.root) do
      {:ok, link} ->
        link = Map.put(link, :monitor, Process.monitor(link.pid))
        {:ok, link, %{state | link: link}}

      :error ->
        :error
    end
  end

  defp link(state), do: {:ok, state.link, state}

  # Sends the events of the frames since the last report to the peer, as one
  # message.
  defp report(%{events: %{authenticated: nil}} = state), do: state

  defp report(%{events: events} = state) do
    confirmed = Enum.reverse(events.confirmed)

    send(
      state.owner,
      {:wg_opened, events_list(events), events.source, confirmed, state.configured, events.authenticated}
    )

    %{state | events: @no_events}
  end

  defp events_list(%{data: true}), do: [:authenticated, :data]
  defp events_list(%{data: false}), do: [:authenticated]

  # REJECT_AFTER_TIME: a key that is this old does not receive.
  defp fresh?(state, key), do: state.clock.() - key.created_at < @reject_after_time

  # A ticket that expired, or that is not valid, raises.
  defp accept(ticket) do
    {:ok, Decibel.accept_handoff(ticket)}
  rescue
    Decibel.HandoffError -> :error
  end

  defp close_key(state, index) do
    case Map.pop(state.keys, index) do
      {nil, _keys} ->
        state

      {key, keys} ->
        :ok = Decibel.close(key.session)
        %{state | keys: keys}
    end
  end

  defp count(state, name, increment \\ 1)
  defp count(state, _name, 0), do: state

  defp count(state, name, increment) do
    :ok = Interface.count_peer_event(state.counters, name, increment)
    state
  end

  defp dropped(state), do: %{state | inbound_dropped: state.inbound_dropped + 1}
end
