defmodule Wagyu.Peer.Sender do
  @moduledoc false

  # Each peer has one sender. The sender writes the datagrams of its peer to
  # the interface's UDP socket with `:gen_udp.send/4`. Thus the send, which is
  # the largest single cost for each packet, is not on the scheduler of the
  # peer. There is one sender for each peer, so the datagrams of a peer stay
  # in the order that the peer sealed them.
  #
  # The sender, the sealer and the peer are the children of one
  # `Wagyu.Peer.Group`. When one of them exits, the group stops the others.
  #
  # The sealer and the peer send `{:wg_send, endpoint, frames, event,
  # bound}`. Each item of `frames` is `{frame, size}`. `size` is the bytes
  # of the packet that the frame carries, or 0 for a frame that no packet is
  # admitted for, such as a handshake message. `bound` is the bound of the
  # peer that the packets are admitted against: `:outbound` for egress from
  # the interface, `:staging` for packets that waited for a key. The packets
  # stay admitted until the sender sends them. Thus the bounds cover the
  # queue of the sender, and the egress credit of the link goes back only
  # after the send.
  #
  # The sender sends the frames in order, in chunks of 8. Immediately before
  # it sends a chunk, it releases the packets of the chunk and counts each
  # frame as `event`. It then moves each frame that it could not send from
  # `event` to `:send_errors`. Thus a frame is counted before it can reach
  # the network, and `Wagyu.info/1` is never behind what the remote party
  # received. If the sender stops during a batch, the interface counts only
  # the packets of later chunks as dropped. It can miss, or count as sent,
  # at most the rest of the current chunk. A release for each frame costs
  # 2–4% of loopback throughput, because the interface updates the same
  # counters at the same time. After a batch of outbound packets, the sender
  # tells the interface that it released them
  # (`Wagyu.Interface.outbound_taken/3`).

  use GenServer, restart: :temporary

  alias Wagyu.Admission
  alias Wagyu.Interface

  # The frames that the sender releases and counts together. If the sender
  # stops during a chunk, the interface can miss the remaining packets of
  # that chunk in its count of dropped packets.
  @chunk 8

  @spec start_link(map()) :: GenServer.on_start()
  def start_link(args), do: GenServer.start_link(__MODULE__, args)

  @impl true
  def init(%{root: root, public_key: public_key, socket: socket, counters: counters} = args) do
    state = %{
      root: root,
      public_key: public_key,
      socket: socket,
      counters: counters,
      outbound: args.outbound,
      staging: args.staging
    }

    {:ok, state}
  end

  @impl true
  def handle_info({:wg_send, {address, port}, frames, event, bound}, state) do
    counters = {Interface.peer_counter(event), Interface.peer_counter(:send_errors)}
    released = send_chunks(state, {address, port}, frames, counters, Map.fetch!(state, bound), false)
    if released and bound == :outbound, do: Interface.outbound_taken(state.root, state.public_key, self())
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  # Sends the frames in chunks of `@chunk`, and releases their packets from
  # `admission`. Returns whether the sender released packets.
  defp send_chunks(_state, _endpoint, [], _counters, _admission, released), do: released

  defp send_chunks(
         state,
         {address, port} = endpoint,
         frames,
         {sent_index, errors_index} = counters,
         admission,
         released
       ) do
    {chunk, rest} = Enum.split(frames, @chunk)

    {packets, bytes} =
      Enum.reduce(chunk, {0, 0}, fn {_frame, size}, {n, b} -> if size > 0, do: {n + 1, b + size}, else: {n, b} end)

    if packets > 0, do: Admission.release(admission, packets, bytes)
    :counters.add(state.counters, sent_index, length(chunk))

    errors =
      Enum.count(chunk, fn {frame, _size} ->
        match?({:error, _reason}, :gen_udp.send(state.socket, address, port, frame))
      end)

    if errors > 0 do
      :counters.sub(state.counters, sent_index, errors)
      :counters.add(state.counters, errors_index, errors)
    end

    send_chunks(state, endpoint, rest, counters, admission, released or packets > 0)
  end
end
