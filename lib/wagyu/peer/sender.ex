defmodule Wagyu.Peer.Sender do
  @moduledoc false

  # Each peer has one sender. The sender writes the datagrams of its peer to
  # the interface's UDP socket with `:gen_udp.send/4`. Thus the send, which is
  # the largest single cost for each packet, is not on the scheduler of the
  # peer. There is one sender for each peer, so the datagrams of a peer stay
  # in the order that the peer sealed them.
  #
  # The sender and its peer are the children of one `Wagyu.Peer.Group`.
  # When one of them exits, the group stops the other.
  #
  # The peer sends `{:wg_send, endpoint, frames, event, released}`. The sender
  # sends the frames in order, and counts each frame that it sent as `event`
  # and each frame that it could not send as `:send_errors`. `released` is the
  # count and the bytes of outbound packets that the frames carry. These
  # packets stay admitted against the peer's `:outbound` bound until the
  # sender sent them. Thus the bound covers the queue of the sender, and the
  # egress credit of the link goes back only after the send. The sender then
  # releases them, and tells the interface (`Wagyu.Interface.outbound_taken/3`).

  use GenServer, restart: :temporary

  alias Wagyu.Admission
  alias Wagyu.Interface

  @spec start_link(map()) :: GenServer.on_start()
  def start_link(args), do: GenServer.start_link(__MODULE__, args)

  @impl true
  def init(%{root: root, public_key: public_key, socket: socket, counters: counters, outbound: outbound}) do
    state = %{
      root: root,
      public_key: public_key,
      socket: socket,
      counters: counters,
      outbound: outbound
    }

    {:ok, state}
  end

  @impl true
  def handle_info({:wg_send, {address, port}, frames, event, {packets, bytes}}, state) do
    {sent, errors} =
      Enum.reduce(frames, {0, 0}, fn frame, {sent, errors} ->
        case :gen_udp.send(state.socket, address, port, frame) do
          :ok -> {sent + 1, errors}
          {:error, _reason} -> {sent, errors + 1}
        end
      end)

    if packets > 0 do
      Admission.release(state.outbound, packets, bytes)
      Interface.outbound_taken(state.root, state.public_key, self())
    end

    count(state, event, sent)
    count(state, :send_errors, errors)
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp count(_state, _name, 0), do: :ok
  defp count(state, name, increment), do: :ok = Interface.count_peer_event(state.counters, name, increment)
end
