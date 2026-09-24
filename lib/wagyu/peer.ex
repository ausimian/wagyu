defmodule Wagyu.Peer do
  @moduledoc false

  # One process per active configured peer, started by the interface when
  # outbound traffic or an authorized initiation first needs it.
  #
  # A peer will own its accepted handshakes and transport sessions, key
  # slots, replay windows, endpoint and timers, and send its own datagrams on
  # the interface's UDP socket.
  #
  # Inbound handshakes. After the interface authorizes an initiation for
  # this peer, the handshake worker hands its responder session over with
  # `{:wg_handoff, ticket, metadata}`, where `metadata` holds the initiator's
  # sender index, the initiation's timestamp and the source endpoint. The
  # peer accepts the ticket, registers a local index for the handshake with
  # the interface, and holds both as its pending handshake, which the
  # response (not implemented yet) will complete. A newer initiation
  # replaces the pending handshake: its session is closed and its index
  # retired. An older one, which can arrive late from a slow worker, is
  # closed instead. A ticket that cannot be accepted is dropped.
  #
  # Every message sent here was admitted against one of the peer's bounds
  # first: `{:wg_outbound, ip_packet}` against `:outbound`,
  # `{:wg_frame, local_index, frame, source}` against `:inbound`, and the
  # handoff against `:handoffs`, which counts messages only. The peer
  # releases each as it takes it off the mailbox. With no transport session
  # to encrypt or decrypt with yet, it drops frames and outbound packets.
  #
  # The peer owns Decibel sessions, whose state lives in the process
  # dictionary, so it is marked sensitive, and its status hides the local
  # key pair and the peer's preshared key.

  use GenServer, restart: :temporary

  alias Wagyu.Admission
  alias Wagyu.Config
  alias Wagyu.Interface
  alias Wagyu.TAI64N

  @spec start_link(Config.t(), map()) :: GenServer.on_start()
  def start_link(%Config{} = identity, args), do: GenServer.start_link(__MODULE__, {identity, args})

  @impl true
  def init({identity, %{root: root, peer: %Config.Peer{} = peer, socket: socket} = args}) do
    %{inbound: inbound, outbound: outbound, handoffs: handoffs} = args
    Process.flag(:sensitive, true)

    {:ok,
     %{
       root: root,
       public_key: peer.public_key,
       identity: identity,
       peer: peer,
       socket: socket,
       inbound: inbound,
       outbound: outbound,
       handoffs: handoffs,
       pending: nil,
       outbound_dropped: 0,
       inbound_dropped: 0
     }}
  end

  @impl true
  def handle_info({:wg_handoff, ticket, metadata}, state) do
    Admission.release(state.handoffs, 1, 0)
    {:noreply, accept_handshake(state, ticket, metadata)}
  end

  def handle_info({:wg_outbound, packet}, state) do
    Admission.release(state.outbound, 1, byte_size(packet))
    {:noreply, %{state | outbound_dropped: state.outbound_dropped + 1}}
  end

  def handle_info({:wg_frame, _index, frame, _source}, state) do
    Admission.release(state.inbound, 1, byte_size(frame))
    {:noreply, %{state | inbound_dropped: state.inbound_dropped + 1}}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def format_status(status), do: Wagyu.Redact.format_status(status, [:identity, :peer])

  # Inbound handshakes

  defp accept_handshake(state, ticket, metadata) do
    with {:ok, session} <- accept(ticket),
         :ok <- newer(state.pending, metadata, session),
         {:ok, index} <- allocate_index(state, session) do
      pending = Map.merge(metadata, %{session: session, local_index: index})
      %{discard_pending(state) | pending: pending}
    else
      :error -> state
    end
  end

  # A ticket that has expired, or was already accepted, raises.
  defp accept(ticket) do
    {:ok, Decibel.accept_handoff(ticket)}
  rescue
    Decibel.HandoffError -> :error
  end

  defp newer(nil, _metadata, _session), do: :ok

  defp newer(pending, metadata, session) do
    if TAI64N.after?(metadata.timestamp, pending.timestamp), do: :ok, else: close(session)
  end

  defp allocate_index(state, session) do
    case Interface.allocate_index(state.root, state.public_key) do
      {:ok, _index} = ok -> ok
      :error -> close(session)
    end
  end

  defp discard_pending(%{pending: nil} = state), do: state

  defp discard_pending(%{pending: pending} = state) do
    :ok = Decibel.close(pending.session)
    :ok = Interface.retire_index(state.root, pending.local_index)
    %{state | pending: nil}
  end

  defp close(session) do
    :ok = Decibel.close(session)
    :error
  end
end
