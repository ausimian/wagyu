defmodule Wagyu.Peer do
  @moduledoc false

  # One process per active configured peer, started by the interface when
  # traffic first needs it.
  #
  # A peer will own its accepted handshakes and transport sessions, key
  # slots, replay windows, endpoint and timers, and send its own datagrams on
  # the interface's UDP socket. Until handshakes exist it has no session to
  # encrypt or decrypt with, so it drains what the interface admits to it and
  # drops it, keeping both queues' bounds honest.
  #
  # Every message the interface sends here was admitted against one of the
  # peer's two bounds first: `{:wg_outbound, ip_packet}` against `:outbound`
  # and `{:wg_frame, local_index, frame, source}` against `:inbound`. The
  # peer releases each as it takes it off the mailbox.
  #
  # The peer will own Decibel sessions, so it is marked sensitive, and its
  # status hides the local key pair and the peer's preshared key.

  use GenServer, restart: :temporary

  alias Wagyu.Admission
  alias Wagyu.Config

  @spec start_link(Config.t(), map()) :: GenServer.on_start()
  def start_link(%Config{} = identity, args), do: GenServer.start_link(__MODULE__, {identity, args})

  @impl true
  def init({identity, %{root: root, peer: %Config.Peer{} = peer, socket: socket, inbound: inbound, outbound: outbound}}) do
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
       outbound_dropped: 0,
       inbound_dropped: 0
     }}
  end

  @impl true
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
end
