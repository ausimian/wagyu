defmodule Wagyu.HandshakeWorker do
  @moduledoc false

  # Processes one admitted handshake initiation, off the UDP receive path.
  #
  # A worker is the only place an unauthenticated sender's frame meets Noise:
  # it will create a responder session, learn the remote static key and
  # timestamp, claim the peer through the interface and hand the session to
  # it. Responder processing is not implemented yet, so a worker drops its
  # candidate silently, as it will drop one that fails authentication, and
  # exits.
  #
  # The worker will own a Decibel session, whose state lives in the process
  # dictionary, so the process is marked sensitive to keep that dictionary
  # out of crash reports, and its status hides the local key pair.

  use GenServer, restart: :temporary

  alias Wagyu.Config

  @spec start_link(Config.t(), map()) :: GenServer.on_start()
  def start_link(%Config{} = identity, candidate), do: GenServer.start_link(__MODULE__, {identity, candidate})

  @impl true
  def init({identity, %{root: _root, frame: <<_::binary-148>>, source: {_address, _port}} = candidate}) do
    Process.flag(:sensitive, true)
    {:ok, Map.put(candidate, :identity, identity), {:continue, :respond}}
  end

  @impl true
  def handle_continue(:respond, state), do: {:stop, :normal, state}

  @impl true
  def format_status(status), do: Wagyu.Redact.format_status(status, [:identity])
end
