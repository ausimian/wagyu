defmodule Wagyu.HandshakeWorker do
  @moduledoc false

  # Processes one admitted handshake initiation, off the UDP receive path.
  #
  # A worker is the only place an unauthenticated sender's frame meets
  # Noise. It creates a responder session and reads the initiation, which
  # authenticates the sender and yields its static public key and
  # timestamp. It then asks the interface to claim the peer for that key
  # (`Wagyu.Interface.claim_peer/3`), which authorizes the key and the
  # timestamp and returns the one peer process for it. The worker hands its
  # session to that peer with `Decibel.handoff/2`, sends it the ticket
  # directly as `{:wg_handoff, ticket, metadata}`, and exits. The peer
  # accepts the ticket in its own process.
  #
  # Nothing waits on the peer's acceptance. The initiator cannot address the
  # new handshake until the peer responds, so no frame can be waiting on it,
  # and Decibel discards a ticket that is not accepted within 60 seconds or
  # whose target exits first. The claim admits the ticket message against
  # the peer's handoff bound, so a peer that is slow to drain its mailbox
  # refuses new handshakes rather than queueing them without limit.
  #
  # Every failure is silent: the worker closes its session, sends nothing
  # and exits. A failed authentication exits with
  # `{:shutdown, :authentication_failed}`, which the interface counts; the
  # interface counts rejected claims itself.
  #
  # The session's state lives in the process dictionary, so the process is
  # marked sensitive to keep that dictionary out of crash reports, and its
  # status hides the local key pair.

  use GenServer, restart: :temporary

  alias Wagyu.Config
  alias Wagyu.Noise
  alias Wagyu.Packet
  alias Wagyu.Packet.Initiation

  @typedoc "Asks the interface for the peer process of an authenticated key and timestamp."
  @type claim :: (<<_::256>>, <<_::96>> -> {:ok, pid()} | {:error, term()})

  @spec start_link(Config.t(), map()) :: GenServer.on_start()
  def start_link(%Config{} = identity, candidate), do: GenServer.start_link(__MODULE__, {identity, candidate})

  @impl true
  def init({identity, %{root: _root, frame: <<_::binary-148>>, source: {_address, _port}} = candidate}) do
    Process.flag(:sensitive, true)
    {:ok, Map.put(candidate, :identity, identity), {:continue, :respond}}
  end

  @impl true
  def handle_continue(:respond, %{identity: identity, root: root, frame: frame, source: source} = state) do
    claim = &Wagyu.Interface.claim_peer(root, &1, &2)

    case respond(Noise.responder(identity), frame, source, claim) do
      {:error, :authentication_failed} -> {:stop, {:shutdown, :authentication_failed}, state}
      _handed_off_or_rejected -> {:stop, :normal, state}
    end
  end

  @impl true
  def format_status(status), do: Wagyu.Redact.format_status(status, [:identity])

  @doc """
  Reads an initiation into `session`, claims its peer with `claim` and hands
  the session to that peer, all in the calling process.

  Returns `{:ok, peer}` once the ticket has been sent to `peer`; the handoff
  has closed `session`. Otherwise this closes `session`, sends nothing, and
  says why: `{:error, :authentication_failed}`, the claim's own error, or
  `{:error, :handoff_failed}` when the peer exited before the handoff.
  """
  @spec respond(Decibel.session(), binary(), {:inet.ip_address(), :inet.port_number()}, claim()) ::
          {:ok, pid()} | {:error, term()}
  def respond(session, frame, source, claim) do
    {:ok, %Initiation{sender_index: sender_index} = initiation} = Packet.decode(frame)

    with {:ok, remote_key, timestamp} <- read(session, initiation),
         {:ok, peer} <- claim.(remote_key, timestamp),
         {:ok, ticket} <- handoff(session, peer) do
      send(peer, {:wg_handoff, ticket, %{sender_index: sender_index, timestamp: timestamp, source: source}})
      {:ok, peer}
    else
      {:error, _reason} = error ->
        :ok = Decibel.close(session)
        error
    end
  end

  defp read(session, initiation) do
    case Noise.read_initiation(session, initiation) do
      {:ok, _remote_key, _timestamp} = ok -> ok
      :error -> {:error, :authentication_failed}
    end
  end

  # A failed handoff leaves the session open; a successful one closes it.
  defp handoff(session, peer) do
    {:ok, Decibel.handoff(session, peer)}
  rescue
    Decibel.HandoffError -> {:error, :handoff_failed}
  end
end
