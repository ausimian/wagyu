defmodule Wagyu.HandshakeWorker do
  @moduledoc false

  # Processes one admitted handshake initiation, off the UDP receive path.
  #
  # A worker is the only place an unauthenticated sender's frame meets
  # Noise. It creates a responder session and reads the initiation, which
  # authenticates the sender and yields its static public key and
  # timestamp. It then asks the interface to claim the peer for that key
  # (`Wagyu.Interface.claim_peer/3`), which authorizes the key and the
  # timestamp and returns the one peer process for it and the peer's
  # configuration, with its preshared key.
  #
  # The first read uses no preshared key (32 zero bytes), because the
  # initiator is not known until it is read, and Decibel takes the key when
  # a session is created. IKpsk2 mixes the key in only at the end of the
  # response, so the read is the same whatever the key. A peer without one
  # keeps that session. For a peer with one, the worker closes it and reads
  # the same initiation again into a session created with the peer's key.
  # That costs two more X25519 operations, only once the claim has
  # authorized an authenticated initiation, so a sender without the
  # initiator's static private key cannot cause it, and a replay cannot
  # either. The session made with the zero key is never handed to a peer
  # that has a preshared key.
  #
  # The worker hands its session to that peer with `Decibel.handoff/2`,
  # sends it the ticket directly as `{:wg_handoff, ticket, metadata}`, and
  # exits. The peer accepts the ticket in its own process. The second read
  # cannot fail for an initiation the first read authenticated, but should
  # it, the worker sends the peer `:wg_handoff_abandoned` instead, which
  # releases the handoff the claim admitted.
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

  @typedoc """
  Asks the interface for the peer process, and the peer's configuration,
  of an authenticated key and timestamp.
  """
  @type claim :: (<<_::256>>, <<_::96>> -> {:ok, pid(), Config.Peer.t()} | {:error, term()})

  @typedoc "Starts a responder session with a preshared key."
  @type responder :: (<<_::256>> -> Decibel.session())

  @zero_psk <<0::256>>

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
    responder = &Noise.responder(identity, &1)

    case respond(responder.(@zero_psk), frame, source, claim, responder) do
      {:error, :authentication_failed} -> {:stop, {:shutdown, :authentication_failed}, state}
      _handed_off_or_rejected -> {:stop, :normal, state}
    end
  end

  @impl true
  def format_status(status), do: Wagyu.Redact.format_status(status, [:identity])

  @doc """
  Reads an initiation into `session`, which has no preshared key, claims
  its peer with `claim` and hands the peer a session, all in the calling
  process. For a peer with a preshared key, that is a session from
  `responder` with the key, into which the initiation is read again, and
  `session` is closed.

  Returns `{:ok, peer}` once the ticket has been sent to `peer`; the handoff
  has closed the session. Otherwise this closes every session it has, sends
  no ticket, and says why: `{:error, :authentication_failed}`, the claim's
  own error, `{:error, :handoff_failed}` when the peer exited before the
  handoff, or `{:error, :preshared_key_failed}` when the second read failed,
  having told the peer so with `:wg_handoff_abandoned`.
  """
  @spec respond(Decibel.session(), binary(), {:inet.ip_address(), :inet.port_number()}, claim(), responder()) ::
          {:ok, pid()} | {:error, term()}
  def respond(session, frame, source, claim, responder) do
    {:ok, %Initiation{sender_index: sender_index} = initiation} = Packet.decode(frame)

    with {:ok, remote_key, timestamp} <- read(session, initiation),
         {:ok, peer, %Config.Peer{preshared_key: preshared_key}} <- claim.(remote_key, timestamp) do
      metadata = %{sender_index: sender_index, timestamp: timestamp, source: source}

      session
      |> with_preshared_key(preshared_key, responder, initiation, {remote_key, timestamp})
      |> hand_off(peer, metadata)
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

  defp with_preshared_key(session, @zero_psk, _responder, _initiation, _read), do: {:ok, session}

  defp with_preshared_key(session, preshared_key, responder, initiation, {remote_key, timestamp}) do
    :ok = Decibel.close(session)
    session = responder.(preshared_key)

    case Noise.read_initiation(session, initiation) do
      {:ok, ^remote_key, ^timestamp} ->
        {:ok, session}

      _failed ->
        :ok = Decibel.close(session)
        :error
    end
  end

  defp hand_off({:ok, session}, peer, metadata) do
    case handoff(session, peer) do
      {:ok, ticket} ->
        send(peer, {:wg_handoff, ticket, metadata})
        {:ok, peer}

      {:error, _reason} = error ->
        :ok = Decibel.close(session)
        error
    end
  end

  defp hand_off(:error, peer, _metadata) do
    send(peer, :wg_handoff_abandoned)
    {:error, :preshared_key_failed}
  end

  # A failed handoff leaves the session open; a successful one closes it.
  defp handoff(session, peer) do
    {:ok, Decibel.handoff(session, peer)}
  rescue
    Decibel.HandoffError -> {:error, :handoff_failed}
  end
end
