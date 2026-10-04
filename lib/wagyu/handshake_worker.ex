defmodule Wagyu.HandshakeWorker do
  @moduledoc false

  # Processes one admitted handshake initiation, away from the UDP receive
  # path.
  #
  # A worker is the only place where the frame of an unauthenticated sender
  # meets Noise. The worker creates a responder session and reads the
  # initiation. This read authenticates the sender and gives its static
  # public key and timestamp. The worker then asks the interface to claim
  # the peer for that key (`Wagyu.Interface.claim_peer/3`). The interface
  # authorizes the key and the timestamp. It returns the one peer process
  # for the key, and the peer's configuration with its preshared key.
  #
  # The first read uses no preshared key (32 zero bytes). The initiator is
  # not known before the read, and Decibel takes the key when it creates a
  # session. IKpsk2 mixes the key in only at the end of the response, so the
  # read is the same for all keys. A peer without a preshared key keeps that
  # session. For a peer with a preshared key, the worker closes the session.
  # It then reads the same initiation again into a session with the peer's
  # key.
  #
  # The second read costs two more X25519 operations. It occurs only after
  # the claim authorizes an authenticated initiation. Thus a sender without
  # the initiator's static private key cannot cause it, and a replay also
  # cannot cause it. The worker never hands the session with the zero key to
  # a peer that has a preshared key.
  #
  # The worker hands its session to that peer with `Decibel.handoff/2`. It
  # sends the ticket directly to the peer as `{:wg_handoff, ticket,
  # metadata}`, and exits. The peer accepts the ticket in its own process.
  # The second read cannot fail for an initiation that the first read
  # authenticated. If it does fail, the worker sends the peer
  # `:wg_handoff_abandoned` instead. This message releases the handoff that
  # the claim admitted.
  #
  # Nothing waits for the peer to accept the ticket. The initiator cannot
  # address the new handshake until the peer responds, so no frame can wait
  # for it. Decibel discards a ticket that is not accepted within 60
  # seconds, or whose target exits first. The claim admits the ticket
  # message against the peer's handoff bound. Thus a peer that is slow to
  # empty its mailbox refuses new handshakes, and does not queue them
  # without limit.
  #
  # Every failure is silent: the worker closes its session, sends nothing
  # and exits. After a failed authentication, the worker exits with
  # `{:shutdown, :authentication_failed}`, and the interface counts it. The
  # interface counts rejected claims itself.
  #
  # The session's state lives in the process dictionary. Thus the process is
  # marked sensitive, which keeps that dictionary out of crash reports. Its
  # status hides the local key pair.

  use GenServer, restart: :temporary

  alias Wagyu.Config
  alias Wagyu.Noise
  alias Wagyu.Packet
  alias Wagyu.Packet.Initiation

  @typedoc """
  Asks the interface for the peer process and peer configuration that
  match an authenticated key and timestamp.
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
  Reads an initiation into `session`, which has no preshared key. Then
  claims its peer with `claim` and hands the peer a session. All of this
  occurs in the calling process. For a peer with a preshared key, `session`
  is closed. The peer gets a session from `responder` with the key, and the
  initiation is read again into that session.

  Returns `{:ok, peer}` after the ticket goes to `peer`. The handoff closed
  the session. Otherwise this function closes every session that it has,
  sends no ticket, and returns one of these errors:

    * `{:error, :authentication_failed}`.
    * The claim's own error.
    * `{:error, :handoff_failed}` if the peer exited before the handoff.
    * `{:error, :preshared_key_failed}` if the second read failed. The
      function first tells the peer with `:wg_handoff_abandoned`.
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
