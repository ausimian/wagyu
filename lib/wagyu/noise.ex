defmodule Wagyu.Noise do
  @moduledoc false

  # WireGuard's Noise parameters and the messages built from them.
  #
  # WireGuard is Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s with its identifier as
  # the prologue. The first message's payload is the initiator's 12-byte
  # TAI64N timestamp and the second's is empty. A peer without a preshared
  # key uses 32 zero bytes.
  #
  # The psk2 modifier mixes the key in only at the end of the second
  # message. Thus the read of an initiation does not depend on the key's
  # value. A responder reads an initiation with the zero key to learn who
  # sent it. If that peer has a key, the responder then reads the initiation
  # again with that key (see `Wagyu.HandshakeWorker`).
  #
  # Noise's Split gives the initiator the first key to send with. This is
  # WireGuard's convention and Decibel's default. Transport messages have
  # empty associated data. The ChaChaPoly nonce is four zero bytes followed
  # by the 64-bit little-endian counter. Thus the counter in a transport
  # header is the session's nonce. WireGuard rotates keys with a new
  # handshake, and never with Noise's rekey.
  #
  # A session lives in the process dictionary of the process that creates
  # it. Thus these functions run in that process: a handshake worker, the
  # peer that the worker hands the session to, or a peer that initiates.
  # Every function that reads attacker-supplied data returns `:error`, and
  # does not raise.
  #
  # `Decibel.new/3` makes the sessions, if the caller does not pass another
  # function of the same shape. Only known-answer tests do this, to fix the
  # ephemeral keys.

  alias Wagyu.Config
  alias Wagyu.IndexTable
  alias Wagyu.Packet
  alias Wagyu.Packet.{Initiation, Response, Transport}

  @protocol "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
  @prologue "WireGuard v1 zx2c4 Jason@zx2c4.com"
  @zero_psk <<0::256>>

  # REJECT_AFTER_MESSAGES: a key does not send or accept a counter this
  # high.
  @reject_after_messages 0xFFFFFFFFFFFFDFFF

  @typedoc "Makes a session, as `Decibel.new/3` does."
  @type new :: (String.t(), Decibel.role(), Decibel.key_material() -> Decibel.session())

  @doc """
  Starts a responder session with the interface's key pair and
  `preshared_key`. The default is no key (32 zero bytes). The initiator is
  not known until the responder reads its initiation, so a first read uses
  the default.
  """
  @spec responder(Config.t(), <<_::256>>, new()) :: Decibel.session()
  def responder(
        %Config{public_key: public_key, private_key: private_key},
        <<_::binary-32>> = preshared_key \\ @zero_psk,
        new \\ &Decibel.new/3
      ) do
    new.(@protocol, :rsp, %{s: {public_key, private_key}, psks: [preshared_key], prologue: @prologue})
  end

  @doc """
  Starts an initiator session to the holder of `remote_key`. The session
  uses the interface's key pair and the peer's `preshared_key` (32 zero
  bytes for no key).
  """
  @spec initiator(Config.t(), <<_::256>>, <<_::256>>, new()) :: Decibel.session()
  def initiator(
        %Config{public_key: public_key, private_key: private_key},
        <<_::binary-32>> = remote_key,
        <<_::binary-32>> = preshared_key,
        new \\ &Decibel.new/3
      ) do
    new.(@protocol, :ini, %{s: {public_key, private_key}, rs: remote_key, psks: [preshared_key], prologue: @prologue})
  end

  @doc """
  Writes an initiator session's first handshake message. Frames it as a
  148-byte initiation from `sender_index` that carries `timestamp`.

  `mac1_key` (the responder's) keys MAC1. `cookie` keys MAC2. It is the
  responder's latest cookie, or `nil`, which gives a zero MAC2.
  """
  @spec write_initiation(Decibel.session(), IndexTable.index(), <<_::96>>, <<_::256>>, <<_::128>> | nil) :: binary()
  def write_initiation(session, sender_index, <<_::binary-12>> = timestamp, mac1_key, cookie \\ nil) do
    <<ephemeral::binary-32, static::binary-48, encrypted_timestamp::binary-28>> =
      session |> Decibel.handshake_encrypt(timestamp) |> IO.iodata_to_binary()

    %Initiation{
      sender_index: sender_index,
      ephemeral: ephemeral,
      encrypted_static: static,
      encrypted_timestamp: encrypted_timestamp
    }
    |> Packet.encode()
    |> Packet.put_macs(mac1_key, cookie)
  end

  @doc """
  Reads an initiation's Noise fields into a responder session. Returns the
  initiator's static public key and timestamp.

  Returns `:error` if the message fails authentication or carries an
  invalid public key. In both cases the session stays open, and the caller
  hands it off or closes it. Every initiation is attacker-supplied, so this
  function never raises for one.
  """
  @spec read_initiation(Decibel.session(), Initiation.t()) :: {:ok, <<_::256>>, <<_::96>>} | :error
  def read_initiation(session, %Initiation{
        ephemeral: ephemeral,
        encrypted_static: static,
        encrypted_timestamp: timestamp
      }) do
    payload = session |> Decibel.handshake_decrypt([ephemeral, static, timestamp]) |> IO.iodata_to_binary()

    case {Decibel.remote_key(session), payload} do
      {<<_::binary-32>> = remote_key, <<_::binary-12>>} -> {:ok, remote_key, payload}
      _unexpected -> :error
    end
  rescue
    Decibel.DecryptionError -> :error
  end

  @doc """
  Writes a responder session's second handshake message, which has an empty
  payload. The session must first read an initiation. Frames the message as
  a 92-byte response from `sender_index` to the initiator's
  `receiver_index`. The session is then ready for transport.

  `mac1_key` (the initiator's) keys MAC1. `cookie` keys MAC2. It is the
  initiator's latest cookie, or `nil`, which gives a zero MAC2.

  Returns `:error`, and does not change the session, if the initiator's
  keys are unusable.
  """
  @spec write_response(Decibel.session(), IndexTable.index(), IndexTable.index(), <<_::256>>, <<_::128>> | nil) ::
          {:ok, binary()} | :error
  def write_response(session, sender_index, receiver_index, mac1_key, cookie \\ nil) do
    <<ephemeral::binary-32, nothing::binary-16>> = session |> Decibel.handshake_encrypt("") |> IO.iodata_to_binary()

    frame =
      %Response{
        sender_index: sender_index,
        receiver_index: receiver_index,
        ephemeral: ephemeral,
        encrypted_nothing: nothing
      }
      |> Packet.encode()
      |> Packet.put_macs(mac1_key, cookie)

    {:ok, frame}
  rescue
    Decibel.DecryptionError -> :error
  end

  @doc """
  Reads a response into an initiator session that wrote its initiation.
  The session is then ready for transport.

  Returns `:error` if the response fails authentication. The session does
  not change, and it continues to wait for the genuine response. Every
  response is attacker-supplied, so this function never raises for one.
  """
  @spec read_response(Decibel.session(), Response.t()) :: :ok | :error
  def read_response(session, %Response{ephemeral: ephemeral, encrypted_nothing: nothing}) do
    payload = Decibel.handshake_decrypt(session, [ephemeral, nothing])
    if IO.iodata_length(payload) == 0 and Decibel.handshake_complete?(session), do: :ok, else: :error
  rescue
    Decibel.DecryptionError -> :error
  end

  @doc """
  Encrypts `plaintext` with a transport session and frames it as a transport
  message to `receiver_index`. Its counter is the session's next outbound
  nonce.

  Returns `:error`, with nothing to send, when that counter reaches
  REJECT_AFTER_MESSAGES (2^64 - 2^13 - 1). The call still uses the counter,
  so every later call also returns `:error`.
  """
  @spec seal(Decibel.session(), IndexTable.index(), iodata()) :: {:ok, binary()} | :error
  def seal(session, receiver_index, plaintext) do
    case Decibel.encrypt_with_nonce(session, plaintext, "") do
      {counter, packet} when counter < @reject_after_messages ->
        {:ok, Packet.encode_transport(receiver_index, counter, packet)}

      _exhausted ->
        :error
    end
  end

  @doc """
  Decrypts a transport message with a transport session. Returns its
  plaintext, which is empty for a keepalive.

  Returns `:error` if the message fails authentication. `Wagyu.Packet`
  already refused counters at or above REJECT_AFTER_MESSAGES. This function
  does no replay check; the caller does it.
  """
  @spec open(Decibel.session(), Transport.t()) :: {:ok, binary()} | :error
  def open(session, %Transport{counter: counter, encrypted_packet: packet}) when counter < @reject_after_messages do
    {:ok, session |> Decibel.decrypt(packet, "", nonce: counter) |> IO.iodata_to_binary()}
  rescue
    Decibel.DecryptionError -> :error
  end

  def open(_session, %Transport{}), do: :error
end
