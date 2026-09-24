defmodule Wagyu.Noise do
  @moduledoc false

  # WireGuard's Noise parameters, and the responder's reading of an
  # initiation.
  #
  # WireGuard is Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s with its identifier as
  # the prologue. The first message's payload is the initiator's 12-byte
  # TAI64N timestamp. An omitted preshared key is 32 zero bytes, the only
  # key this release supports. The psk2 modifier mixes it in only at the end
  # of the second message, so a responder can read an initiation, and learn
  # who sent it, before choosing a peer's key.
  #
  # A session lives in the process dictionary of the process that creates
  # it, so these functions run in that process: a handshake worker, and
  # later the peer it hands the session to.

  alias Wagyu.Config
  alias Wagyu.Packet.Initiation

  @protocol "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
  @prologue "WireGuard v1 zx2c4 Jason@zx2c4.com"
  @zero_psk <<0::256>>

  @doc "Starts a responder session with the interface's key pair."
  @spec responder(Config.t()) :: Decibel.session()
  def responder(%Config{public_key: public_key, private_key: private_key}) do
    Decibel.new(@protocol, :rsp, %{s: {public_key, private_key}, psks: [@zero_psk], prologue: @prologue})
  end

  @doc """
  Reads an initiation's Noise fields into a responder session, returning the
  initiator's static public key and timestamp.

  Returns `:error` when the message fails authentication or carries an
  invalid public key. The session stays open either way, for the caller to
  hand off or close. Every initiation is attacker-supplied, so this never
  raises for one.
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
end
