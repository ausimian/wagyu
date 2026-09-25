defmodule Wagyu.Cookie do
  @moduledoc false

  # WireGuard's cookies, both sides of them (whitepaper section 5.4.7).
  #
  # A receiver under load answers a handshake message that has a valid MAC1
  # but no valid MAC2 with a cookie reply instead of Noise work. The cookie
  # is keyed BLAKE2s-128 of the message's source, its IP address and
  # big-endian UDP port as in Linux, under a random secret that the receiver
  # replaces once it is 120 seconds old. A MAC2 is valid only under the
  # cookie for the address the message actually came from, and only while
  # the secret that made that cookie is current. The reply carries the
  # cookie encrypted with XChaCha20-Poly1305 under HASH("cookie--" || the
  # receiver's public key), with a random 24-byte nonce and the MAC1 of the
  # message it answers as associated data.
  #
  # The sender of that message decrypts the reply with the key derived from
  # the public key it sent to and the MAC1 of the last handshake message it
  # sent, so it takes only a reply to that message from a party that knows
  # that public key. It then keys MAC2 on its handshake messages with the
  # cookie for 120 seconds.

  alias Wagyu.Blake2s
  alias Wagyu.Packet
  alias Wagyu.Packet.CookieReply
  alias Wagyu.XChaCha20Poly1305

  @label "cookie--"
  # COOKIE_REFRESH_TIME, in milliseconds: a secret's lifetime.
  @lifetime 120_000

  @derive {Inspect, except: [:secret]}
  @enforce_keys [:key]
  defstruct [:key, secret: nil, created_at: nil]

  @typedoc "A receiver's cookie state: the reply key and the current secret, if any."
  @type t :: %__MODULE__{key: <<_::256>>, secret: <<_::256>> | nil, created_at: integer() | nil}

  @type source :: {:inet.ip_address(), :inet.port_number()}

  @doc """
  Returns the key that cookie replies from the holder of `public_key` are
  encrypted with: BLAKE2s-256("cookie--" || public_key).
  """
  @spec key(<<_::256>>) :: <<_::256>>
  def key(<<public_key::binary-32>>), do: Blake2s.hash(@label <> public_key)

  @doc "Returns the cookie state of a receiver with `public_key`, which has no secret yet."
  @spec checker(<<_::256>>) :: t()
  def checker(public_key), do: %__MODULE__{key: key(public_key)}

  @doc """
  Returns whether `frame`, an initiation or response from `source`, has a
  MAC2 made with that source's cookie under the current secret at `now`,
  in monotonic milliseconds. With no secret, or one 120 seconds old, no
  MAC2 is valid.
  """
  @spec valid_mac2?(t(), binary(), source(), integer()) :: boolean()
  def valid_mac2?(%__MODULE__{secret: secret, created_at: created_at}, frame, source, now) do
    secret != nil and now - created_at < @lifetime and Packet.valid_mac2?(frame, make(secret, source))
  end

  @doc """
  Returns a cookie reply to `frame`, an initiation or response from
  `source`, addressed to `receiver_index`, the frame's sender index, and the
  cookie state, whose secret is replaced first if it is 120 seconds old.
  `nonce` defaults to 24 random bytes.
  """
  @spec reply(t(), binary(), non_neg_integer(), source(), integer(), <<_::192>>) :: {binary(), t()}
  def reply(checker, frame, receiver_index, source, now, nonce \\ :crypto.strong_rand_bytes(24)) do
    checker = refresh(checker, now)
    {:ok, mac1} = Packet.mac1(frame)
    {seal(checker.key, make(checker.secret, source), receiver_index, nonce, mac1), checker}
  end

  @doc """
  Returns the cookie for `source` under `secret`: keyed BLAKE2s-128 of its
  IP address, 4 or 16 bytes, and its UDP port, big-endian.
  """
  @spec make(<<_::256>>, source()) :: <<_::128>>
  def make(<<secret::binary-32>>, {address, port}),
    do: Blake2s.hash(<<address_bytes(address)::binary, port::16>>, secret, 16)

  @doc """
  Encodes a cookie reply to `receiver_index` carrying `cookie`, encrypted
  under `key` with `nonce` and the answered message's `mac1`.
  """
  @spec seal(<<_::256>>, <<_::128>>, non_neg_integer(), <<_::192>>, <<_::128>>) :: binary()
  def seal(key, <<cookie::binary-16>>, receiver_index, <<nonce::binary-24>>, <<mac1::binary-16>>) do
    encrypted = XChaCha20Poly1305.seal(key, nonce, cookie, mac1)
    Packet.encode(%CookieReply{receiver_index: receiver_index, nonce: nonce, encrypted_cookie: encrypted})
  end

  @doc """
  Decrypts a cookie reply with `key`, `key/1` of the public key the answered
  message was sent to, and that message's `mac1`. Returns `{:ok, cookie}`,
  or `:error` for a reply that does not authenticate. Every reply is
  attacker-supplied, so this never raises for one.
  """
  @spec open(CookieReply.t(), <<_::256>>, <<_::128>>) :: {:ok, <<_::128>>} | :error
  def open(%CookieReply{nonce: nonce, encrypted_cookie: encrypted}, key, mac1),
    do: XChaCha20Poly1305.open(key, nonce, encrypted, mac1)

  defp refresh(%__MODULE__{secret: secret, created_at: created_at} = checker, now)
       when is_binary(secret) and now - created_at < @lifetime,
       do: checker

  defp refresh(checker, now), do: %{checker | secret: :crypto.strong_rand_bytes(32), created_at: now}

  defp address_bytes({a, b, c, d}), do: <<a, b, c, d>>
  defp address_bytes({a, b, c, d, e, f, g, h}), do: <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
end
