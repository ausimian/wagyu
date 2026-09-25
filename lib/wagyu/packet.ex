defmodule Wagyu.Packet do
  @moduledoc false

  # WireGuard message framing, MAC1 and MAC2.
  #
  # Every message starts with a one-byte type and three reserved bytes that
  # must be zero. Indices and counters are little-endian. Handshake and cookie
  # messages have exact sizes; a transport message has a 16-byte header and at
  # least a 16-byte AEAD tag. `decode/1` runs on untrusted UDP payloads, so it
  # returns an error for every malformed input and never raises.

  alias Wagyu.Blake2s
  alias Wagyu.Packet.{CookieReply, Initiation, Response, Transport}

  @initiation 1
  @response 2
  @cookie_reply 3
  @transport 4

  @initiation_size 148
  @response_size 92
  @tag_size 16
  @mac_size 16

  # Counters at or above REJECT_AFTER_MESSAGES (2^64 - 2^13 - 1) are never
  # valid, so a frame carrying one is rejected before any crypto runs.
  @reject_after_messages 0xFFFFFFFFFFFFDFFF

  @mac1_label "mac1----"
  @types [@initiation, @response, @cookie_reply, @transport]

  @type message :: Initiation.t() | Response.t() | CookieReply.t() | Transport.t()
  @type decode_error :: :malformed | :invalid_length | :unknown_type | :invalid_reserved | :invalid_counter

  defguardp is_index(value) when is_integer(value) and value >= 0 and value <= 0xFFFFFFFF
  defguardp is_bytes(value, size) when is_binary(value) and byte_size(value) == size

  @doc """
  Decodes one UDP payload into a WireGuard message.

  Errors:

    * `:invalid_length` - shorter than the 4-byte header, the wrong size for a
      handshake or cookie message, or a transport message under 32 bytes
    * `:unknown_type` - a type other than 1 to 4
    * `:invalid_reserved` - a known type with nonzero reserved bytes
    * `:invalid_counter` - a transport counter at or above the reject limit
    * `:malformed` - not a binary
  """
  @spec decode(term()) :: {:ok, message()} | {:error, decode_error()}
  def decode(
        <<@initiation, 0, 0, 0, sender::little-32, ephemeral::binary-32, static::binary-48, timestamp::binary-28,
          mac1::binary-16, mac2::binary-16>>
      ) do
    {:ok,
     %Initiation{
       sender_index: sender,
       ephemeral: ephemeral,
       encrypted_static: static,
       encrypted_timestamp: timestamp,
       mac1: mac1,
       mac2: mac2
     }}
  end

  def decode(
        <<@response, 0, 0, 0, sender::little-32, receiver::little-32, ephemeral::binary-32, nothing::binary-16,
          mac1::binary-16, mac2::binary-16>>
      ) do
    {:ok,
     %Response{
       sender_index: sender,
       receiver_index: receiver,
       ephemeral: ephemeral,
       encrypted_nothing: nothing,
       mac1: mac1,
       mac2: mac2
     }}
  end

  def decode(<<@cookie_reply, 0, 0, 0, receiver::little-32, nonce::binary-24, cookie::binary-32>>) do
    {:ok, %CookieReply{receiver_index: receiver, nonce: nonce, encrypted_cookie: cookie}}
  end

  def decode(<<@transport, 0, 0, 0, receiver::little-32, counter::little-64, packet::binary>>)
      when byte_size(packet) >= @tag_size do
    if counter < @reject_after_messages do
      {:ok, %Transport{receiver_index: receiver, counter: counter, encrypted_packet: packet}}
    else
      {:error, :invalid_counter}
    end
  end

  def decode(<<type, 0, 0, 0, _rest::binary>>) when type in @types, do: {:error, :invalid_length}
  def decode(<<type, _reserved::binary-3, _rest::binary>>) when type in @types, do: {:error, :invalid_reserved}
  def decode(<<_type, _reserved::binary-3, _rest::binary>>), do: {:error, :unknown_type}
  def decode(datagram) when is_binary(datagram), do: {:error, :invalid_length}
  def decode(_datagram), do: {:error, :malformed}

  @doc """
  Encodes a message.

  Raises `ArgumentError` if a field has the wrong type or size, or if a
  transport counter is at or above the reject limit.
  """
  @spec encode(message()) :: binary()
  def encode(%Initiation{
        sender_index: sender,
        ephemeral: ephemeral,
        encrypted_static: static,
        encrypted_timestamp: timestamp,
        mac1: mac1,
        mac2: mac2
      })
      when is_index(sender) and is_bytes(ephemeral, 32) and is_bytes(static, 48) and is_bytes(timestamp, 28) and
             is_bytes(mac1, @mac_size) and is_bytes(mac2, @mac_size) do
    <<@initiation, 0, 0, 0, sender::little-32, ephemeral::binary, static::binary, timestamp::binary, mac1::binary,
      mac2::binary>>
  end

  def encode(%Response{
        sender_index: sender,
        receiver_index: receiver,
        ephemeral: ephemeral,
        encrypted_nothing: nothing,
        mac1: mac1,
        mac2: mac2
      })
      when is_index(sender) and is_index(receiver) and is_bytes(ephemeral, 32) and is_bytes(nothing, @tag_size) and
             is_bytes(mac1, @mac_size) and is_bytes(mac2, @mac_size) do
    <<@response, 0, 0, 0, sender::little-32, receiver::little-32, ephemeral::binary, nothing::binary, mac1::binary,
      mac2::binary>>
  end

  def encode(%CookieReply{receiver_index: receiver, nonce: nonce, encrypted_cookie: cookie})
      when is_index(receiver) and is_bytes(nonce, 24) and is_bytes(cookie, 32) do
    <<@cookie_reply, 0, 0, 0, receiver::little-32, nonce::binary, cookie::binary>>
  end

  def encode(%Transport{receiver_index: receiver, counter: counter, encrypted_packet: packet})
      when is_index(receiver) and is_integer(counter) and counter >= 0 and counter < @reject_after_messages and
             is_binary(packet) and byte_size(packet) >= @tag_size do
    <<@transport, 0, 0, 0, receiver::little-32, counter::little-64, packet::binary>>
  end

  def encode(message), do: raise(ArgumentError, "invalid WireGuard message: " <> inspect(message))

  @doc """
  Returns the MAC1 key for messages sent to the holder of `public_key`:
  BLAKE2s-256("mac1----" || public_key).

  Initiations are keyed with the responder's static public key and responses
  with the initiator's, so a receiver checks MAC1 with the key derived from its
  own public key.
  """
  @spec mac1_key(<<_::256>>) :: <<_::256>>
  def mac1_key(<<public_key::binary-32>>), do: Blake2s.hash(@mac1_label <> public_key)

  @doc """
  Fills in MAC1 on an encoded initiation or response and clears MAC2, as
  `put_macs/3` does without a cookie.
  """
  @spec put_mac1(binary(), <<_::256>>) :: binary()
  def put_mac1(frame, key), do: put_macs(frame, key, nil)

  @doc """
  Fills in MAC1 and MAC2 on an encoded initiation or response.

  MAC1 is keyed BLAKE2s-128 over every byte before the MAC1 field. MAC2 is
  keyed BLAKE2s-128 with `cookie` over every byte before the MAC2 field,
  MAC1 included, or zero without a cookie, which is what a sender that has
  none transmits.

  Raises `ArgumentError` for any other frame, a key that is not 32 bytes or
  a cookie that is neither nil nor 16 bytes.
  """
  @spec put_macs(binary(), <<_::256>>, <<_::128>> | nil) :: binary()
  def put_macs(frame, key, cookie) do
    with true <- is_bytes(key, 32) and (is_nil(cookie) or is_bytes(cookie, @mac_size)),
         {:ok, covered, _mac1, _mac2} <- split_macs(frame) do
      mac1 = mac(key, covered)
      mac2 = if cookie, do: mac(cookie, covered <> mac1), else: <<0::size(@mac_size * 8)>>
      <<covered::binary, mac1::binary, mac2::binary>>
    else
      _invalid -> raise ArgumentError, "MACs apply only to encoded initiation and response messages"
    end
  end

  @doc """
  Returns the MAC1 field of an initiation or response of the exact size, or
  `:error` for anything else.
  """
  @spec mac1(term()) :: {:ok, <<_::128>>} | :error
  def mac1(frame) do
    case split_macs(frame) do
      {:ok, _covered, mac1, _mac2} -> {:ok, mac1}
      :error -> :error
    end
  end

  @doc """
  Returns `true` when `frame` is an initiation or response of the exact size
  whose MAC1 matches `key`. Returns `false` for anything else and never raises.
  The comparison takes constant time.
  """
  @spec valid_mac1?(term(), term()) :: boolean()
  def valid_mac1?(frame, key) when is_bytes(key, 32) do
    case split_macs(frame) do
      {:ok, covered, mac1, _mac2} -> :crypto.hash_equals(mac(key, covered), mac1)
      :error -> false
    end
  end

  def valid_mac1?(_frame, _key), do: false

  @doc """
  Returns `true` when `frame` is an initiation or response of the exact size
  whose MAC2 was made with `cookie`, as `put_macs/3` makes it. Returns
  `false` for anything else and never raises. The comparison takes constant
  time.
  """
  @spec valid_mac2?(term(), term()) :: boolean()
  def valid_mac2?(frame, cookie) when is_bytes(cookie, @mac_size) do
    case split_macs(frame) do
      {:ok, covered, mac1, mac2} -> :crypto.hash_equals(mac(cookie, covered <> mac1), mac2)
      :error -> false
    end
  end

  def valid_mac2?(_frame, _cookie), do: false

  defp mac(key, covered), do: Blake2s.hash(covered, key, @mac_size)

  defp split_macs(<<@initiation, 0, 0, 0, _rest::binary>> = frame) when byte_size(frame) == @initiation_size,
    do: split_macs(frame, @initiation_size - 2 * @mac_size)

  defp split_macs(<<@response, 0, 0, 0, _rest::binary>> = frame) when byte_size(frame) == @response_size,
    do: split_macs(frame, @response_size - 2 * @mac_size)

  defp split_macs(_frame), do: :error

  defp split_macs(frame, covered_size) do
    <<covered::binary-size(^covered_size), mac1::binary-size(@mac_size), mac2::binary-size(@mac_size)>> = frame
    {:ok, covered, mac1, mac2}
  end
end
