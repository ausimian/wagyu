defmodule Wagyu.XChaCha20Poly1305 do
  @moduledoc false

  # XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha), which encrypts WireGuard's
  # cookie replies.
  #
  # OTP's `:crypto` has ChaCha20-Poly1305 with a 12-byte nonce but no
  # XChaCha, so Wagyu derives XChaCha's subkey itself: HChaCha20 of the key
  # and the first 16 bytes of the 24-byte nonce. The subkey then encrypts
  # with `:crypto`'s ChaCha20-Poly1305 under four zero bytes and the
  # nonce's last 8 bytes. HChaCha20 is one ChaCha20 block without the final
  # addition, so it is a fixed, small amount of work.

  import Bitwise

  @mask 0xFFFFFFFF
  @tag_size 16

  # "expand 32-byte k"
  @constants {0x61707865, 0x3320646E, 0x79622D32, 0x6B206574}

  @doc """
  Encrypts `plaintext` under `key` and a 24-byte `nonce`, authenticating
  `aad` too. Returns the ciphertext followed by its 16-byte tag.
  """
  @spec seal(<<_::256>>, <<_::192>>, iodata(), iodata()) :: binary()
  def seal(<<_::binary-32>> = key, <<_::binary-24>> = nonce, plaintext, aad) do
    {subkey, chacha_nonce} = subkey(key, nonce)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:chacha20_poly1305, subkey, chacha_nonce, plaintext, aad, true)
    ciphertext <> tag
  end

  @doc """
  Decrypts a ciphertext and tag from `seal/4`. Returns `{:ok, plaintext}`, or
  `:error` when it does not authenticate under `key`, `nonce` and `aad`.
  Never raises for a ciphertext of any size.
  """
  @spec open(<<_::256>>, <<_::192>>, binary(), iodata()) :: {:ok, binary()} | :error
  def open(<<_::binary-32>> = key, <<_::binary-24>> = nonce, sealed, aad)
      when is_binary(sealed) and byte_size(sealed) >= @tag_size do
    size = byte_size(sealed) - @tag_size
    <<ciphertext::binary-size(^size), tag::binary-size(@tag_size)>> = sealed
    {subkey, chacha_nonce} = subkey(key, nonce)

    case :crypto.crypto_one_time_aead(:chacha20_poly1305, subkey, chacha_nonce, ciphertext, aad, tag, false) do
      plaintext when is_binary(plaintext) -> {:ok, plaintext}
      :error -> :error
    end
  end

  def open(_key, _nonce, _sealed, _aad), do: :error

  defp subkey(key, <<prefix::binary-16, suffix::binary-8>>), do: {hchacha20(key, prefix), <<0::32, suffix::binary>>}

  @doc """
  HChaCha20 (draft-irtf-cfrg-xchacha section 2.2): the 32-byte subkey for
  `key` and a 16-byte `nonce`.
  """
  @spec hchacha20(<<_::256>>, <<_::128>>) :: <<_::256>>
  def hchacha20(
        <<k0::little-32, k1::little-32, k2::little-32, k3::little-32, k4::little-32, k5::little-32, k6::little-32,
          k7::little-32>>,
        <<n0::little-32, n1::little-32, n2::little-32, n3::little-32>>
      ) do
    {c0, c1, c2, c3} = @constants
    state = {c0, c1, c2, c3, k0, k1, k2, k3, k4, k5, k6, k7, n0, n1, n2, n3}

    {x0, x1, x2, x3, _x4, _x5, _x6, _x7, _x8, _x9, _x10, _x11, x12, x13, x14, x15} =
      Enum.reduce(1..10, state, fn _round, state -> double_round(state) end)

    <<x0::little-32, x1::little-32, x2::little-32, x3::little-32, x12::little-32, x13::little-32, x14::little-32,
      x15::little-32>>
  end

  # Four column quarter rounds, then four diagonal ones.
  defp double_round({x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15}) do
    {x0, x4, x8, x12} = quarter_round(x0, x4, x8, x12)
    {x1, x5, x9, x13} = quarter_round(x1, x5, x9, x13)
    {x2, x6, x10, x14} = quarter_round(x2, x6, x10, x14)
    {x3, x7, x11, x15} = quarter_round(x3, x7, x11, x15)
    {x0, x5, x10, x15} = quarter_round(x0, x5, x10, x15)
    {x1, x6, x11, x12} = quarter_round(x1, x6, x11, x12)
    {x2, x7, x8, x13} = quarter_round(x2, x7, x8, x13)
    {x3, x4, x9, x14} = quarter_round(x3, x4, x9, x14)
    {x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15}
  end

  defp quarter_round(a, b, c, d) do
    a = a + b &&& @mask
    d = rotl(bxor(d, a), 16)
    c = c + d &&& @mask
    b = rotl(bxor(b, c), 12)
    a = a + b &&& @mask
    d = rotl(bxor(d, a), 8)
    c = c + d &&& @mask
    b = rotl(bxor(b, c), 7)
    {a, b, c, d}
  end

  defp rotl(word, bits), do: (word <<< bits ||| word >>> (32 - bits)) &&& @mask
end
