defmodule Wagyu.Blake2s do
  @moduledoc false

  # BLAKE2s (RFC 7693) with optional key and variable digest size.
  #
  # OTP's `:crypto` exposes only unkeyed BLAKE2s-256, but WireGuard's MAC1 and
  # MAC2 are keyed BLAKE2s with a 16-byte digest, so Wagyu carries its own
  # implementation. It is sequential and allocation-light rather than fast; the
  # inputs it sees are single handshake messages of at most a few blocks.

  import Bitwise

  @mask 0xFFFFFFFF
  @block_size 64

  @iv {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19}

  @sigma [
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
  ]

  @doc """
  Hashes `data` with BLAKE2s.

  `key` may be empty (unkeyed) or up to 32 bytes. `size` is the digest length
  in bytes, from 1 to 32. The digest size and key length are part of the
  parameter block, so a 16-byte digest is not a prefix of the 32-byte one.

  Raises `FunctionClauseError` for a key longer than 32 bytes or a size outside
  `1..32`.
  """
  @spec hash(binary(), binary(), 1..32) :: binary()
  def hash(data, key \\ <<>>, size \\ 32)
      when is_binary(data) and is_binary(key) and byte_size(key) <= 32 and is_integer(size) and size >= 1 and
             size <= 32 do
    {iv0, iv1, iv2, iv3, iv4, iv5, iv6, iv7} = @iv
    h0 = iv0 |> bxor(0x01010000) |> bxor(byte_size(key) <<< 8) |> bxor(size)
    state = {h0, iv1, iv2, iv3, iv4, iv5, iv6, iv7}

    input =
      case key do
        <<>> -> data
        key -> <<key::binary, 0::size((@block_size - byte_size(key)) * 8), data::binary>>
      end

    <<digest::binary-size(^size), _rest::binary>> = blocks(state, input, 0)
    digest
  end

  # Every block but the last is compressed with the running byte count. The
  # last block, which may be empty, is zero-padded and carries the final flag.
  defp blocks(state, <<block::binary-size(@block_size), rest::binary>>, count) when rest != <<>> do
    count = count + @block_size
    blocks(compress(state, block, count, false), rest, count)
  end

  defp blocks(state, last, count) do
    length = byte_size(last)
    block = <<last::binary, 0::size((@block_size - length) * 8)>>

    {h0, h1, h2, h3, h4, h5, h6, h7} = compress(state, block, count + length, true)

    <<h0::little-32, h1::little-32, h2::little-32, h3::little-32, h4::little-32, h5::little-32, h6::little-32,
      h7::little-32>>
  end

  defp compress({h0, h1, h2, h3, h4, h5, h6, h7}, block, count, final?) do
    <<m0::little-32, m1::little-32, m2::little-32, m3::little-32, m4::little-32, m5::little-32, m6::little-32,
      m7::little-32, m8::little-32, m9::little-32, m10::little-32, m11::little-32, m12::little-32, m13::little-32,
      m14::little-32, m15::little-32>> = block

    message = {m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15}
    {iv0, iv1, iv2, iv3, iv4, iv5, iv6, iv7} = @iv
    v14 = if final?, do: bxor(iv6, @mask), else: iv6

    work =
      {h0, h1, h2, h3, h4, h5, h6, h7, iv0, iv1, iv2, iv3, bxor(iv4, count &&& @mask),
       bxor(iv5, count >>> 32 &&& @mask), v14, iv7}

    {v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15} =
      Enum.reduce(@sigma, work, fn schedule, work -> mix(work, message, schedule) end)

    {h0 |> bxor(v0) |> bxor(v8), h1 |> bxor(v1) |> bxor(v9), h2 |> bxor(v2) |> bxor(v10), h3 |> bxor(v3) |> bxor(v11),
     h4 |> bxor(v4) |> bxor(v12), h5 |> bxor(v5) |> bxor(v13), h6 |> bxor(v6) |> bxor(v14), h7 |> bxor(v7) |> bxor(v15)}
  end

  # One round: four column mixes, then four diagonal mixes.
  defp mix(
         {v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15},
         m,
         {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15}
       ) do
    {v0, v4, v8, v12} = g(v0, v4, v8, v12, elem(m, s0), elem(m, s1))
    {v1, v5, v9, v13} = g(v1, v5, v9, v13, elem(m, s2), elem(m, s3))
    {v2, v6, v10, v14} = g(v2, v6, v10, v14, elem(m, s4), elem(m, s5))
    {v3, v7, v11, v15} = g(v3, v7, v11, v15, elem(m, s6), elem(m, s7))
    {v0, v5, v10, v15} = g(v0, v5, v10, v15, elem(m, s8), elem(m, s9))
    {v1, v6, v11, v12} = g(v1, v6, v11, v12, elem(m, s10), elem(m, s11))
    {v2, v7, v8, v13} = g(v2, v7, v8, v13, elem(m, s12), elem(m, s13))
    {v3, v4, v9, v14} = g(v3, v4, v9, v14, elem(m, s14), elem(m, s15))
    {v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15}
  end

  defp g(a, b, c, d, x, y) do
    a = a + b + x &&& @mask
    d = rotr(bxor(d, a), 16)
    c = c + d &&& @mask
    b = rotr(bxor(b, c), 12)
    a = a + b + y &&& @mask
    d = rotr(bxor(d, a), 8)
    c = c + d &&& @mask
    b = rotr(bxor(b, c), 7)
    {a, b, c, d}
  end

  defp rotr(word, bits), do: (word >>> bits ||| word <<< (32 - bits)) &&& @mask
end
