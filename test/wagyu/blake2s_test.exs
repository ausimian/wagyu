defmodule Wagyu.Blake2sTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias Wagyu.Blake2s

  @kat_key :binary.list_to_bin(Enum.to_list(0..31))
  @kat_input :binary.list_to_bin(Enum.to_list(0..255))

  defp vectors(file) do
    Path.join([__DIR__, "..", "fixtures", file])
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.reject(&String.starts_with?(&1, "#"))
    |> Enum.map(&Base.decode16!(&1, case: :lower))
  end

  describe "RFC 7693" do
    test "Appendix B: BLAKE2s-256 of \"abc\"" do
      assert Blake2s.hash("abc") ==
               Base.decode16!("508C5E8C327C14E2E1A72BA34EEB452F37458B209ED63A294D999B4C86675982")
    end

    # The RFC's self-test hashes unkeyed and keyed digests of 16, 20, 28 and
    # 32 bytes over inputs of 0, 3, 64, 65, 255 and 1024 bytes, then checks a
    # BLAKE2s-256 of all of them.
    test "Appendix E: self-test grand hash over keyed and unkeyed digests" do
      digests =
        for outlen <- [16, 20, 28, 32], inlen <- [0, 3, 64, 65, 255, 1024] do
          input = selftest_seq(inlen, inlen)
          key = selftest_seq(outlen, outlen)
          Blake2s.hash(input, <<>>, outlen) <> Blake2s.hash(input, key, outlen)
        end

      assert Blake2s.hash(IO.iodata_to_binary(digests)) ==
               Base.decode16!("6A411F08CE25ADCDFB02ABA641451CEC53C598B24F4FC787FBDC88797F4C1DFE")
    end
  end

  describe "reference known-answer vectors" do
    test "keyed BLAKE2s-256 matches every blake2s-kat.txt entry" do
      expected = vectors("blake2s_keyed_256.txt")
      assert length(expected) == 256

      for {digest, length} <- Enum.with_index(expected) do
        assert Blake2s.hash(binary_part(@kat_input, 0, length), @kat_key) == digest, "input length #{length}"
      end
    end

    test "keyed BLAKE2s-128 matches independent vectors at WireGuard's MAC size" do
      expected = vectors("blake2s_keyed_128.txt")
      assert length(expected) == 256

      for {digest, length} <- Enum.with_index(expected) do
        assert Blake2s.hash(binary_part(@kat_input, 0, length), @kat_key, 16) == digest, "input length #{length}"
      end
    end
  end

  test "unkeyed BLAKE2s-256 agrees with :crypto across block boundaries" do
    for length <- Enum.to_list(0..200) ++ [255, 256, 257, 1023, 1024, 1025] do
      input = :crypto.strong_rand_bytes(length)
      assert Blake2s.hash(input) == :crypto.hash(:blake2s, input), "input length #{length}"
    end
  end

  test "digest size and key length are parameters, not truncation" do
    input = "WireGuard"

    assert byte_size(Blake2s.hash(input, <<>>, 16)) == 16
    refute Blake2s.hash(input, <<>>, 16) == binary_part(Blake2s.hash(input), 0, 16)
    refute Blake2s.hash(input, <<1>>) == Blake2s.hash(input, <<1, 0>>)
  end

  test "rejects keys over 32 bytes and sizes outside 1..32" do
    assert_raise FunctionClauseError, fn -> Blake2s.hash("", :binary.copy(<<0>>, 33)) end
    assert_raise FunctionClauseError, fn -> Blake2s.hash("", <<>>, 0) end
    assert_raise FunctionClauseError, fn -> Blake2s.hash("", <<>>, 33) end
  end

  # RFC 7693 Appendix E: a Fibonacci generator for deterministic test input.
  defp selftest_seq(length, seed) do
    {bytes, _a, _b} =
      Enum.reduce(1..length//1, {[], 0xDEAD4BAD * seed &&& 0xFFFFFFFF, 1}, fn _index, {bytes, a, b} ->
        t = a + b &&& 0xFFFFFFFF
        {[t >>> 24 | bytes], b, t}
      end)

    bytes |> Enum.reverse() |> :binary.list_to_bin()
  end
end
