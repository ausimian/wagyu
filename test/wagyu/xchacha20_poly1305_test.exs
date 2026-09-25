defmodule Wagyu.XChaCha20Poly1305Test do
  use ExUnit.Case, async: true

  alias Wagyu.XChaCha20Poly1305

  defp hex(string), do: string |> String.replace(~r/\s/, "") |> Base.decode16!(case: :lower)

  # draft-irtf-cfrg-xchacha-03, section 2.2.1.
  test "HChaCha20 matches the draft's test vector" do
    key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    nonce = hex("000000090000004a0000000031415927")

    assert XChaCha20Poly1305.hchacha20(key, nonce) ==
             hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
  end

  describe "AEAD_XChaCha20_Poly1305" do
    # draft-irtf-cfrg-xchacha-03, appendix A.3.1.
    setup do
      %{
        key: hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        nonce: hex("404142434445464748494a4b4c4d4e4f5051525354555657"),
        aad: hex("50515253c0c1c2c3c4c5c6c7"),
        plaintext:
          "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, " <>
            "sunscreen would be it.",
        sealed:
          hex("""
          bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39
          ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
          21f9664c97637da9768812f615c68b13b52e
          c0875924c1c7987947deafd8780acf49
          """)
      }
    end

    test "seals and opens the draft's test vector", vector do
      assert XChaCha20Poly1305.seal(vector.key, vector.nonce, vector.plaintext, vector.aad) == vector.sealed
      assert XChaCha20Poly1305.open(vector.key, vector.nonce, vector.sealed, vector.aad) == {:ok, vector.plaintext}
    end

    test "refuses a changed ciphertext, tag, nonce, key or associated data", vector do
      flip = fn <<first, rest::binary>> -> <<Bitwise.bxor(first, 1), rest::binary>> end
      size = byte_size(vector.sealed) - 16
      <<ciphertext::binary-size(^size), tag::binary-16>> = vector.sealed

      for {key, nonce, sealed, aad} <- [
            {vector.key, vector.nonce, flip.(ciphertext) <> tag, vector.aad},
            {vector.key, vector.nonce, ciphertext <> flip.(tag), vector.aad},
            {vector.key, flip.(vector.nonce), vector.sealed, vector.aad},
            {flip.(vector.key), vector.nonce, vector.sealed, vector.aad},
            {vector.key, vector.nonce, vector.sealed, flip.(vector.aad)}
          ] do
        assert XChaCha20Poly1305.open(key, nonce, sealed, aad) == :error
      end
    end

    test "refuses, without raising, a ciphertext shorter than a tag or a malformed key or nonce", vector do
      assert XChaCha20Poly1305.open(vector.key, vector.nonce, binary_part(vector.sealed, 0, 15), vector.aad) == :error
      assert XChaCha20Poly1305.open(vector.key, <<0::128>>, vector.sealed, vector.aad) == :error
      assert XChaCha20Poly1305.open(<<0::128>>, vector.nonce, vector.sealed, vector.aad) == :error
      assert XChaCha20Poly1305.open(vector.key, vector.nonce, nil, vector.aad) == :error
    end
  end
end
