defmodule Wagyu.IPTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias Wagyu.IP

  defp ipv4(options \\ []) do
    ihl = Keyword.get(options, :ihl, 5)
    payload = Keyword.get(options, :payload, "hello")
    options_bytes = :binary.copy(<<1>>, max(ihl - 5, 0) * 4)
    total_length = Keyword.get(options, :total_length, 20 + byte_size(options_bytes) + byte_size(payload))

    <<4::4, ihl::4, 0, total_length::16, 0::16, 0::16, 64, 17, 0::16, 10, 13, 0, 2, 10, 13, 0, 1, options_bytes::binary,
      payload::binary>>
  end

  defp ipv6(options \\ []) do
    payload = Keyword.get(options, :payload, "hello")
    payload_length = Keyword.get(options, :payload_length, byte_size(payload))

    <<6::4, 0::8, 0::20, payload_length::16, 17, 64, 0xFD00::16, 0::16, 0::16, 0::16, 0::16, 0::16, 0::16, 2::16,
      0xFD00::16, 0::16, 0::16, 0::16, 0::16, 0::16, 0::16, 1::16, payload::binary>>
  end

  describe "parse/1 with IPv4" do
    test "returns the addresses and the total length" do
      assert IP.parse(ipv4()) ==
               {:ok, %{version: 4, source: {10, 13, 0, 2}, destination: {10, 13, 0, 1}, length: 25}}
    end

    test "returns the length to trim padding to, whatever the padding holds" do
      packet = ipv4()

      for padding <- [<<0>>, :binary.copy(<<0>>, 7), :binary.copy(<<0xFF>>, 15), "not an ip header"] do
        assert {:ok, %{length: 25}} = IP.parse(packet <> padding)
      end
    end

    test "accepts header options and a header-only packet" do
      assert {:ok, %{length: 33}} = IP.parse(ipv4(ihl: 7, payload: "hello"))
      assert {:ok, %{length: 20}} = IP.parse(ipv4(payload: ""))
      assert {:ok, %{length: 60}} = IP.parse(ipv4(ihl: 15, payload: ""))
    end

    test "rejects a total length beyond the plaintext" do
      assert IP.parse(ipv4(total_length: 26)) == {:error, :length_exceeds_plaintext}
      assert IP.parse(ipv4(total_length: 65_535)) == {:error, :length_exceeds_plaintext}
    end

    test "rejects header lengths under 20 bytes or over the total length" do
      for ihl <- 0..4 do
        assert IP.parse(ipv4(ihl: ihl)) == {:error, :invalid_header_length}
      end

      assert IP.parse(ipv4(total_length: 19)) == {:error, :invalid_header_length}
      assert IP.parse(ipv4(total_length: 0)) == {:error, :invalid_header_length}
      assert IP.parse(ipv4(ihl: 6, payload: "", total_length: 20)) == {:error, :invalid_header_length}
    end

    test "rejects a packet shorter than the fixed header" do
      packet = ipv4(payload: "")

      for length <- 1..19 do
        assert IP.parse(binary_part(packet, 0, length)) == {:error, :truncated}
      end
    end
  end

  describe "parse/1 with IPv6" do
    test "returns the addresses and the header plus payload length" do
      assert IP.parse(ipv6()) ==
               {:ok,
                %{
                  version: 6,
                  source: {0xFD00, 0, 0, 0, 0, 0, 0, 2},
                  destination: {0xFD00, 0, 0, 0, 0, 0, 0, 1},
                  length: 45
                }}
    end

    test "returns the length to trim padding to" do
      assert {:ok, %{length: 45}} = IP.parse(ipv6() <> :binary.copy(<<0xAA>>, 11))
      assert {:ok, %{length: 40}} = IP.parse(ipv6(payload: "") <> <<1, 2, 3>>)
    end

    test "rejects a payload length beyond the plaintext" do
      assert IP.parse(ipv6(payload_length: 6)) == {:error, :length_exceeds_plaintext}
      assert IP.parse(ipv6(payload_length: 65_535)) == {:error, :length_exceeds_plaintext}
    end

    test "rejects a packet shorter than the fixed header" do
      packet = ipv6(payload: "")

      for length <- 1..39 do
        assert IP.parse(binary_part(packet, 0, length)) == {:error, :truncated}
      end
    end
  end

  test "rejects other IP versions" do
    for version <- [0, 1, 5, 7, 15] do
      <<_version::4, rest::bitstring>> = ipv4()
      assert IP.parse(<<version::4, rest::bitstring>>) == {:error, :invalid_version}
    end
  end

  test "rejects empty plaintext, which is a keepalive rather than a packet" do
    assert IP.parse(<<>>) == {:error, :truncated}
  end

  test "never raises on arbitrary input" do
    for version <- [4, 6, 9], length <- 1..120, _trial <- 1..3 do
      <<_version::4, rest::bitstring>> = :crypto.strong_rand_bytes(length)

      case IP.parse(<<version::4, rest::bitstring>>) do
        {:ok, %{length: parsed}} -> assert parsed <= length
        {:error, reason} -> assert is_atom(reason)
      end
    end

    assert IP.parse(nil) == {:error, :truncated}
  end

  describe "address conversion" do
    test "round-trips IPv4 and IPv6 addresses" do
      for {address, value, bits} <- [
            {{0, 0, 0, 0}, 0, 32},
            {{10, 13, 0, 2}, 0x0A0D0002, 32},
            {{255, 255, 255, 255}, 0xFFFFFFFF, 32},
            {{0xFD00, 0, 0, 0, 0, 0, 0, 1}, 0xFD00 <<< 112 ||| 1, 128},
            {{0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF}, (1 <<< 128) - 1, 128}
          ] do
        assert IP.to_integer(address) == {:ok, value, bits}
        assert IP.from_integer(value, bits) == address
      end
    end

    test "rejects anything that is not an address tuple" do
      for address <- [{256, 0, 0, 0}, {-1, 0, 0, 0}, {1, 2, 3}, {0, 0, 0, 0, 0, 0, 0, 0x10000}, "10.0.0.1", nil] do
        assert IP.to_integer(address) == :error
      end
    end
  end
end
