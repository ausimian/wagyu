defmodule Wagyu.IP do
  @moduledoc false

  # Validation of the IP packet inside decrypted transport plaintext.
  #
  # Senders pad plaintext to a multiple of 16 bytes, so the IP length comes
  # from the header: the IPv4 total length, or the IPv6 payload length plus the
  # 40-byte fixed header. A packet claiming more bytes than the plaintext holds
  # is dropped; otherwise the caller trims the plaintext to that length. Like
  # wireguard-go and Linux, the padding bytes themselves are not inspected.
  #
  # The IPv4 header checksum is not verified here; the network stack checks it
  # on ingress.

  @ipv4_header_size 20
  @ipv6_header_size 40

  defguardp is_octet(value) when is_integer(value) and value >= 0 and value <= 0xFF
  defguardp is_hextet(value) when is_integer(value) and value >= 0 and value <= 0xFFFF

  @type info :: %{
          version: 4 | 6,
          source: :inet.ip_address(),
          destination: :inet.ip_address(),
          length: pos_integer()
        }

  @type error :: :truncated | :invalid_version | :invalid_header_length | :length_exceeds_plaintext

  @doc """
  Parses the IP header at the start of `plaintext`.

  On success returns the IP version, source and destination addresses, and
  `length`, the exact number of bytes to keep from `plaintext`.

  Errors:

    * `:truncated` - shorter than the fixed IPv4 (20-byte) or IPv6 (40-byte)
      header, including empty plaintext
    * `:invalid_version` - neither IPv4 nor IPv6
    * `:invalid_header_length` - an IPv4 header length under 20 bytes or
      greater than the total length
    * `:length_exceeds_plaintext` - the IP length is greater than the
      plaintext

  Never raises.
  """
  @spec parse(term()) :: {:ok, info()} | {:error, error()}
  def parse(
        <<4::4, ihl::4, _tos, total_length::16, _id_flags_ttl_protocol_checksum::binary-8, s1, s2, s3, s4, d1, d2, d3,
          d4, _rest::binary>> = plaintext
      ) do
    cond do
      ihl * 4 < @ipv4_header_size or ihl * 4 > total_length -> {:error, :invalid_header_length}
      total_length > byte_size(plaintext) -> {:error, :length_exceeds_plaintext}
      true -> {:ok, %{version: 4, source: {s1, s2, s3, s4}, destination: {d1, d2, d3, d4}, length: total_length}}
    end
  end

  def parse(
        <<6::4, _traffic_class_flow_label::28, payload_length::16, _next_header, _hop_limit, source::binary-16,
          destination::binary-16, _rest::binary>> = plaintext
      ) do
    length = @ipv6_header_size + payload_length

    if length > byte_size(plaintext) do
      {:error, :length_exceeds_plaintext}
    else
      {:ok, %{version: 6, source: ipv6(source), destination: ipv6(destination), length: length}}
    end
  end

  def parse(<<version::4, _rest::bitstring>>) when version in [4, 6], do: {:error, :truncated}
  def parse(<<_version::4, _rest::bitstring>>), do: {:error, :invalid_version}
  def parse(_plaintext), do: {:error, :truncated}

  @doc """
  Converts an address tuple to `{:ok, integer, bits}`, where `bits` is 32 for
  IPv4 and 128 for IPv6. Returns `:error` for anything that is not a valid
  address tuple.
  """
  @spec to_integer(term()) :: {:ok, non_neg_integer(), 32 | 128} | :error
  def to_integer({a, b, c, d}) when is_octet(a) and is_octet(b) and is_octet(c) and is_octet(d) do
    <<value::32>> = <<a, b, c, d>>
    {:ok, value, 32}
  end

  def to_integer({a, b, c, d, e, f, g, h})
      when is_hextet(a) and is_hextet(b) and is_hextet(c) and is_hextet(d) and is_hextet(e) and is_hextet(f) and
             is_hextet(g) and is_hextet(h) do
    <<value::128>> = <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
    {:ok, value, 128}
  end

  def to_integer(_address), do: :error

  @doc "Converts a 32-bit or 128-bit integer back to an address tuple."
  @spec from_integer(non_neg_integer(), 32 | 128) :: :inet.ip_address()
  def from_integer(value, 32) do
    <<a, b, c, d>> = <<value::32>>
    {a, b, c, d}
  end

  def from_integer(value, 128), do: ipv6(<<value::128>>)

  defp ipv6(<<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>), do: {a, b, c, d, e, f, g, h}
end
