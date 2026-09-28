defmodule Wagyu.PacketTest do
  use ExUnit.Case, async: true

  alias Wagyu.Packet
  alias Wagyu.Packet.{CookieReply, Initiation, Response, Transport}

  # REJECT_AFTER_MESSAGES: 2^64 - 2^13 - 1.
  @reject_after_messages 18_446_744_073_709_543_423

  # A real handshake captured from wireguard-go
  # (golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446, Go 1.26.0,
  # tun/netstack over loopback). The initiator's private key is 10 11 .. 2f
  # and the responder's is 40 41 .. 5f. The initiator sent the first message;
  # a second wireguard-go device holding the responder key answered it.
  @initiator_public Base.decode16!("d89e3bad79437dbed9f843418304f460ff05c7fe81fe4a9577a804cb9367ff66", case: :lower)
  @responder_public Base.decode16!("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a", case: :lower)
  @captured_initiation Base.decode16!(
                         "01000000a3bee0f810d63fdb05cef1b924bd4fd7f00ca2c3140bb1d587fb199980606329e90c031761c0bf3e4" <>
                           "173f50273d8f37b4e13f23fa53858cf102916d2827ea9e362c8603125ff062d67d7e7bf1e3eee445f5494d34d4" <>
                           "0e91513661d406b7a0d842e3b76b3a7db1988ebd9cd4eac53d0f8386d9d9b3b2aea882a1e502180542879000" <>
                           "00000000000000000000000000000",
                         case: :lower
                       )
  @captured_response Base.decode16!(
                       "0200000099db6ea6a3bee0f8d95114bacc0a50d73681771072ca5665ac0e942eeb735e581c2596cd1d583d06" <>
                         "96b97ae49592edbaff0b737f73a8de2d70e99c20685f3f4b85c92b9e1e30cad1000000000000000000000000" <>
                         "00000000",
                       case: :lower
                     )

  defp bytes(size), do: :crypto.strong_rand_bytes(size)

  defp initiation do
    %Initiation{
      sender_index: 0x01020304,
      ephemeral: bytes(32),
      encrypted_static: bytes(48),
      encrypted_timestamp: bytes(28),
      mac1: bytes(16),
      mac2: bytes(16)
    }
  end

  defp response do
    %Response{
      sender_index: 0xFFFFFFFF,
      receiver_index: 0,
      ephemeral: bytes(32),
      encrypted_nothing: bytes(16),
      mac1: bytes(16),
      mac2: bytes(16)
    }
  end

  defp cookie_reply, do: %CookieReply{receiver_index: 7, nonce: bytes(24), encrypted_cookie: bytes(32)}

  defp transport(size, counter \\ 1), do: %Transport{receiver_index: 9, counter: counter, encrypted_packet: bytes(size)}

  describe "exact frames" do
    test "round-trip at their legal sizes" do
      for {message, size} <- [
            {initiation(), 148},
            {response(), 92},
            {cookie_reply(), 64},
            {transport(16), 32},
            {transport(17), 33},
            {transport(1436), 1452},
            {transport(16, 0), 32},
            {transport(16, @reject_after_messages - 1), 32}
          ] do
        frame = Packet.encode(message)
        assert byte_size(frame) == size
        assert Packet.decode(frame) == {:ok, message}
      end
    end

    test "use a little-endian type word and little-endian indices and counters" do
      frame =
        Packet.encode(%Transport{receiver_index: 0x0A0B0C0D, counter: 0x0102030405060708, encrypted_packet: <<0::128>>})

      assert <<4, 0, 0, 0, 0x0D, 0x0C, 0x0B, 0x0A, 8, 7, 6, 5, 4, 3, 2, 1, 0::128>> = frame
    end

    test "decode the captured wireguard-go handshake" do
      assert {:ok, %Initiation{sender_index: sender, mac2: <<0::128>>}} = Packet.decode(@captured_initiation)
      assert {:ok, %Response{receiver_index: ^sender, mac2: <<0::128>>}} = Packet.decode(@captured_response)
      assert sender == 0xF8E0BEA3
    end
  end

  describe "decode/1 fails closed" do
    test "on frames shorter than the header" do
      for frame <- [<<>>, <<1>>, <<4, 0, 0>>] do
        assert Packet.decode(frame) == {:error, :invalid_length}
      end
    end

    test "on truncated or oversized fixed frames" do
      for {type, size} <- [{1, 148}, {2, 92}, {3, 64}], length <- [4, size - 1, size + 1, 2 * size] do
        frame = <<type, 0, 0, 0>> <> bytes(length - 4)
        assert Packet.decode(frame) == {:error, :invalid_length}, "type #{type}, #{length} bytes"
      end
    end

    test "on transport frames under 32 bytes" do
      for length <- [4, 8, 16, 31] do
        assert Packet.decode(<<4, 0, 0, 0>> <> bytes(length - 4)) == {:error, :invalid_length}
      end
    end

    test "on unknown types" do
      for type <- [0, 5, 6, 0x80, 0xFF], length <- [4, 32, 64, 92, 148] do
        assert Packet.decode(<<type, 0, 0, 0>> <> bytes(length - 4)) == {:error, :unknown_type}
      end
    end

    test "on nonzero reserved bytes" do
      frames = [Packet.encode(initiation()), Packet.encode(response()), Packet.encode(cookie_reply())]

      for <<type, _reserved::binary-3, rest::binary>> <- frames ++ [Packet.encode(transport(16))],
          reserved <- [<<1, 0, 0>>, <<0, 1, 0>>, <<0, 0, 1>>, <<0xFF, 0xFF, 0xFF>>] do
        assert Packet.decode(<<type, reserved::binary, rest::binary>>) == {:error, :invalid_reserved}
      end
    end

    test "on transport counters at or above the reject limit" do
      for counter <- [@reject_after_messages, @reject_after_messages + 1, 0xFFFFFFFFFFFFFFFF] do
        frame = <<4, 0, 0, 0, 9::little-32, counter::little-64>> <> bytes(16)
        assert Packet.decode(frame) == {:error, :invalid_counter}
      end
    end

    test "on non-binary input" do
      for input <- [nil, ~c"abc", <<1::7>>, {:udp, <<>>}, 148] do
        assert Packet.decode(input) == {:error, :malformed}
      end
    end

    test "without raising for arbitrary datagrams" do
      for type <- 0..5, reserved <- [<<0, 0, 0>>, <<0, 0, 1>>], length <- 4..200, _trial <- 1..2 do
        frame = <<type, reserved::binary>> <> bytes(length - 4)

        assert match?({:ok, _message}, Packet.decode(frame)) or
                 match?({:error, reason} when is_atom(reason), Packet.decode(frame))
      end
    end
  end

  describe "encode/1" do
    test "rejects fields of the wrong size or range" do
      invalid = [
        %{initiation() | sender_index: -1},
        %{initiation() | sender_index: 0x100000000},
        %{initiation() | ephemeral: bytes(31)},
        %{initiation() | encrypted_static: bytes(49)},
        %{initiation() | mac2: nil},
        %{response() | receiver_index: :index},
        %{response() | encrypted_nothing: bytes(15)},
        %{cookie_reply() | nonce: bytes(12)},
        transport(15),
        transport(16, -1),
        transport(16, @reject_after_messages),
        :not_a_message
      ]

      for message <- invalid do
        assert_raise ArgumentError, fn -> Packet.encode(message) end
      end
    end
  end

  describe "encode_transport/3" do
    test "frames an iodata packet as encode/1 frames it flattened" do
      packet = bytes(1240)
      <<a::binary-7, b::binary-600, c::binary>> = packet

      for iodata <- [packet, [a, b, c], [[a], ?x | [binary_part(b, 1, 599), c]]] do
        flat = IO.iodata_to_binary(iodata)
        message = %Transport{receiver_index: 9, counter: 5, encrypted_packet: flat}
        assert Packet.encode_transport(9, 5, iodata) == Packet.encode(message)
      end
    end

    test "rejects fields of the wrong size or range" do
      invalid = [
        {-1, 1, bytes(16)},
        {0x100000000, 1, bytes(16)},
        {9, -1, bytes(16)},
        {9, @reject_after_messages, bytes(16)},
        {9, 1, bytes(15)},
        {9, 1, [bytes(8), bytes(7)]},
        {9, 1, [:not_iodata, bytes(16)]},
        {9, 1, nil}
      ]

      for {receiver, counter, packet} <- invalid do
        assert_raise ArgumentError, fn -> Packet.encode_transport(receiver, counter, packet) end
      end
    end
  end

  describe "MAC1" do
    test "keys are BLAKE2s-256 of the label and public key" do
      assert Packet.mac1_key(@responder_public) == :crypto.hash(:blake2s, "mac1----" <> @responder_public)
    end

    test "matches the captured wireguard-go initiation and response" do
      assert Packet.valid_mac1?(@captured_initiation, Packet.mac1_key(@responder_public))
      assert Packet.valid_mac1?(@captured_response, Packet.mac1_key(@initiator_public))

      # Each message is keyed with the receiver's public key, not the sender's.
      refute Packet.valid_mac1?(@captured_initiation, Packet.mac1_key(@initiator_public))
      refute Packet.valid_mac1?(@captured_response, Packet.mac1_key(@responder_public))
    end

    test "put_mac1/2 reproduces the captured MAC1 bytes" do
      for {frame, public_key} <- [{@captured_initiation, @responder_public}, {@captured_response, @initiator_public}] do
        covered_size = byte_size(frame) - 32
        <<covered::binary-size(^covered_size), _macs::binary>> = frame

        assert Packet.put_mac1(<<covered::binary, bytes(32)::binary>>, Packet.mac1_key(public_key)) == frame
      end
    end

    test "detects a change to any covered byte but ignores MAC2" do
      key = Packet.mac1_key(@responder_public)

      for offset <- 0..115 do
        <<before::binary-size(^offset), byte, rest::binary>> = @captured_initiation
        refute Packet.valid_mac1?(<<before::binary, Bitwise.bxor(byte, 1), rest::binary>>, key), "offset #{offset}"
      end

      <<covered_and_mac1::binary-132, _mac2::binary-16>> = @captured_initiation
      assert Packet.valid_mac1?(covered_and_mac1 <> bytes(16), key)
    end

    test "valid_mac1?/2 is false for anything but a full handshake frame and a 32-byte key" do
      key = Packet.mac1_key(@responder_public)

      for frame <- [
            binary_part(@captured_initiation, 0, 147),
            @captured_initiation <> <<0>>,
            Packet.encode(cookie_reply()),
            Packet.encode(transport(116)),
            <<1, 0, 0, 1>> <> binary_part(@captured_initiation, 4, 144),
            nil
          ] do
        refute Packet.valid_mac1?(frame, key)
      end

      refute Packet.valid_mac1?(@captured_initiation, binary_part(key, 0, 16))
      refute Packet.valid_mac1?(@captured_initiation, nil)
    end

    test "put_mac1/2 rejects other frames and bad keys" do
      key = Packet.mac1_key(@responder_public)

      assert_raise ArgumentError, fn -> Packet.put_mac1(Packet.encode(transport(116)), key) end
      assert_raise ArgumentError, fn -> Packet.put_mac1(Packet.encode(cookie_reply()), key) end
      assert_raise ArgumentError, fn -> Packet.put_mac1(@captured_initiation, <<0::128>>) end
    end
  end

  describe "MAC2" do
    test "is keyed BLAKE2s-128 with the cookie over every byte before it, MAC1 included" do
      key = Packet.mac1_key(@responder_public)
      cookie = bytes(16)

      for frame <- [@captured_initiation, @captured_response] do
        mac1_key = if frame == @captured_initiation, do: key, else: Packet.mac1_key(@initiator_public)
        with_mac2 = Packet.put_macs(frame, mac1_key, cookie)
        size = byte_size(frame) - 16
        <<covered::binary-size(^size), mac2::binary-16>> = with_mac2

        # MAC1 is unchanged, and MAC2 covers it.
        assert covered == binary_part(frame, 0, size)
        assert mac2 == Wagyu.Blake2s.hash(covered, cookie, 16)
        assert Packet.valid_mac1?(with_mac2, mac1_key)
        assert Packet.valid_mac2?(with_mac2, cookie)
        assert Packet.mac1(with_mac2) == Packet.mac1(frame)

        # Without a cookie, MAC2 is zero, as put_mac1/2 leaves it.
        assert Packet.put_macs(frame, mac1_key, nil) == frame
        assert Packet.put_mac1(with_mac2, mac1_key) == frame
      end
    end

    test "valid_mac2?/2 detects a change to any byte, and never raises" do
      cookie = bytes(16)
      frame = Packet.put_macs(@captured_initiation, Packet.mac1_key(@responder_public), cookie)

      for offset <- 0..147 do
        <<before::binary-size(^offset), byte, rest::binary>> = frame
        refute Packet.valid_mac2?(<<before::binary, Bitwise.bxor(byte, 1), rest::binary>>, cookie), "offset #{offset}"
      end

      refute Packet.valid_mac2?(frame, bytes(16))
      refute Packet.valid_mac2?(@captured_initiation, <<0::128>>)

      for {frame, cookie} <- [
            {binary_part(frame, 0, 147), cookie},
            {Packet.encode(cookie_reply()), cookie},
            {nil, cookie},
            {frame, bytes(32)},
            {frame, nil}
          ] do
        refute Packet.valid_mac2?(frame, cookie)
      end
    end

    test "mac1/1 reads only full handshake frames, and put_macs/3 rejects bad cookies" do
      <<_covered::binary-116, mac1::binary-16, _mac2::binary-16>> = @captured_initiation
      assert Packet.mac1(@captured_initiation) == {:ok, mac1}
      assert Packet.mac1(Packet.encode(cookie_reply())) == :error
      assert Packet.mac1(nil) == :error

      key = Packet.mac1_key(@responder_public)
      assert_raise ArgumentError, fn -> Packet.put_macs(@captured_initiation, key, bytes(32)) end
      assert_raise ArgumentError, fn -> Packet.put_macs(Packet.encode(cookie_reply()), key, bytes(16)) end
    end
  end
end
