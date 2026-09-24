defmodule Wagyu.NoiseTest do
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.Config
  alias Wagyu.Noise
  alias Wagyu.Packet

  @initiator_index 0x11223344
  @responder_index 0x55667788

  defp vector(name), do: Wagyu.GoldenVectors.fetch!(name)

  defp identity(private_key) do
    {:ok, identity} = Config.new(private_key: private_key)
    identity
  end

  # Decibel generates ephemeral keys itself. Its known-answer seam fixes
  # them, so the transcript is deterministic; nothing else here uses it.
  defp with_ephemeral(private_key) do
    ephemeral = :crypto.generate_key(:ecdh, :x25519, private_key)
    fn protocol, role, keys -> Decibel.Unsafe.new(protocol, role, Map.put(keys, :e, ephemeral)) end
  end

  defp decode(frame) do
    {:ok, message} = Packet.decode(frame)
    message
  end

  test "reproduces the golden handshake transcript, framing and MAC1 included" do
    initiator = identity(vector(:initiator_private))
    responder = identity(vector(:responder_private))
    assert initiator.public_key == vector(:initiator_public)
    assert responder.public_key == vector(:responder_public)

    ini = Noise.initiator(initiator, responder.public_key, with_ephemeral(vector(:initiator_ephemeral_private)))
    rsp = Noise.responder(responder, with_ephemeral(vector(:responder_ephemeral_private)))

    initiation =
      Noise.write_initiation(ini, @initiator_index, vector(:timestamp), Packet.mac1_key(responder.public_key))

    assert initiation == vector(:initiation)

    assert Noise.read_initiation(rsp, decode(initiation)) ==
             {:ok, initiator.public_key, vector(:timestamp)}

    assert {:ok, response} =
             Noise.write_response(rsp, @responder_index, @initiator_index, Packet.mac1_key(initiator.public_key))

    assert response == vector(:response)
    assert Noise.read_response(ini, decode(response)) == :ok

    assert {:ok, initiator_keepalive} = Noise.seal(ini, @responder_index, "")
    assert initiator_keepalive == vector(:initiator_keepalive)
    assert Noise.open(rsp, decode(initiator_keepalive)) == {:ok, ""}

    assert {:ok, responder_keepalive} = Noise.seal(rsp, @initiator_index, "")
    assert responder_keepalive == vector(:responder_keepalive)
    assert Noise.open(ini, decode(responder_keepalive)) == {:ok, ""}
  end

  describe "a genuine handshake" do
    setup do
      initiator = identity(elem(keypair(), 1))
      responder = identity(elem(keypair(), 1))
      ini = Noise.initiator(initiator, responder.public_key)
      rsp = Noise.responder(responder)
      initiation = Noise.write_initiation(ini, 1, timestamp(1), Packet.mac1_key(responder.public_key))
      {:ok, _key, _timestamp} = Noise.read_initiation(rsp, decode(initiation))
      {:ok, response} = Noise.write_response(rsp, 2, 1, Packet.mac1_key(initiator.public_key))
      %{initiator: initiator, responder: responder, ini: ini, rsp: rsp, response: response}
    end

    test "a forged response fails without changing the initiator's session", context do
      %Packet.Response{ephemeral: ephemeral, encrypted_nothing: nothing} = genuine = decode(context.response)
      flip = fn <<first, rest::binary>> -> <<Bitwise.bxor(first, 1), rest::binary>> end

      for forged <- [
            %{genuine | encrypted_nothing: flip.(nothing)},
            %{genuine | ephemeral: flip.(ephemeral)},
            # X25519 rejects an all-zero public key.
            %{genuine | ephemeral: <<0::256>>}
          ] do
        assert Noise.read_response(context.ini, forged) == :error
      end

      # The genuine response still completes the handshake.
      assert Noise.read_response(context.ini, genuine) == :ok
      assert {:ok, keepalive} = Noise.seal(context.ini, 2, "")
      assert Noise.open(context.rsp, decode(keepalive)) == {:ok, ""}
    end

    test "transport messages authenticate, carry their counter, and a forged one fails", context do
      :ok = Noise.read_response(context.ini, decode(context.response))

      for counter <- 0..2 do
        assert {:ok, frame} = Noise.seal(context.ini, 2, "packet #{counter}")
        assert %Packet.Transport{receiver_index: 2, counter: ^counter} = decode(frame)
        assert Noise.open(context.rsp, decode(frame)) == {:ok, "packet #{counter}"}
      end

      {:ok, frame} = Noise.seal(context.ini, 2, "late")
      %Packet.Transport{encrypted_packet: <<first, rest::binary>>} = transport = decode(frame)

      assert Noise.open(context.rsp, %{transport | encrypted_packet: <<Bitwise.bxor(first, 1), rest::binary>>}) ==
               :error

      assert Noise.open(context.rsp, transport) == {:ok, "late"}
    end

    test "sending stops at REJECT_AFTER_MESSAGES", context do
      :ok = Noise.read_response(context.ini, decode(context.response))
      :ok = Decibel.set_nonce(context.ini, :out, 0xFFFFFFFFFFFFDFFE)

      assert {:ok, frame} = Noise.seal(context.ini, 2, "")
      assert %Packet.Transport{counter: 0xFFFFFFFFFFFFDFFE} = decode(frame)
      assert Noise.seal(context.ini, 2, "") == :error
    end
  end

  test "WireGuard key rotation never uses Noise's rekey" do
    for path <- Path.wildcard("lib/**/*.ex") do
      refute File.read!(path) =~ ~r/Decibel\.rekey\b/, "#{path} calls Decibel.rekey/2"
    end
  end
end
