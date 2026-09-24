defmodule Wagyu.TestHelpers do
  @moduledoc false

  import Bitwise
  import ExUnit.Assertions

  alias Wagyu.Packet
  alias Wagyu.Packet.Initiation

  @roles [:link, :interface, :handshake_supervisor, :peer_supervisor]

  def keypair, do: :crypto.generate_key(:ecdh, :x25519)

  @doc """
  The design's example configuration: a /32 address with a default route via
  an off-subnet gateway, and one peer that takes every IPv4 destination. It
  listens on an OS-chosen loopback port.
  """
  def options(overrides \\ []) do
    {_public_key, private_key} = keypair()
    {peer_key, _private_key} = keypair()

    Keyword.merge(
      [
        private_key: private_key,
        listen: %{address: {127, 0, 0, 1}, port: 0},
        stack: [
          addresses: [{{10, 13, 0, 2}, 32}],
          routes: [{{0, 0, 0, 0}, 0, {10, 13, 0, 1}}],
          mtu: 1280
        ],
        peers: [
          %{
            public_key: peer_key,
            endpoint: %{address: {127, 0, 0, 1}, port: 51_820},
            allowed_ips: [{{0, 0, 0, 0}, 0}]
          }
        ]
      ],
      overrides
    )
  end

  @doc "A UDP port that was free a moment ago."
  def free_port do
    {:ok, socket} = :gen_udp.open(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(socket)
    :ok = :gen_udp.close(socket)
    port
  end

  @doc "Polls `fun` every 10 ms until it returns a truthy value, and returns it."
  def eventually(fun, attempts \\ 300) do
    case fun.() do
      falsy when falsy in [nil, false] and attempts > 1 ->
        Process.sleep(10)
        eventually(fun, attempts - 1)

      falsy when falsy in [nil, false] ->
        flunk("condition not met in time")

      value ->
        value
    end
  end

  @doc "Returns the live process registered as `root`'s `role`, or nil."
  def child(root, role) do
    case Wagyu.Registry.lookup(root, role) do
      {:ok, pid, _value} -> pid
      :error -> nil
    end
  end

  @doc "Waits until every child of `root` is running, and returns them by role."
  def children(root) do
    eventually(fn ->
      children = Map.new(@roles, &{&1, child(root, &1)})
      if Enum.all?(Map.values(children), &is_pid/1), do: children
    end)
  end

  @doc "Waits for `root`'s counters to satisfy `fun`, and returns them."
  def counters(root, fun \\ fn _counters -> true end) do
    eventually(fn ->
      with {:ok, %{counters: counters}} <- Wagyu.info(root), true <- fun.(counters), do: counters
    end)
  end

  @doc "Opens a SmolNet UDP socket on `stack`, bound to the example address."
  def open_udp(stack) do
    {:ok, socket} = SmolNet.open(:inet, :dgram, :udp, stack: stack)
    :ok = SmolNet.bind(socket, %{family: :inet, addr: {10, 13, 0, 2}, port: 0})
    socket
  end

  @doc "Sends `count` datagrams from a SmolNet socket to an address beyond the gateway."
  def send_egress(socket, count, destination \\ {192, 0, 2, 9}) do
    for n <- 1..count//1 do
      :ok = SmolNet.sendto(socket, "packet #{n}", %{family: :inet, addr: destination, port: 9})
    end

    :ok
  end

  @doc "An initiation frame with a valid MAC1 for `public_key` and arbitrary Noise fields."
  def initiation(public_key) do
    frame = <<1, 0, 0, 0, :crypto.strong_rand_bytes(4)::binary, :crypto.strong_rand_bytes(140)::binary>>
    Packet.put_mac1(frame, Packet.mac1_key(public_key))
  end

  @doc """
  A genuine initiation from the holder of `initiator` (a key pair) to the
  holder of `responder_key`, carrying `timestamp`, with a valid MAC1.

  It is built with a Decibel initiator from WireGuard's parameters, stated
  here independently of `Wagyu.Noise`.
  """
  def noise_initiation(responder_key, initiator, timestamp, sender_index \\ :rand.uniform(0xFFFFFFFF)) do
    session =
      Decibel.new("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s", :ini, %{
        s: initiator,
        rs: responder_key,
        psks: [<<0::256>>],
        prologue: "WireGuard v1 zx2c4 Jason@zx2c4.com"
      })

    <<ephemeral::binary-32, static::binary-48, encrypted_timestamp::binary-28>> =
      session |> Decibel.handshake_encrypt(timestamp) |> IO.iodata_to_binary()

    :ok = Decibel.close(session)

    %Initiation{
      sender_index: sender_index,
      ephemeral: ephemeral,
      encrypted_static: static,
      encrypted_timestamp: encrypted_timestamp
    }
    |> Packet.encode()
    |> Packet.put_mac1(Packet.mac1_key(responder_key))
  end

  @doc "The `n`th of a series of strictly increasing TAI64N timestamps."
  def timestamp(n), do: <<0x400000000000000A + 1_700_000_000::64, n * 0x1000000::32>>

  @doc """
  Replaces an interface's clock with a fake one that starts at `start` and
  moves only when `advance/2` moves it. Returns the clock.
  """
  def fake_clock(interface, start \\ 1_000_000) do
    clock = :atomics.new(1, signed: true)
    :atomics.put(clock, 1, start)
    :sys.replace_state(interface, &%{&1 | clock: fn -> :atomics.get(clock, 1) end})
    clock
  end

  @doc "Moves a fake clock forward by `milliseconds`."
  def advance(clock, milliseconds), do: :atomics.add(clock, 1, milliseconds)

  @doc "A complete IPv4 UDP packet with valid header and UDP checksums."
  def ipv4_udp({s1, s2, s3, s4} = _source, {d1, d2, d3, d4} = _destination, source_port, destination_port, payload) do
    source = <<s1, s2, s3, s4>>
    destination = <<d1, d2, d3, d4>>
    udp_length = 8 + byte_size(payload)

    udp_checksum =
      checksum(
        <<source::binary, destination::binary, 0, 17, udp_length::16, source_port::16, destination_port::16,
          udp_length::16, 0::16, payload::binary>>
      )

    udp = <<source_port::16, destination_port::16, udp_length::16, udp_checksum::16, payload::binary>>
    total_length = 20 + udp_length

    header = fn checksum ->
      <<0x45, 0, total_length::16, 0::16, 0x40, 0, 64, 17, checksum::16, source::binary, destination::binary>>
    end

    header.(checksum(header.(0))) <> udp
  end

  defp checksum(data) do
    padded = if rem(byte_size(data), 2) == 1, do: data <> <<0>>, else: data
    sum = for <<word::16 <- padded>>, reduce: 0, do: (sum -> sum + word)
    bnot(fold(sum)) &&& 0xFFFF
  end

  defp fold(sum) when sum > 0xFFFF, do: fold((sum &&& 0xFFFF) + (sum >>> 16))
  defp fold(sum), do: sum
end
