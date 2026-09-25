defmodule Wagyu.TestHelpers do
  @moduledoc false

  import Bitwise
  import ExUnit.Assertions

  alias Wagyu.Packet
  alias Wagyu.Packet.{Initiation, Response, Transport}

  @roles [:link, :interface, :handshake_supervisor, :peer_supervisor]

  # WireGuard's Noise parameters, stated here independently of
  # `Wagyu.Noise`, for the remote parties that tests play.
  @protocol "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
  @prologue "WireGuard v1 zx2c4 Jason@zx2c4.com"
  @zero_psk <<0::256>>

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
  """
  def noise_initiation(responder_key, initiator, timestamp, sender_index \\ random_index()) do
    {frame, session} = initiate_to(responder_key, initiator, timestamp, sender_index)
    :ok = Decibel.close(session)
    frame
  end

  @doc """
  Plays the initiator: returns a genuine initiation, as `noise_initiation/4`
  does, and the Decibel session that wrote it, owned by the caller and
  waiting for the response (see `complete/2`).
  """
  def initiate_to(responder_key, initiator, timestamp, sender_index \\ random_index()) do
    session = Decibel.new(@protocol, :ini, %{s: initiator, rs: responder_key, psks: [@zero_psk], prologue: @prologue})

    <<ephemeral::binary-32, static::binary-48, encrypted_timestamp::binary-28>> =
      session |> Decibel.handshake_encrypt(timestamp) |> IO.iodata_to_binary()

    frame =
      %Initiation{
        sender_index: sender_index,
        ephemeral: ephemeral,
        encrypted_static: static,
        encrypted_timestamp: encrypted_timestamp
      }
      |> Packet.encode()
      |> Packet.put_mac1(Packet.mac1_key(responder_key))

    {frame, session}
  end

  @doc """
  Reads a response frame into an initiator session from `initiate_to/4`,
  which is then ready for transport. Returns `:ok`, or `:error` if the
  response does not authenticate.
  """
  def complete(session, response) do
    {:ok, %Response{ephemeral: ephemeral, encrypted_nothing: nothing}} = Packet.decode(response)
    "" = session |> Decibel.handshake_decrypt([ephemeral, nothing]) |> IO.iodata_to_binary()
    :ok
  rescue
    Decibel.DecryptionError -> :error
  end

  @doc """
  Plays the responder to an initiation frame: checks its MAC1 for
  `responder` (a key pair), reads it with a Decibel responder and writes a
  response from `sender_index` with a valid MAC1. Returns the response
  frame, the responder's transport session, owned by the caller, and what
  the initiation carried.
  """
  def respond_to(initiation, {public_key, _private_key} = responder, sender_index \\ random_index()) do
    assert Packet.valid_mac1?(initiation, Packet.mac1_key(public_key))
    {:ok, %Initiation{} = message} = Packet.decode(initiation)
    session = Decibel.new(@protocol, :rsp, %{s: responder, psks: [@zero_psk], prologue: @prologue})

    timestamp =
      session
      |> Decibel.handshake_decrypt([message.ephemeral, message.encrypted_static, message.encrypted_timestamp])
      |> IO.iodata_to_binary()

    initiator_key = Decibel.remote_key(session)
    <<ephemeral::binary-32, nothing::binary-16>> = session |> Decibel.handshake_encrypt("") |> IO.iodata_to_binary()

    frame =
      %Response{
        sender_index: sender_index,
        receiver_index: message.sender_index,
        ephemeral: ephemeral,
        encrypted_nothing: nothing
      }
      |> Packet.encode()
      |> Packet.put_mac1(Packet.mac1_key(initiator_key))

    {frame, session, %{timestamp: timestamp, initiator_key: initiator_key, sender_index: message.sender_index}}
  end

  @doc "A transport message to `receiver_index`, encrypted with a transport session the caller owns."
  def transport_frame(session, receiver_index, plaintext \\ "") do
    counter = Decibel.nonce(session, :out)
    packet = session |> Decibel.encrypt(plaintext, "") |> IO.iodata_to_binary()
    Packet.encode(%Transport{receiver_index: receiver_index, counter: counter, encrypted_packet: packet})
  end

  @doc "Decrypts a transport frame with a session the caller owns: `{:ok, plaintext}` or `:error`."
  def open_transport(session, frame) do
    {:ok, %Transport{counter: counter, encrypted_packet: packet}} = Packet.decode(frame)
    :ok = Decibel.set_nonce(session, :in, counter)
    {:ok, session |> Decibel.decrypt(packet, "") |> IO.iodata_to_binary()}
  rescue
    Decibel.DecryptionError -> :error
  end

  @doc "Whether a session the calling process owned has been closed."
  def closed?(session) do
    Decibel.handshake_complete?(session)
    false
  rescue
    error in Decibel.SessionError -> error.reason in [:closed, :unknown]
  end

  @doc """
  Runs `fun` on a GenServer's state inside that process, which owns its
  Decibel sessions, and returns the result. The state is left unchanged.
  """
  def in_process(pid, fun) do
    test = self()
    ref = make_ref()

    :sys.replace_state(pid, fn state ->
      send(test, {ref, fun.(state)})
      state
    end)

    receive do
      {^ref, result} -> result
    end
  end

  def random_index, do: :rand.uniform(0x100000000) - 1

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

  @doc "A complete IPv6 UDP packet with a valid UDP checksum."
  def ipv6_udp(source, destination, source_port, destination_port, payload) do
    source = ipv6_binary(source)
    destination = ipv6_binary(destination)
    udp_length = 8 + byte_size(payload)

    udp_checksum =
      checksum(
        <<source::binary, destination::binary, udp_length::32, 0::24, 17, source_port::16, destination_port::16,
          udp_length::16, 0::16, payload::binary>>
      )

    <<6::4, 0::28, udp_length::16, 17, 64, source::binary, destination::binary, source_port::16, destination_port::16,
      udp_length::16, udp_checksum::16, payload::binary>>
  end

  defp ipv6_binary(address), do: for(hextet <- Tuple.to_list(address), into: <<>>, do: <<hextet::16>>)

  defp checksum(data) do
    padded = if rem(byte_size(data), 2) == 1, do: data <> <<0>>, else: data
    sum = for <<word::16 <- padded>>, reduce: 0, do: (sum -> sum + word)
    bnot(fold(sum)) &&& 0xFFFF
  end

  defp fold(sum) when sum > 0xFFFF, do: fold((sum &&& 0xFFFF) + (sum >>> 16))
  defp fold(sum), do: sum
end
