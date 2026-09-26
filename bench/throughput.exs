# Bulk TCP throughput through the tunnel.
#
# Two interfaces on 127.0.0.1, each with its own SmolNet stack, peered with
# each other. Every run sends `WAGYU_BENCH_MB` MiB from sockets on one stack
# to a listener on the other, split across 1, 4 or 8 streams. SmolNet's own
# loopback link, which carries the same TCP with no tunnel, is the baseline.
#
#     mix run bench/throughput.exs
#
# Environment:
#
#   * `WAGYU_BENCH_MB` - MiB sent per run (default 16)
#   * `WAGYU_BENCH_TIME` - seconds measured per scenario (default 10)
#   * `WAGYU_BENCH_MTU` - the stacks' MTU (default 1280)
#
# Both ends run in this VM and share its schedulers, so one interface talking
# to a remote peer does about half this work. After Benchee's report the
# script prints each scenario's rate in MiB/s and, for the tunnel, the packets
# the interface dropped: drops are what make many streams collapse.

defmodule Wagyu.Bench.Throughput do
  @moduledoc false

  @chunk 64 * 1024
  @tunnel_a {10, 13, 0, 2}
  @tunnel_b {10, 13, 0, 1}
  @drops [:egress_peer_dropped, :inbound_peer_dropped, :staged_dropped]

  @doc "Starts two interfaces peered with each other, and completes their handshake."
  def tunnel(mtu) do
    {a_public, a_private} = :crypto.generate_key(:ecdh, :x25519)
    {b_public, b_private} = :crypto.generate_key(:ecdh, :x25519)
    {a_port, b_port} = {free_port(), free_port()}

    a = interface(a_private, a_port, @tunnel_a, @tunnel_b, b_public, b_port, mtu)
    b = interface(b_private, b_port, @tunnel_b, @tunnel_a, a_public, a_port, mtu)
    {:ok, a_stack} = Wagyu.stack(a)
    {:ok, b_stack} = Wagyu.stack(b)

    tunnel = %{interface: a, from: a_stack, to: b_stack, address: @tunnel_b}
    connections = connect(tunnel, 1)
    :ok = transfer(connections, 1024 * 1024)
    close(connections)
    tunnel
  end

  @doc "Starts a SmolNet loopback stack, whose egress feeds its own ingress."
  def loopback(mtu) do
    {:ok, _link, stack} = SmolNet.Loopback.start_link(addresses: [{{127, 0, 0, 1}, 8}], mtu: mtu)
    %{from: stack, to: stack, address: {127, 0, 0, 1}}
  end

  @doc """
  Opens `streams` connections from `from` to a listener on `to`, each end
  held by its own process. Runs reuse them: a TCP socket that closes first
  keeps one of its stack's 64 socket slots, the default, through TIME_WAIT,
  for about 10 seconds, so a connection per run would soon exhaust them.
  """
  def connect(%{from: from, to: to, address: address}, streams) do
    port = 10_000 + rem(System.unique_integer([:positive, :monotonic]), 50_000)
    {:ok, listener} = :gen_tcp.listen(port, tcp_options(to) ++ [ip: address, backlog: streams])
    # One connection at a time: a listener takes one accept at a time, and
    # a burst of connects can overrun its backlog. Each accepted socket goes
    # to the process that receives on it.
    pairs =
      for _stream <- 1..streams do
        sender = spawn_link(fn -> sender(from, address, port) end)
        {:ok, socket} = :gen_tcp.accept(listener, 30_000)
        receiver = spawn_link(fn -> receive(do: ({:socket, socket} -> receiver(socket))) end)
        :ok = :gen_tcp.controlling_process(socket, receiver)
        send(receiver, {:socket, socket})
        {sender, receiver}
      end

    {senders, receivers} = Enum.unzip(pairs)
    %{streams: streams, senders: senders, receivers: receivers, listener: listener}
  end

  @doc "Sends `bytes` over `connections`, split evenly, and waits until all of it has arrived."
  def transfer(%{senders: senders, receivers: receivers}, bytes) do
    per_stream = div(bytes, length(senders))
    for pid <- senders ++ receivers, do: send(pid, {:transfer, per_stream, self()})
    for pid <- senders ++ receivers, do: receive(do: ({:done, ^pid} -> :ok))
    :ok
  end

  @doc "Closes the connections and their listener."
  def close(%{senders: senders, receivers: receivers, listener: listener}) do
    for pid <- senders ++ receivers, do: send(pid, {:close, self()})
    for pid <- senders ++ receivers, do: receive(do: ({:done, ^pid} -> :ok))
    :gen_tcp.close(listener)
  end

  @doc "The interface's drop counters."
  def drops(interface) do
    {:ok, %{counters: counters}} = Wagyu.info(interface)
    Map.take(counters, @drops)
  end

  defp interface(private_key, port, address, gateway, peer_key, peer_port, mtu) do
    {:ok, interface} =
      Wagyu.start_link(
        private_key: private_key,
        listen: %{address: {127, 0, 0, 1}, port: port},
        stack: [addresses: [{address, 32}], routes: [{{0, 0, 0, 0}, 0, gateway}], mtu: mtu],
        peers: [
          %{
            public_key: peer_key,
            endpoint: %{address: {127, 0, 0, 1}, port: peer_port},
            allowed_ips: [{{0, 0, 0, 0}, 0}]
          }
        ]
      )

    interface
  end

  defp free_port do
    {:ok, socket} = :gen_udp.open(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(socket)
    :ok = :gen_udp.close(socket)
    port
  end

  defp tcp_options(stack), do: [{:tcp_module, SmolNet.Inet.Tcp}, {:smolnet_stack, stack}, :inet, :binary, active: false]

  defp sender(stack, address, port) do
    {:ok, socket} = :gen_tcp.connect(address, port, tcp_options(stack), 30_000)
    chunk = :crypto.strong_rand_bytes(@chunk)
    serve(socket, fn bytes -> send_bytes(socket, chunk, bytes) end)
  end

  defp receiver(socket), do: serve(socket, fn bytes -> receive_bytes(socket, bytes) end)

  defp serve(socket, transfer) do
    receive do
      {:transfer, bytes, from} ->
        transfer.(bytes)
        send(from, {:done, self()})
        serve(socket, transfer)

      {:close, from} ->
        :gen_tcp.close(socket)
        send(from, {:done, self()})
    end
  end

  defp send_bytes(_socket, _chunk, bytes) when bytes <= 0, do: :ok

  defp send_bytes(socket, chunk, bytes) do
    :ok = :gen_tcp.send(socket, binary_part(chunk, 0, min(bytes, @chunk)))
    send_bytes(socket, chunk, bytes - @chunk)
  end

  defp receive_bytes(_socket, bytes) when bytes <= 0, do: :ok

  defp receive_bytes(socket, bytes) do
    {:ok, data} = :gen_tcp.recv(socket, 0, 30_000)
    receive_bytes(socket, bytes - byte_size(data))
  end
end

alias Wagyu.Bench.Throughput

Logger.configure(level: :warning)

mb = String.to_integer(System.get_env("WAGYU_BENCH_MB", "16"))
time = String.to_integer(System.get_env("WAGYU_BENCH_TIME", "10"))
mtu = String.to_integer(System.get_env("WAGYU_BENCH_MTU", "1280"))
bytes = mb * 1024 * 1024

tunnel = Throughput.tunnel(mtu)
loopback = Throughput.loopback(mtu)
drops = :ets.new(:drops, [:public])

# Each scenario opens its connections once; every run then pushes `bytes`
# through them. The tunnel's drop counters are compared across a scenario.
job = fn target, drops_of ->
  {fn connections -> Throughput.transfer(connections, bytes) end,
   before_scenario: fn streams ->
     :ets.insert(drops, {{target, streams}, drops_of.()})
     Throughput.connect(target, streams)
   end,
   after_scenario: fn connections ->
     Throughput.close(connections)
     key = {target, connections.streams}
     [{^key, before}] = :ets.lookup(drops, key)
     :ets.insert(drops, {key, Map.new(drops_of.(), fn {name, n} -> {name, n - Map.fetch!(before, name)} end)})
   end}
end

suite =
  Benchee.run(
    %{
      "wagyu tunnel" => job.(tunnel, fn -> Throughput.drops(tunnel.interface) end),
      "smolnet loopback" => job.(loopback, fn -> %{} end)
    },
    inputs: [{"1 stream", 1}, {"4 streams", 4}, {"8 streams", 8}],
    warmup: 1,
    time: time,
    title: "Bulk TCP, #{mb} MiB per run, MTU #{mtu}"
  )

IO.puts("\nThroughput (median run):")

for scenario <- Enum.sort_by(suite.scenarios, &{&1.job_name, &1.input}) do
  median = scenario.run_time_data.statistics.median
  rate = mb / (median / 1.0e9)
  line = "  #{String.pad_trailing(scenario.job_name, 18)} #{String.pad_trailing(scenario.input_name, 10)}"
  line = line <> " #{:erlang.float_to_binary(rate, decimals: 1)} MiB/s"

  line =
    case {scenario.job_name, :ets.lookup(drops, {tunnel, scenario.input})} do
      {"wagyu tunnel", [{_key, dropped}]} -> line <> "  drops #{inspect(dropped)}"
      _no_drops -> line
    end

  IO.puts(line)
end
