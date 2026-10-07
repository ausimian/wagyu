# Bulk TCP throughput through the tunnel.
#
# The benchmark uses two interfaces on 127.0.0.1. Each interface has its own
# SmolNet stack and is a peer of the other interface. Each run sends
# `WAGYU_BENCH_MB` MiB from sockets on one stack to a listener on the other
# stack, divided across 1, 4 or 8 streams. The baseline is the loopback link
# of SmolNet, which sends the same TCP without a tunnel.
#
#     mix run bench/throughput.exs
#
# Environment:
#
#   * `WAGYU_BENCH_MB` - the MiB that each run sends (default 16)
#   * `WAGYU_BENCH_TIME` - the seconds measured for each scenario (default 10)
#   * `WAGYU_BENCH_MTU` - the MTU of the stacks (default 1280)
#
# The two ends run in this VM and use the same schedulers. Thus one interface
# that sends to a remote peer does about half of this work. After the Benchee
# report, the script prints the median rate of each scenario in MiB/s. For the
# tunnel, it also prints the packets that the interface dropped. Dropped
# packets are the cause when many streams collapse.

Code.require_file("support/throughput.ex", __DIR__)

alias Wagyu.Bench.Throughput

Logger.configure(level: :warning)

mb = String.to_integer(System.get_env("WAGYU_BENCH_MB", "16"))
time = String.to_integer(System.get_env("WAGYU_BENCH_TIME", "10"))
mtu = String.to_integer(System.get_env("WAGYU_BENCH_MTU", "1280"))
bytes = mb * 1024 * 1024

tunnel = Throughput.tunnel(mtu)
loopback = Throughput.loopback(mtu)
drops = :ets.new(:drops, [:public])

# Each scenario opens its connections one time. Each run then sends `bytes`
# through them. The script compares the drop counters of the tunnel before
# and after a scenario.
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
