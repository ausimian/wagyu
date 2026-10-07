# Run state of the processes on the data path during bulk TCP through the
# tunnel.
#
# The script uses the same two interfaces as `throughput.exs`. A sampler
# reads the status and the message queue length of each process on the data
# path every millisecond while the transfers run. It then prints, for each
# process, the percentage of samples in which the process was running, the
# percentage in which it was running or waiting for a scheduler (busy), and
# the longest message queue that it saw.
#
#     mix run bench/profile.exs
#
# Environment:
#
#   * `WAGYU_BENCH_MB` - the MiB that each run sends (default 64)
#   * `WAGYU_BENCH_RUNS` - the runs that are sampled for each stream count
#     (default 3)
#   * `WAGYU_BENCH_STREAMS` - the stream counts, separated by commas
#     (default "1,8")
#   * `WAGYU_BENCH_MTU` - the MTU of the stacks (default 1280)
#
# Interface A sends the data and interface B receives it.

Code.require_file("support/throughput.ex", __DIR__)

defmodule Wagyu.Bench.Profile do
  @moduledoc false

  alias Wagyu.Bench.Throughput

  @doc "Returns `{label, pid}` for each process on the data path of the tunnel."
  def processes(%{interface: a, peer_interface: b}) do
    processes(a, "A (sender)") ++ processes(b, "B (receiver)")
  end

  defp processes(interface, side) do
    root = GenServer.whereis(interface)
    {:ok, interface_pid, _value} = Wagyu.Registry.lookup(root, :interface)
    {:ok, link_pid, %{stack: stack}} = Wagyu.Registry.lookup(root, :link)
    state = :sys.get_state(interface_pid)
    {:"$inet", :gen_udp_socket, {socket_pid, _socket}} = state.socket

    peers =
      Enum.flat_map(state.peers, fn {_key, peer} ->
        [{"Wagyu.Peer", peer.pid}] ++
          for {field, name} <- [sealer: "Wagyu.Peer.Sealer", sender: "Wagyu.Peer.Sender"],
              pid = Map.get(peer, field),
              do: {name, pid}
      end)

    labelled =
      peers ++
        [
          {"SmolNet.Stack", stack.stack},
          {"Wagyu.Interface", interface_pid},
          {"Wagyu.Link", link_pid},
          {":gen_udp_socket", socket_pid}
        ]

    for {name, pid} <- labelled, do: {"#{side} #{name}", pid}
  end

  @doc "Samples `pids` every millisecond until it gets `:stop`. Returns the counts to `from`."
  def sampler(pids, from) do
    counts = Map.new(pids, &{&1, %{running: 0, runnable: 0, samples: 0, max_queue: 0}})
    sample(pids, counts, from)
  end

  defp sample(pids, counts, from) do
    receive do
      :stop -> send(from, {:samples, counts})
    after
      1 -> sample(pids, Enum.reduce(pids, counts, &record/2), from)
    end
  end

  defp record(pid, counts) do
    case Process.info(pid, [:status, :message_queue_len]) do
      [status: status, message_queue_len: queue] -> Map.update!(counts, pid, &add_sample(&1, status, queue))
      nil -> counts
    end
  end

  defp add_sample(count, status, queue) do
    %{
      count
      | running: count.running + if(status == :running, do: 1, else: 0),
        runnable: count.runnable + if(status == :runnable, do: 1, else: 0),
        samples: count.samples + 1,
        max_queue: max(count.max_queue, queue)
    }
  end

  @doc "Sends `bytes` through `streams` streams `runs` times while it samples. Prints the rate and the table."
  def profile(tunnel, streams, runs, bytes) do
    connections = Throughput.connect(tunnel, streams)
    :ok = Throughput.transfer(connections, bytes)
    labelled = processes(tunnel)
    me = self()
    sampler = spawn_link(fn -> sampler(Enum.map(labelled, &elem(&1, 1)), me) end)
    started = System.monotonic_time(:microsecond)
    for _run <- 1..runs, do: :ok = Throughput.transfer(connections, bytes)
    elapsed = System.monotonic_time(:microsecond) - started
    send(sampler, :stop)
    counts = receive(do: ({:samples, counts} -> counts))
    Throughput.close(connections)

    rate = runs * bytes / 1_048_576 / (elapsed / 1.0e6)
    IO.puts("\n#{streams} stream(s): #{:erlang.float_to_binary(rate, decimals: 1)} MiB/s over #{runs} runs")
    IO.puts("  #{String.pad_trailing("process", 34)} running   busy  max queue")

    for {label, pid} <- labelled do
      %{running: running, runnable: runnable, samples: samples, max_queue: max_queue} = Map.fetch!(counts, pid)
      percent = fn n -> String.pad_leading("#{round(100 * n / max(samples, 1))}%", 6) end
      IO.puts("  #{String.pad_trailing(label, 34)} #{percent.(running)} #{percent.(running + runnable)}  #{max_queue}")
    end
  end
end

alias Wagyu.Bench.{Profile, Throughput}

Logger.configure(level: :warning)

mb = String.to_integer(System.get_env("WAGYU_BENCH_MB", "64"))
runs = String.to_integer(System.get_env("WAGYU_BENCH_RUNS", "3"))
mtu = String.to_integer(System.get_env("WAGYU_BENCH_MTU", "1280"))
streams = System.get_env("WAGYU_BENCH_STREAMS", "1,8") |> String.split(",") |> Enum.map(&String.to_integer/1)

tunnel = Throughput.tunnel(mtu)
IO.puts("Bulk TCP, #{mb} MiB per run, MTU #{mtu}, #{System.schedulers_online()} schedulers")
for count <- streams, do: Profile.profile(tunnel, count, runs, mb * 1024 * 1024)
