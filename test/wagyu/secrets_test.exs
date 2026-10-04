defmodule Wagyu.SecretsTest do
  # This test changes the global log level and how reports are handled.
  # Thus it runs alone.
  use ExUnit.Case, async: false

  import Wagyu.TestHelpers

  @moduletag :capture_log

  defmodule Handler do
    @moduledoc false

    # Sends each event to the test process, with the format that the default
    # handler of Elixir uses.
    def log(event, %{config: %{test: test}, formatter: {formatter, config}}) do
      send(test, {:log, IO.chardata_to_string(formatter.format(event, config))})
    end
  end

  setup do
    level = Logger.level()
    %{filters: filters} = :logger.get_primary_config()
    {translator, translator_config} = Keyword.fetch!(filters, :logger_translator)

    # This is equivalent to `handle_sasl_reports: true`. Thus the logger
    # records crash, supervisor and progress reports, at the most detailed
    # level.
    :ok = :logger.remove_primary_filter(:logger_translator)
    :ok = :logger.add_primary_filter(:logger_translator, {translator, %{translator_config | sasl: true}})
    :ok = Logger.configure(level: :debug)

    :ok =
      :logger.add_handler(:wagyu_secrets_test, Handler, %{
        level: :all,
        config: %{test: self()},
        formatter: Logger.default_formatter()
      })

    on_exit(fn ->
      :logger.remove_handler(:wagyu_secrets_test)
      Logger.configure(level: level)
      :logger.remove_primary_filter(:logger_translator)
      :logger.add_primary_filter(:logger_translator, {translator, translator_config})
    end)
  end

  defp collect_logs(logs \\ []) do
    receive do
      {:log, text} -> collect_logs([text | logs])
    after
      300 -> logs |> Enum.reverse() |> Enum.join("\n")
    end
  end

  defp kill(pid) do
    monitor = Process.monitor(pid)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :killed}
  end

  defp only_child(supervisor) do
    eventually(fn ->
      case DynamicSupervisor.which_children(supervisor) do
        [{_id, pid, _type, _modules}] -> pid
        _none -> nil
      end
    end)
  end

  test "crash, supervisor and progress reports never show private or preshared keys" do
    private_key = "a private key for the crash test"
    preshared_key = :crypto.strong_rand_bytes(32)
    {peer_key, _peer_private_key} = initiator = keypair()
    [peer] = options()[:peers]
    peer = %{peer | public_key: peer_key}
    name = :wagyu_secrets_test

    options =
      options(name: name, private_key: private_key, peers: [Map.put(peer, :preshared_key, preshared_key)])

    # The supervisor of a user. Its progress reports print the child spec of
    # Wagyu.
    {:ok, user_supervisor} = Supervisor.start_link([{Wagyu, options}], strategy: :one_for_one)
    root = Process.whereis(name)
    %{interface: interface} = children(root)

    # The interface raises. Thus its report shows its state and last message.
    # The crash report shows its stack trace, with the arguments.
    catch_exit(GenServer.call(interface, :crash))
    children = eventually(fn -> if child(root, :interface) != interface, do: children(root) end)

    # A peer raises in the same way. At that time, it holds the transport
    # session of a handshake that it responded to. Its Noise state includes
    # the private key and the session keys. This state is in its process
    # dictionary. Crash reports include the dictionary of a process that is
    # not sensitive.
    {:ok, %{public_key: public_key, listen: %{port: port}}} = Wagyu.info(root)
    {:ok, client} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}])

    # The `sys` debug log of the interface records its replies without
    # change. The reply to the claim of the worker contains the configuration
    # of the peer.
    :ok = :sys.log(children.interface, true)
    :ok = :gen_udp.send(client, {127, 0, 0, 1}, port, noise_initiation(public_key, initiator, timestamp(1)))
    peer = only_child(children.peer_supervisor)
    assert eventually(fn -> :sys.get_state(peer).next end)
    status = inspect(:sys.get_status(children.interface), limit: :infinity, printable_limit: :infinity)
    assert status =~ ~r/\{:ok, #PID<[0-9.]+>, #Wagyu.Config.Peer</
    catch_exit(GenServer.call(peer, :crash))

    # A handshake worker fails in init, with its key pair in its arguments.
    assert {:error, _reason} =
             DynamicSupervisor.start_child(children.handshake_supervisor, {Wagyu.HandshakeWorker, :bad})

    # When children stop unexpectedly, their supervisors report the start
    # arguments of the children.
    kill(children.handshake_supervisor)
    children(root)
    kill(root)
    restarted = eventually(fn -> Process.whereis(name) != root and Process.whereis(name) end)
    children(restarted)

    logs = collect_logs()
    Supervisor.stop(user_supervisor)

    # The logger recorded the reports, and the formatted configuration was
    # redacted.
    assert logs =~ "GenServer #{inspect(interface)} terminating"
    assert logs =~ "no function clause matching in Wagyu.Interface.handle_call/3"
    assert logs =~ "GenServer #{inspect(peer)} terminating"
    assert logs =~ "Wagyu.HandshakeWorker.init"
    assert logs =~ "Start Call: Wagyu.start_link(#Wagyu.Config<"
    assert logs =~ "Start Call: Wagyu.HandshakeSupervisor.start_link("
    assert logs =~ "config: :redacted"

    # Noise state, for example the chaining and cipher keys of the peer, does
    # not appear. Session handles do not hold Noise state, and they show as
    # #Decibel.Session<...>. Noise state is a plain %Decibel... struct. A
    # replay window is also plain, but it holds only counters.
    assert logs =~ "#Decibel.Session<"
    assert logs =~ "%Decibel.ReplayWindow{"
    refute logs =~ ~r/%Decibel\.(?!ReplayWindow\{)/

    for secret <- [private_key, preshared_key],
        form <- [
          secret,
          inspect(secret),
          inspect(secret, binaries: :as_binaries, limit: :infinity),
          Base.encode16(secret),
          Base.encode16(secret, case: :lower),
          Base.encode64(secret)
        ] do
      refute logs =~ form
      refute status =~ form
    end
  end
end
