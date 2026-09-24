defmodule Wagyu.SecretsTest do
  # Changes the global log level and report handling, so it runs alone.
  use ExUnit.Case, async: false

  import Wagyu.TestHelpers

  @moduletag :capture_log

  defmodule Handler do
    @moduledoc false

    # Forwards every event, formatted as Elixir's default handler formats it,
    # to the test process.
    def log(event, %{config: %{test: test}, formatter: {formatter, config}}) do
      send(test, {:log, IO.chardata_to_string(formatter.format(event, config))})
    end
  end

  setup do
    level = Logger.level()
    %{filters: filters} = :logger.get_primary_config()
    {translator, translator_config} = Keyword.fetch!(filters, :logger_translator)

    # The equivalent of `handle_sasl_reports: true`, so that crash,
    # supervisor and progress reports are logged, at the most detailed level.
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
    preshared_key = <<0::256>>
    {peer_key, _peer_private_key} = initiator = keypair()
    [peer] = options()[:peers]
    peer = %{peer | public_key: peer_key}
    name = :wagyu_secrets_test

    options =
      options(name: name, private_key: private_key, peers: [Map.put(peer, :preshared_key, preshared_key)])

    # A user's supervisor, whose progress reports print Wagyu's child spec.
    {:ok, user_supervisor} = Supervisor.start_link([{Wagyu, options}], strategy: :one_for_one)
    root = Process.whereis(name)
    %{interface: interface} = children(root)

    # The interface raises, so its report shows its state and last message
    # and the crash report shows its stack trace, arguments included.
    catch_exit(GenServer.call(interface, :crash))
    children = eventually(fn -> if child(root, :interface) != interface, do: children(root) end)

    # A peer raises the same way, while it holds the transport session of
    # a handshake it has responded to. Its Noise state, which includes the
    # private key and the session keys, lives in its process dictionary, and
    # crash reports include the dictionary of a process that is not
    # sensitive.
    {:ok, %{public_key: public_key, listen: %{port: port}}} = Wagyu.info(root)
    {:ok, client} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}])
    :ok = :gen_udp.send(client, {127, 0, 0, 1}, port, noise_initiation(public_key, initiator, timestamp(1)))
    peer = only_child(children.peer_supervisor)
    assert eventually(fn -> :sys.get_state(peer).next end)
    catch_exit(GenServer.call(peer, :crash))

    # A handshake worker fails in init, with its key pair in its arguments.
    assert {:error, _reason} =
             DynamicSupervisor.start_child(children.handshake_supervisor, {Wagyu.HandshakeWorker, :bad})

    # Supervisors report their children's start arguments when those die.
    kill(children.handshake_supervisor)
    children(root)
    kill(root)
    restarted = eventually(fn -> Process.whereis(name) != root and Process.whereis(name) end)
    children(restarted)

    logs = collect_logs()
    Supervisor.stop(user_supervisor)

    # The reports were logged, and formatted the configuration redacted.
    assert logs =~ "GenServer #{inspect(interface)} terminating"
    assert logs =~ "no function clause matching in Wagyu.Interface.handle_call/3"
    assert logs =~ "GenServer #{inspect(peer)} terminating"
    assert logs =~ "Wagyu.HandshakeWorker.init"
    assert logs =~ "Start Call: Wagyu.start_link(#Wagyu.Config<"
    assert logs =~ "Start Call: Wagyu.HandshakeSupervisor.start_link("
    assert logs =~ "config: :redacted"

    # Noise state, such as the peer's chaining and cipher keys, never
    # appears. Session handles, which hold none, are inspected as
    # #Decibel.Session<...>; state is a plain %Decibel... struct.
    assert logs =~ "#Decibel.Session<"
    refute logs =~ "%Decibel."

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
    end
  end
end
