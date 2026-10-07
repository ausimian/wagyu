defmodule Wagyu.ConfigStore do
  @moduledoc false

  # Keeps the latest configuration that the interface accepted. It is the
  # first child of the root supervisor. Thus the configuration survives a
  # restart of the link, the stack, the interface and the supervisors after
  # them. The interface reads the configuration from this process when it
  # starts, and writes each peer set that it accepts (`put/2`).
  #
  # The store starts with the configuration from the start options. It holds
  # only data and does no I/O. Thus it is not expected to fail. If it fails,
  # the root restarts all of its children, and the interface starts again
  # with the start options. A restart of the root does the same.
  #
  # The registration of the store creates an Erlang link to the registry.
  # If the registry exits, the registrations of this interface go with it.
  # Thus the store exits too, and the root starts the complete interface
  # again, the same as for a failure of the link.
  #
  # The configuration holds the private key and the preshared keys. Thus the
  # process is sensitive, and its status, messages and replies hide the
  # configuration.

  use GenServer

  alias Wagyu.Config

  @spec start_link({pid(), Config.t()}) :: GenServer.on_start()
  def start_link({root, %Config{} = config}), do: GenServer.start_link(__MODULE__, {root, config})

  @doc "Returns the latest configuration of `root`, or `:error` if no store runs."
  @spec fetch(pid()) :: {:ok, Config.t()} | :error
  def fetch(root) do
    case Wagyu.Registry.lookup(root, :config) do
      {:ok, store, _value} -> GenServer.call(store, :fetch)
      :error -> :error
    end
  catch
    :exit, _reason -> :error
  end

  @doc """
  Replaces the configuration of `root`. Raises if no store runs. A store
  that is not running restarts the complete interface. Thus the caller
  stops with it.
  """
  @spec put(pid(), Config.t()) :: :ok
  def put(root, %Config{} = config) do
    {:ok, store, _value} = Wagyu.Registry.lookup(root, :config)
    GenServer.call(store, {:put, config})
  end

  @impl true
  def init({root, config}) do
    Process.flag(:sensitive, true)
    # Trap exits to see the exit of the registry.
    Process.flag(:trap_exit, true)
    :ok = Wagyu.Registry.register(root, :config)
    {:ok, %{config: config}}
  end

  @impl true
  def handle_call(:fetch, _from, state), do: {:reply, {:ok, state.config}, state}
  def handle_call({:put, %Config{} = config}, _from, state), do: {:reply, :ok, %{state | config: config}}

  # The parent is the only other process with an Erlang link to the store.
  # GenServer handles the exit of the parent.
  @impl true
  def handle_info({:EXIT, _registry, reason}, state), do: {:stop, {:shutdown, {:registry_down, reason}}, state}
  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def format_status(status), do: Wagyu.Redact.format_status(status, [:config], message: &redact/1, reply: &redact/1)

  defp redact({:put, %Config{}}), do: {:put, :redacted}
  defp redact({:ok, %Config{}}), do: {:ok, :redacted}
  defp redact(other), do: other
end
