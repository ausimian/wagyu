defmodule Wagyu.HandshakeSupervisor do
  @moduledoc false

  # Supervises the temporary workers that process inbound initiations. The
  # interface admits candidates with `Wagyu.HandshakeQueue` before it starts
  # a worker here. `:max_children` applies the same limit again.
  #
  # The local key pair goes to the workers as an extra argument. The
  # supervisor holds this argument one time, inside a `Wagyu.Config`. The
  # `Inspect` implementation of `Wagyu.Config` hides the private key. Thus
  # the child specs of the workers and the supervisor reports do not contain
  # the raw key.

  use DynamicSupervisor

  alias Wagyu.Config

  @max_workers 8

  @spec start_link({pid(), Config.t()}) :: Supervisor.on_start()
  def start_link({root, %Config{} = identity}) do
    DynamicSupervisor.start_link(__MODULE__, identity, name: Wagyu.Registry.via(root, :handshake_supervisor))
  end

  @doc "Starts a worker for an admitted initiation under the handshake supervisor of `root`."
  @spec start_worker(pid(), map()) :: DynamicSupervisor.on_start_child() | {:error, :unavailable}
  def start_worker(root, candidate) do
    case Wagyu.Registry.lookup(root, :handshake_supervisor) do
      {:ok, supervisor, _value} ->
        DynamicSupervisor.start_child(supervisor, {Wagyu.HandshakeWorker, Map.put(candidate, :root, root)})

      :error ->
        {:error, :unavailable}
    end
  catch
    # The supervisor exited between the lookup and the call.
    :exit, _reason -> {:error, :unavailable}
  end

  @impl true
  def init(identity) do
    DynamicSupervisor.init(strategy: :one_for_one, max_children: @max_workers, extra_arguments: [identity])
  end
end
