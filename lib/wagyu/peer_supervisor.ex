defmodule Wagyu.PeerSupervisor do
  @moduledoc false

  # Supervises one temporary process per active configured peer. Only the
  # interface starts peers, on demand; configured peers are not started
  # eagerly. The local key pair reaches peers as an extra argument, as it
  # does for handshake workers.

  use DynamicSupervisor

  alias Wagyu.Config

  @max_peers 1024

  @spec start_link({pid(), Config.t()}) :: Supervisor.on_start()
  def start_link({root, %Config{} = identity}) do
    DynamicSupervisor.start_link(__MODULE__, identity, name: Wagyu.Registry.via(root, :peer_supervisor))
  end

  @doc "Starts a peer under `root`'s peer supervisor."
  @spec start_peer(pid(), map()) :: DynamicSupervisor.on_start_child() | {:error, :unavailable}
  def start_peer(root, args) do
    case Wagyu.Registry.lookup(root, :peer_supervisor) do
      {:ok, supervisor, _value} -> DynamicSupervisor.start_child(supervisor, {Wagyu.Peer, args})
      :error -> {:error, :unavailable}
    end
  catch
    # The supervisor exited between the lookup and the call.
    :exit, _reason -> {:error, :unavailable}
  end

  @impl true
  def init(identity) do
    DynamicSupervisor.init(strategy: :one_for_one, max_children: @max_peers, extra_arguments: [identity])
  end
end
