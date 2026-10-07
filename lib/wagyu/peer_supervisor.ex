defmodule Wagyu.PeerSupervisor do
  @moduledoc false

  # Supervises one temporary `Wagyu.Peer.Group` for each active configured
  # peer. The group holds the peer and its sender. Only the interface starts
  # peers. It starts a peer on demand. It also starts each peer with a
  # persistent keepalive when this supervisor tells the interface that the
  # supervisor started. The local key pair goes to the peers as an extra
  # argument, the same as for the handshake workers.

  use DynamicSupervisor

  alias Wagyu.Config

  @max_peers 1024

  @spec start_link({pid(), Config.t()}) :: Supervisor.on_start()
  def start_link({root, %Config{} = identity}) do
    DynamicSupervisor.start_link(__MODULE__, {root, identity}, name: Wagyu.Registry.via(root, :peer_supervisor))
  end

  @doc "Starts a peer under `root`'s peer supervisor."
  @spec start_peer(pid(), map()) :: DynamicSupervisor.on_start_child() | {:error, :unavailable}
  def start_peer(root, args) do
    case Wagyu.Registry.lookup(root, :peer_supervisor) do
      {:ok, supervisor, _value} -> DynamicSupervisor.start_child(supervisor, {Wagyu.Peer.Group, args})
      :error -> {:error, :unavailable}
    end
  catch
    # The supervisor exited between the lookup and the call.
    :exit, _reason -> {:error, :unavailable}
  end

  @impl true
  def init({root, identity}) do
    # The interface starts before this supervisor, and its start_peer calls
    # wait until this returns.
    with {:ok, interface, _value} <- Wagyu.Registry.lookup(root, :interface),
         do: send(interface, :peer_supervisor_started)

    DynamicSupervisor.init(strategy: :one_for_one, max_children: @max_peers, extra_arguments: [identity])
  end
end
