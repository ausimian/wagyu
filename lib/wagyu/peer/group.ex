defmodule Wagyu.Peer.Group do
  @moduledoc false

  # Supervises the three processes of one peer: its sender
  # (`Wagyu.Peer.Sender`), its sealer (`Wagyu.Peer.Sealer`) and the peer
  # (`Wagyu.Peer`). The peer supervisor starts one group for each active
  # peer. A group is temporary, the same as a peer was before it had other
  # processes.
  #
  # The three processes live and stop together:
  #
  #   * All children are temporary and significant. The group uses
  #     `auto_shutdown: :any_significant`. Thus, when one child exits for
  #     any reason, the group stops the other children and then exits.
  #   * The group never restarts a child. The interface starts a new group
  #     when it next needs the peer.
  #
  # The sealer needs the pid of the sender, and the peer needs both. Thus the
  # group starts with no children, and `start_link/2` adds the sender, the
  # sealer and then the peer. If a child cannot start, the group stops and
  # `start_link/2` returns the error.
  #
  # The interface gets the pids from the start. It sends egress to the
  # sealer, and frames to the peer, which it monitors. It stops the group
  # when it stops the peer, because the exit of the peer makes the group
  # stop.

  use Supervisor, restart: :temporary

  alias Wagyu.Config
  alias Wagyu.Peer.{Sealer, Sender}

  @spec start_link(Config.t(), map()) ::
          {:ok, pid(), %{peer: pid(), sender: pid(), sealer: pid()}} | {:error, term()}
  def start_link(%Config{} = identity, %{peer: %Config.Peer{public_key: public_key}} = args) do
    common = Map.merge(Map.take(args, [:root, :counters, :outbound]), %{public_key: public_key})

    with {:ok, group} <- Supervisor.start_link(__MODULE__, :ok) do
      with {:ok, sender} <-
             start_child(group, Sender, [Map.merge(common, %{socket: args.socket, staging: args.staging})]),
           sealer_args = Map.merge(common, %{sender: sender, staging: args.staging, mtu: identity.stack[:mtu]}),
           {:ok, sealer} <- start_child(group, Sealer, [sealer_args]),
           peer_args = Map.merge(args, %{sender: sender, sealer: sealer}),
           {:ok, peer} <- start_child(group, Wagyu.Peer, [identity, peer_args]) do
        {:ok, group, %{peer: peer, sender: sender, sealer: sealer}}
      else
        error ->
          Supervisor.stop(group)
          error
      end
    end
  end

  @impl true
  def init(:ok), do: Supervisor.init([], strategy: :one_for_all, auto_shutdown: :any_significant)

  defp start_child(group, module, args),
    do:
      Supervisor.start_child(group, %{
        id: module,
        start: {module, :start_link, args},
        restart: :temporary,
        significant: true
      })
end
