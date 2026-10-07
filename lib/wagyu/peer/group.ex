defmodule Wagyu.Peer.Group do
  @moduledoc false

  # Supervises the two processes of one peer: its sender
  # (`Wagyu.Peer.Sender`) and the peer (`Wagyu.Peer`). The peer supervisor
  # starts one group for each active peer. A group is temporary, the same as
  # a peer was before it had a sender.
  #
  # The two processes live and stop together:
  #
  #   * Both children are temporary and significant. The group uses
  #     `auto_shutdown: :any_significant`. Thus, when one child exits for
  #     any reason, the group stops the other child and then exits.
  #   * The group never restarts a child. The interface starts a new group
  #     when it next needs the peer.
  #
  # The peer needs the pid of its sender. Thus the group starts with no
  # children, and `start_link/2` adds the sender and then the peer. If a
  # child cannot start, the group stops and `start_link/2` returns the error.
  #
  # The interface gets both pids from the start. It sends frames to the peer
  # and monitors it. It stops the group when it stops the peer, because the
  # exit of the peer makes the group stop.

  use Supervisor, restart: :temporary

  alias Wagyu.Config
  alias Wagyu.Peer.Sender

  @spec start_link(Config.t(), map()) :: {:ok, pid(), %{peer: pid(), sender: pid()}} | {:error, term()}
  def start_link(%Config{} = identity, %{peer: %Config.Peer{public_key: public_key}} = args) do
    sender_args = Map.merge(Map.take(args, [:root, :socket, :counters, :outbound]), %{public_key: public_key})

    with {:ok, group} <- Supervisor.start_link(__MODULE__, :ok) do
      with {:ok, sender} <- Supervisor.start_child(group, child(Sender, :start_link, [sender_args])),
           {:ok, peer} <-
             Supervisor.start_child(group, child(Wagyu.Peer, :start_link, [identity, Map.put(args, :sender, sender)])) do
        {:ok, group, %{peer: peer, sender: sender}}
      else
        error ->
          Supervisor.stop(group)
          error
      end
    end
  end

  @impl true
  def init(:ok), do: Supervisor.init([], strategy: :one_for_all, auto_shutdown: :any_significant)

  defp child(module, function, args),
    do: %{id: module, start: {module, function, args}, restart: :temporary, significant: true}
end
