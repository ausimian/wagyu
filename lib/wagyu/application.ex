defmodule Wagyu.Application do
  @moduledoc false

  use Application

  # The application runs only the registry that each interface's processes
  # use to find one another. Interfaces themselves run in their callers'
  # supervision trees.
  @impl true
  def start(_type, _args) do
    Supervisor.start_link([Wagyu.Registry], strategy: :one_for_one, name: Wagyu.Supervisor)
  end
end
