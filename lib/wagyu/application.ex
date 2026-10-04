defmodule Wagyu.Application do
  @moduledoc false

  use Application

  # The application runs only the registry. The processes of each interface
  # use the registry to find one another. The interfaces run in the
  # supervision trees of their callers.
  @impl true
  def start(_type, _args) do
    Supervisor.start_link([Wagyu.Registry], strategy: :one_for_one, name: Wagyu.Supervisor)
  end
end
