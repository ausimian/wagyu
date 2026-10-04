defmodule Wagyu.Registry do
  @moduledoc false

  # The processes of each interface find one another here. The key is the
  # root supervisor of the interface and a role. The processes do not use
  # PIDs that they captured when they started. A restarted process registers
  # again, and the other processes find it on their next lookup.
  #
  # The value of a registration contains the data that other processes need
  # to communicate with its owner. This data is the admission bounds of its
  # mailbox and its shared counters.

  @type role :: :link | :interface | :handshake_supervisor | :peer_supervisor

  @spec child_spec(term()) :: Supervisor.child_spec()
  def child_spec(_arg), do: Registry.child_spec(keys: :unique, name: __MODULE__)

  @doc "Registers the calling process as the `role` of `root`."
  @spec register(term(), role(), term()) :: :ok
  def register(root, role, value \\ nil) do
    {:ok, _owner} = Registry.register(__MODULE__, {root, role}, value)
    :ok
  end

  @doc "Returns a name that registers a process as the `role` of `root` when it starts."
  @spec via(term(), role()) :: {:via, Registry, {module(), {term(), role()}}}
  def via(root, role), do: {:via, Registry, {__MODULE__, {root, role}}}

  @doc """
  Returns `{:ok, pid, value}` for the live process registered as the `role`
  of `root`, or `:error`.

  The registry removes an entry only after it processes the exit of the
  owner. Thus a lookup soon after an exit can still find the entry. This
  function returns `:error` for a dead owner. It also returns `:error` for
  all lookups while the registry restarts.
  """
  @spec lookup(term(), role()) :: {:ok, pid(), term()} | :error
  def lookup(root, role) do
    case Registry.lookup(__MODULE__, {root, role}) do
      [{pid, value}] -> if Process.alive?(pid), do: {:ok, pid, value}, else: :error
      [] -> :error
    end
  rescue
    # The registry is not running.
    ArgumentError -> :error
  end
end
