defmodule Wagyu.Registry do
  @moduledoc false

  # Each interface's processes find one another here, keyed by the
  # interface's root supervisor and a role, rather than through PIDs captured
  # when they started. A restarted process registers afresh, and the others
  # reach it on their next lookup.
  #
  # A registration's value carries what other processes need to talk to its
  # owner: the admission bounds of its mailbox and its shared counters.

  @type role :: :root | :link | :interface | :handshake_supervisor | :peer_supervisor

  @spec child_spec(term()) :: Supervisor.child_spec()
  def child_spec(_arg), do: Registry.child_spec(keys: :unique, name: __MODULE__)

  @doc "Registers the calling process as `root`'s `role`."
  @spec register(term(), role(), term()) :: :ok
  def register(root, role, value \\ nil) do
    {:ok, _owner} = Registry.register(__MODULE__, {root, role}, value)
    :ok
  end

  @doc "A name that registers a process as `root`'s `role` when it starts."
  @spec via(term(), role()) :: {:via, Registry, {module(), {term(), role()}}}
  def via(root, role), do: {:via, Registry, {__MODULE__, {root, role}}}

  @doc """
  Returns `{:ok, pid, value}` for the live process registered as `root`'s
  `role`, or `:error`.

  The registry removes an entry only once it has processed its owner's exit,
  so a lookup soon after an exit can still find the entry; a dead owner is
  reported as `:error`.
  """
  @spec lookup(term(), role()) :: {:ok, pid(), term()} | :error
  def lookup(root, role) do
    case Registry.lookup(__MODULE__, {root, role}) do
      [{pid, value}] -> if Process.alive?(pid), do: {:ok, pid, value}, else: :error
      [] -> :error
    end
  end
end
