defmodule Wagyu.IndexTable do
  @moduledoc false

  # The interface's local receiver indices.
  #
  # Every handshake and key slot a peer holds is addressed on the wire by a
  # 32-bit index that this interface chose: the remote party puts it in the
  # receiver field of each response, cookie reply and transport message it
  # sends back. Indices are random and unique, so an off-path sender cannot
  # guess a live one, and each maps to the peer process that owns it.
  #
  # An index is active until its owner retires it or exits. It then becomes
  # a drop-only tombstone for 180 seconds, so that delayed messages for the
  # old slot are dropped rather than reaching a new owner, and only then is
  # it deleted. Neither an active nor a tombstoned value is ever allocated
  # again.
  #
  # The table is a pure data structure. Time is passed in, in monotonic
  # milliseconds, so retirement and expiry can be tested with a fake clock.
  # Times must not decrease from one call to the next: tombstones expire in
  # the order they were made.

  @retention 180_000

  @enforce_keys [:expiry]
  defstruct [:expiry, active: %{}, owners: %{}, retired: %{}]

  @type index :: 0..0xFFFFFFFF
  @type owner :: term()

  @type t :: %__MODULE__{
          active: %{optional(index()) => owner()},
          owners: %{optional(owner()) => MapSet.t(index())},
          retired: %{optional(index()) => integer()},
          expiry: :queue.queue({integer(), index()})
        }

  @spec new() :: t()
  def new, do: %__MODULE__{expiry: :queue.new()}

  @doc "How long a retired index stays a tombstone, in milliseconds."
  @spec retention() :: pos_integer()
  def retention, do: @retention

  @doc """
  Allocates a random index for `owner`, never one that is active or
  tombstoned. `random` returns candidate indices; tests supply their own.
  """
  @spec allocate(t(), owner(), (-> index())) :: {index(), t()}
  def allocate(%__MODULE__{} = table, owner, random \\ &random/0) do
    index = random.()

    if Map.has_key?(table.active, index) or Map.has_key?(table.retired, index) do
      allocate(table, owner, random)
    else
      owners = Map.update(table.owners, owner, MapSet.new([index]), &MapSet.put(&1, index))
      {index, %{table | active: Map.put(table.active, index, owner), owners: owners}}
    end
  end

  @doc "Returns `{:active, owner}`, `:retired` for a tombstone, or `:unknown`."
  @spec lookup(t(), term()) :: {:active, owner()} | :retired | :unknown
  def lookup(%__MODULE__{} = table, index) do
    case table.active do
      %{^index => owner} -> {:active, owner}
      _active -> if Map.has_key?(table.retired, index), do: :retired, else: :unknown
    end
  end

  @doc "Returns the indices active for `owner`."
  @spec owned(t(), owner()) :: MapSet.t(index())
  def owned(%__MODULE__{} = table, owner), do: Map.get(table.owners, owner, MapSet.new())

  @doc "Retires an active index at time `now`. Anything else is left alone."
  @spec retire(t(), term(), integer()) :: t()
  def retire(%__MODULE__{} = table, index, now) do
    case Map.pop(table.active, index) do
      {nil, _active} ->
        table

      {owner, active} ->
        owned = table.owners |> Map.fetch!(owner) |> MapSet.delete(index)

        owners =
          if MapSet.size(owned) == 0, do: Map.delete(table.owners, owner), else: Map.put(table.owners, owner, owned)

        tombstone(%{table | active: active, owners: owners}, index, now)
    end
  end

  @doc "Retires every index `owner` holds, at time `now`."
  @spec retire_owner(t(), owner(), integer()) :: t()
  def retire_owner(%__MODULE__{} = table, owner, now) do
    {owned, owners} = Map.pop(table.owners, owner, MapSet.new())
    table = %{table | active: Map.drop(table.active, MapSet.to_list(owned)), owners: owners}
    Enum.reduce(Enum.sort(owned), table, &tombstone(&2, &1, now))
  end

  @doc "Deletes the tombstones whose retention has ended by time `now`."
  @spec expire(t(), integer()) :: t()
  def expire(%__MODULE__{} = table, now) do
    case :queue.peek(table.expiry) do
      {:value, {expires_at, index}} when expires_at <= now ->
        expire(%{table | retired: Map.delete(table.retired, index), expiry: :queue.drop(table.expiry)}, now)

      _none_due ->
        table
    end
  end

  @doc "Returns when the oldest tombstone expires, or `nil` if there are none."
  @spec next_expiry(t()) :: integer() | nil
  def next_expiry(%__MODULE__{} = table) do
    case :queue.peek(table.expiry) do
      {:value, {expires_at, _index}} -> expires_at
      :empty -> nil
    end
  end

  defp tombstone(table, index, now) do
    expires_at = now + @retention
    %{table | retired: Map.put(table.retired, index, expires_at), expiry: :queue.in({expires_at, index}, table.expiry)}
  end

  defp random do
    <<index::32>> = :crypto.strong_rand_bytes(4)
    index
  end
end
