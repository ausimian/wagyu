defmodule Wagyu.IndexTableTest do
  use ExUnit.Case, async: true

  alias Wagyu.IndexTable

  # A random source that yields `values` in order, one per call.
  defp scripted(values) do
    source = :counters.new(1, [])
    values = List.to_tuple(values)

    fn ->
      :ok = :counters.add(source, 1, 1)
      elem(values, :counters.get(source, 1) - 1)
    end
  end

  test "allocates random 32-bit indices, each mapped to its owner" do
    {indices, table} =
      Enum.map_reduce(1..100, IndexTable.new(), fn n, table -> IndexTable.allocate(table, {:peer, rem(n, 2)}) end)

    assert length(Enum.uniq(indices)) == 100
    assert Enum.all?(indices, &(&1 in 0..0xFFFFFFFF))
    assert MapSet.size(IndexTable.owned(table, {:peer, 0})) == 50
    assert IndexTable.lookup(table, hd(indices)) == {:active, {:peer, 1}}
  end

  test "never allocates an active or tombstoned index" do
    random = scripted([7, 8, 7, 8, 9, 7, 8, 9, 10])
    table = IndexTable.new()

    {7, table} = IndexTable.allocate(table, :a, random)
    {8, table} = IndexTable.allocate(table, :a, random)
    table = IndexTable.retire(table, 8, 0)

    # 7 is active and 8 a tombstone, so both are skipped.
    assert {9, table} = IndexTable.allocate(table, :b, random)

    # Just before the tombstone expires, 8 is still refused.
    table = IndexTable.expire(table, IndexTable.retention() - 1)
    assert {10, _table} = IndexTable.allocate(table, :b, random)
  end

  test "an index moves from active to tombstone to deleted" do
    {index, table} = IndexTable.allocate(IndexTable.new(), :a, scripted([42, 42]))
    assert IndexTable.lookup(table, index) == {:active, :a}

    table = IndexTable.retire(table, index, 1_000)
    assert IndexTable.lookup(table, index) == :retired
    assert IndexTable.owned(table, :a) == MapSet.new()
    assert IndexTable.next_expiry(table) == 1_000 + 180_000

    table = IndexTable.expire(table, 1_000 + 179_999)
    assert IndexTable.lookup(table, index) == :retired

    table = IndexTable.expire(table, 1_000 + 180_000)
    assert IndexTable.lookup(table, index) == :unknown
    assert IndexTable.next_expiry(table) == nil

    # Once it has expired, the value may be allocated again.
    assert {42, _table} = IndexTable.allocate(table, :b, scripted([42]))
  end

  test "retiring an owner tombstones every index it holds and no other" do
    random = scripted([1, 2, 3, 4])
    {_one, table} = IndexTable.allocate(IndexTable.new(), :a, random)
    {_two, table} = IndexTable.allocate(table, :b, random)
    {_three, table} = IndexTable.allocate(table, :a, random)
    {_four, table} = IndexTable.allocate(table, :a, random)
    table = IndexTable.retire(table, 4, 0)

    table = IndexTable.retire_owner(table, :a, 10)

    assert Enum.map(1..4, &IndexTable.lookup(table, &1)) == [:retired, {:active, :b}, :retired, :retired]
    assert IndexTable.owned(table, :a) == MapSet.new()

    # Each tombstone lasts 180 seconds from its own retirement.
    table = IndexTable.expire(table, 180_000)
    assert Enum.map(1..4, &IndexTable.lookup(table, &1)) == [:retired, {:active, :b}, :retired, :unknown]

    table = IndexTable.expire(table, 180_010)
    assert Enum.map(1..4, &IndexTable.lookup(table, &1)) == [:unknown, {:active, :b}, :unknown, :unknown]
  end

  test "retiring an index that is not active changes nothing" do
    {index, table} = IndexTable.allocate(IndexTable.new(), :a, scripted([5]))
    retired = IndexTable.retire(table, index, 0)

    assert IndexTable.retire(table, 6, 0) == table
    assert IndexTable.retire(retired, index, 50) == retired
    assert IndexTable.retire_owner(table, :nobody, 0) == table
  end
end
