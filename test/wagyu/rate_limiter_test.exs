defmodule Wagyu.RateLimiterTest do
  use ExUnit.Case, async: true

  alias Wagyu.RateLimiter

  # Runs `allow/3` for each address at `now`, returning the results in order.
  defp allow_all(limiter, addresses, now) do
    Enum.map_reduce(addresses, limiter, fn address, limiter ->
      {result, limiter} = RateLimiter.allow(limiter, address, now)
      {result, limiter}
    end)
  end

  test "a source may send a burst of 5, then one every 50 ms" do
    address = {192, 0, 2, 1}
    {results, limiter} = allow_all(RateLimiter.new(), List.duplicate(address, 7), 0)
    assert results == [:ok, :ok, :ok, :ok, :ok, :limited, :limited]

    assert {:limited, limiter} = RateLimiter.allow(limiter, address, 49)
    assert {:ok, limiter} = RateLimiter.allow(limiter, address, 50)
    assert {:limited, limiter} = RateLimiter.allow(limiter, address, 50)

    # An idle source refills to a burst of 5, never more.
    {results, _limiter} = allow_all(limiter, List.duplicate(address, 6), 10_000)
    assert results == [:ok, :ok, :ok, :ok, :ok, :limited]
  end

  test "budgets are per IPv4 address and per IPv6 /64, whatever the port" do
    {results, limiter} = allow_all(RateLimiter.new(), List.duplicate({192, 0, 2, 1}, 5), 0)
    assert Enum.all?(results, &(&1 == :ok))
    assert {:ok, limiter} = RateLimiter.allow(limiter, {192, 0, 2, 2}, 0)

    same_64 = for n <- 1..6, do: {0x2001, 0xDB8, 0, 1, 0, 0, 0, n}
    {results, limiter} = allow_all(limiter, same_64, 0)
    assert results == [:ok, :ok, :ok, :ok, :ok, :limited]
    assert {:ok, limiter} = RateLimiter.allow(limiter, {0x2001, 0xDB8, 0, 2, 0, 0, 0, 1}, 0)

    # An IPv4 address and an IPv6 prefix with the same numbers are distinct.
    {_results, limiter} = allow_all(limiter, List.duplicate({1, 2, 3, 4, 0, 0, 0, 1}, 5), 0)
    assert {:limited, limiter} = RateLimiter.allow(limiter, {1, 2, 3, 4, 0, 0, 0, 2}, 0)
    assert {:ok, _limiter} = RateLimiter.allow(limiter, {1, 2, 3, 4}, 0)
  end

  test "the table is bounded, refusing new sources until idle ones can go" do
    limiter = RateLimiter.new(max_sources: 3)
    {results, limiter} = allow_all(limiter, [{10, 0, 0, 1}, {10, 0, 0, 2}, {10, 0, 0, 3}, {10, 0, 0, 4}], 0)
    assert results == [:ok, :ok, :ok, :limited]
    assert map_size(limiter.entries) == 3

    # Known sources keep their budgets while the table is full.
    assert {:ok, limiter} = RateLimiter.allow(limiter, {10, 0, 0, 1}, 999)

    # A second later the other two are idle and make room. The pruning ran
    # at 0, when nothing was idle, but a second has passed since.
    assert {:ok, limiter} = RateLimiter.allow(limiter, {10, 0, 0, 4}, 1_000)
    assert Map.keys(limiter.entries) |> Enum.sort() == [{10, 0, 0, 1}, {10, 0, 0, 4}]
  end

  test "a full table of active sources is pruned at most once a second" do
    limiter = RateLimiter.new(max_sources: 2)
    {_results, limiter} = allow_all(limiter, [{10, 0, 0, 1}, {10, 0, 0, 2}], 0)
    {_results, limiter} = allow_all(limiter, [{10, 0, 0, 1}, {10, 0, 0, 2}], 999)
    assert {:limited, limiter} = RateLimiter.allow(limiter, {10, 0, 0, 3}, 1_000)
    assert limiter.pruned_at == 1_000

    # Both entries are idle from 1,999, but the next prune waits until 2,000.
    assert {:limited, limiter} = RateLimiter.allow(limiter, {10, 0, 0, 3}, 1_999)
    assert limiter.pruned_at == 1_000
    assert {:ok, limiter} = RateLimiter.allow(limiter, {10, 0, 0, 3}, 2_000)
    assert limiter.pruned_at == 2_000
  end
end
