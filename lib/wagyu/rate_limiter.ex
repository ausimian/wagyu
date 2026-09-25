defmodule Wagyu.RateLimiter do
  @moduledoc false

  # Per-source budgets for handshake messages under load, as in wireguard-go
  # and Linux: a token bucket for each IPv4 address or IPv6 /64, which
  # allows 20 messages a second in bursts of up to 5. Only messages with a
  # valid MAC2 reach it, so each source has shown it receives at its
  # address.
  #
  # The table is bounded. A source idle for a second has a full bucket, the
  # same as one with no entry, so when the table is full such entries are
  # dropped, at most once a second so that a full table of active sources
  # costs no scan per message. A new source that still does not fit is
  # refused, failing closed.
  #
  # Tokens are milliseconds of `now`, the caller's monotonic clock.

  # Each message costs 1/20 s, and a bucket holds 5 of them.
  @cost 50
  @max_tokens 5 * @cost
  @idle 1_000
  @max_sources 4096

  defstruct entries: %{}, pruned_at: nil, max_sources: @max_sources

  @type t :: %__MODULE__{
          entries: %{term() => {non_neg_integer(), integer()}},
          pruned_at: integer() | nil,
          max_sources: pos_integer()
        }

  @spec new(keyword()) :: t()
  def new(options \\ []), do: struct!(__MODULE__, options)

  @doc """
  Takes one message's cost from the bucket for `address` at `now`. Returns
  `{:ok, limiter}` when it had enough, and `{:limited, limiter}` when it did
  not or the table has no room for a new source.
  """
  @spec allow(t(), :inet.ip_address(), integer()) :: {:ok | :limited, t()}
  def allow(%__MODULE__{entries: entries} = limiter, address, now) do
    key = key(address)

    case entries do
      %{^key => {tokens, last}} ->
        tokens = min(tokens + now - last, @max_tokens)

        if tokens >= @cost,
          do: {:ok, put(limiter, key, tokens - @cost, now)},
          else: {:limited, put(limiter, key, tokens, now)}

      _new ->
        limiter = if map_size(entries) >= limiter.max_sources, do: prune(limiter, now), else: limiter

        if map_size(limiter.entries) < limiter.max_sources,
          do: {:ok, put(limiter, key, @max_tokens - @cost, now)},
          else: {:limited, limiter}
    end
  end

  defp put(limiter, key, tokens, now), do: %{limiter | entries: Map.put(limiter.entries, key, {tokens, now})}

  defp prune(%__MODULE__{pruned_at: pruned_at} = limiter, now) when is_integer(pruned_at) and now - pruned_at < @idle,
    do: limiter

  defp prune(limiter, now) do
    entries = Map.reject(limiter.entries, fn {_key, {_tokens, last}} -> now - last >= @idle end)
    %{limiter | entries: entries, pruned_at: now}
  end

  defp key({_a, _b, _c, _d} = address), do: address
  defp key({a, b, c, d, _e, _f, _g, _h}), do: {:inet6, a, b, c, d}
end
