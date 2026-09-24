defmodule Wagyu.AllowedIPs do
  @moduledoc false

  # Immutable longest-prefix-match routing from IP prefixes to peers.
  #
  # Outbound, the destination's longest matching prefix selects the peer to
  # encrypt for. Inbound, a decrypted packet is accepted only if its source's
  # longest matching prefix belongs to the peer that decrypted it. Both
  # directions use the same lookup, so they cannot disagree.
  #
  # Prefixes are normalized by clearing host bits. Nested prefixes are allowed
  # and the most specific wins; the same exact prefix twice is rejected rather
  # than silently reassigned. Each family is a list of `{length, networks}`
  # pairs, longest first, where `networks` maps the prefix's network bits to its
  # peer, so a lookup costs one map probe per distinct prefix length.

  import Bitwise

  alias Wagyu.IP

  defstruct ipv4: [], ipv6: []

  @type peer :: term()
  @type prefix :: {:inet.ip_address(), non_neg_integer()}
  @type t :: %__MODULE__{
          ipv4: [{0..32, %{non_neg_integer() => peer()}}],
          ipv6: [{0..128, %{non_neg_integer() => peer()}}]
        }

  @doc """
  Builds a table from `{prefix, peer}` pairs.

  Returns `{:error, {:invalid_prefix, prefix}}` for a malformed prefix and
  `{:error, {:duplicate_prefix, prefix}}` (normalized) when two entries have
  the same exact prefix after normalization.
  """
  @spec new([{prefix(), peer()}]) ::
          {:ok, t()} | {:error, {:invalid_prefix, term()} | {:duplicate_prefix, prefix()}}
  def new(entries) when is_list(entries) do
    entries
    |> Enum.reduce_while({:ok, %{}}, fn entry, {:ok, seen} ->
      case add(seen, entry) do
        {:ok, seen} -> {:cont, {:ok, seen}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, seen} -> {:ok, build(seen)}
      {:error, _reason} = error -> error
    end
  end

  @doc """
  Clears the host bits of an `{address, length}` prefix.

  Returns `:error` for an invalid address or a length outside the family's
  range.
  """
  @spec normalize(term()) :: {:ok, prefix()} | :error
  def normalize({address, length}) when is_integer(length) do
    case IP.to_integer(address) do
      {:ok, value, bits} when length >= 0 and length <= bits ->
        {:ok, {IP.from_integer(network(value, bits, length) <<< (bits - length), bits), length}}

      _invalid ->
        :error
    end
  end

  def normalize(_prefix), do: :error

  @doc """
  Returns `{:ok, peer}` for the longest prefix containing `address`, or
  `:error` when none does or `address` is not an address tuple. Never raises.
  """
  @spec lookup(t(), term()) :: {:ok, peer()} | :error
  def lookup(%__MODULE__{} = table, address) do
    case IP.to_integer(address) do
      {:ok, value, 32} -> find(table.ipv4, value, 32)
      {:ok, value, 128} -> find(table.ipv6, value, 128)
      :error -> :error
    end
  end

  @doc """
  Returns `true` when `source`'s longest matching prefix belongs to `peer`:
  the inbound check on a decrypted packet's source address.
  """
  @spec allowed?(t(), term(), peer()) :: boolean()
  def allowed?(%__MODULE__{} = table, source, peer), do: lookup(table, source) == {:ok, peer}

  @doc "Returns the table's `{prefix, peer}` pairs, IPv4 first, longest prefix first."
  @spec to_list(t()) :: [{prefix(), peer()}]
  def to_list(%__MODULE__{ipv4: ipv4, ipv6: ipv6}), do: entries(ipv4, 32) ++ entries(ipv6, 128)

  defp add(seen, {prefix, peer}) do
    case normalize(prefix) do
      {:ok, {address, length} = normalized} ->
        {:ok, value, bits} = IP.to_integer(address)
        key = {bits, length, network(value, bits, length)}

        if Map.has_key?(seen, key),
          do: {:error, {:duplicate_prefix, normalized}},
          else: {:ok, Map.put(seen, key, peer)}

      :error ->
        {:error, {:invalid_prefix, prefix}}
    end
  end

  defp add(_seen, entry), do: {:error, {:invalid_prefix, entry}}

  # Groups the validated entries by family and prefix length, longest first.
  defp build(seen) do
    tables =
      Enum.reduce(seen, %{}, fn {{bits, length, network}, peer}, tables ->
        Map.update(tables, {bits, length}, %{network => peer}, &Map.put(&1, network, peer))
      end)

    %__MODULE__{ipv4: family(tables, 32), ipv6: family(tables, 128)}
  end

  defp family(tables, bits) do
    tables
    |> Enum.flat_map(fn
      {{^bits, length}, networks} -> [{length, networks}]
      _other_family -> []
    end)
    |> Enum.sort_by(&elem(&1, 0), :desc)
  end

  defp find([], _value, _bits), do: :error

  defp find([{length, networks} | rest], value, bits) do
    case Map.fetch(networks, network(value, bits, length)) do
      {:ok, _peer} = found -> found
      :error -> find(rest, value, bits)
    end
  end

  defp network(value, bits, length), do: value >>> (bits - length)

  defp entries(family, bits) do
    for {length, networks} <- family, {network, peer} <- Enum.sort(networks) do
      {{IP.from_integer(network <<< (bits - length), bits), length}, peer}
    end
  end
end
