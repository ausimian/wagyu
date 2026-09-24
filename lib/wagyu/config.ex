defmodule Wagyu.Config do
  @moduledoc """
  Validated configuration for one Wagyu interface.

  `new/1` checks the options accepted by `Wagyu.start_link(options)` and
  returns a `Wagyu.Config` struct, or an error that names the offending
  option. Peers are static: the configuration is validated once and never
  changes while the interface runs.

  ## Options

    * `:private_key` (required) - the interface's 32-byte X25519 private key.
      The matching public key is derived and stored as `:public_key`.

    * `:name` - registers the interface's root supervisor under a standard OTP
      name: an atom, `{:global, term}` or `{:via, module, term}`.

    * `:listen` - the UDP socket's local endpoint, `%{address: address, port:
      port}`, where `port` is in `0..65535` and `0` lets the OS choose.
      Defaults to `%{address: {0, 0, 0, 0}, port: 0}`. The address family
      (IPv4 or IPv6) is the family every peer endpoint must use.

    * `:stack` - a keyword list of SmolNet stack options:

      * `:addresses` - at most 8 interface addresses, as `{address,
        prefix_length}`. Defaults to `[]`.
      * `:routes` - at most 4 routes, as `{destination, prefix_length,
        gateway}`, where the gateway has the destination's family.
        Destinations are normalized. Defaults to `[]`.
      * `:mtu` - the stack's MTU, from 1280 to 65,475. Transport plaintext is
        padded to a multiple of 16 bytes but never beyond the MTU, so a
        full-size packet plus WireGuard's 32 bytes of framing and tag still
        fits the largest IPv4 UDP payload (65,507 bytes). Defaults to 1420, as
        in wg-quick.

      Wagyu sets SmolNet's `:egress`, `:limits` and `:link_down` options
      itself, so passing them is an error. Addresses and routes follow
      SmolNet's own checks, so a configuration that passes here is one
      SmolNet accepts: no multicast or IPv4-mapped IPv6 addresses, no IPv4
      broadcast interface address or gateway, and no unspecified gateway.

    * `:peers` - at most 1024 peer maps, each with:

      * `:public_key` (required) - the peer's 32-byte X25519 public key,
        distinct from every other peer's and from the interface's own.
      * `:endpoint` - `%{address: address, port: port}` with `port` in
        `1..65535`, a specified address, and the listen address's family.
        Omit it (or pass `nil`) when the peer always initiates, so that this
        interface only responds to it.
      * `:allowed_ips` - the `{address, prefix_length}` prefixes the peer may
        send from and that route to it. Host bits are cleared. Nested prefixes
        are allowed and the longest match wins, but an exact prefix may appear
        only once across all peers. Defaults to `[]`.
      * `:preshared_key` - omit it for no preshared key, which the protocol
        treats as 32 zero bytes. An explicit 32 zero bytes is accepted too.
        Any nonzero key fails with `{:error, :unsupported_preshared_key}`
        rather than being silently replaced by zeros. `nil` is rejected as
        `:invalid` rather than treated as omitted, so an unset variable
        cannot quietly disable a key.

  Unknown or repeated options fail validation at every level.

  ## Errors

  `new/1` returns `{:error, :unsupported_preshared_key}` for a nonzero
  preshared key and otherwise `{:error, {:invalid_option, path, reason}}`.
  `path` locates the option, with list positions as zero-based indices, for
  example `[:peers, 1, :allowed_ips, 0]`. Errors never contain option values,
  so they are safe to log. `reason` is one of:

    * `:missing` - a required option is absent
    * `:unknown` - an unrecognized option
    * `:reserved` - a stack option that Wagyu sets itself
    * `:invalid` - the wrong type or shape
    * `:invalid_length` - a key that is not exactly 32 bytes
    * `:out_of_range` - a port or MTU outside its range
    * `:too_many` - more addresses, routes or peers than allowed
    * `:family_mismatch` - an endpoint or gateway in the wrong address family
    * `:duplicate` - a repeated option, public key, address, route or prefix
    * `:local_key` - a peer public key equal to the interface's own

  ## Secrets

  The struct's `Inspect` implementation omits the private key and preshared
  keys, so `inspect/2` with its default options, and anything else that
  formats the struct through `Inspect`, does not show them. The redaction
  lives only in that implementation: `inspect(config, structs: false)`,
  Erlang's own term formatting (`~p`) and direct field access all bypass it
  and expose the keys. Don't rely on it when logging a configuration any
  other way.
  """

  import Bitwise

  alias Wagyu.AllowedIPs
  alias Wagyu.Config.Peer
  alias Wagyu.IP

  @options [:name, :private_key, :listen, :stack, :peers]
  @stack_options [:addresses, :routes, :mtu]
  @reserved_stack_options [:egress, :limits, :link_down]
  @peer_options [:public_key, :endpoint, :allowed_ips, :preshared_key]
  @endpoint_options [:address, :port]

  @default_listen %{address: {0, 0, 0, 0}, port: 0}
  @default_mtu 1420
  # 65,535 less the IPv4 and UDP headers (28) and the transport header and
  # tag (32). Padding is capped at the MTU, so it adds nothing at the limit.
  @mtu_range 1280..65_475
  @max_addresses 8
  @max_routes 4
  @max_peers 1024
  @zero_key <<0::256>>

  @derive {Inspect, except: [:private_key]}
  @enforce_keys [:private_key, :public_key]
  defstruct [
    :name,
    :private_key,
    :public_key,
    listen: @default_listen,
    stack: [addresses: [], routes: [], mtu: @default_mtu],
    peers: %{},
    allowed_ips: %AllowedIPs{}
  ]

  @typedoc "A validated interface configuration. `:peers` maps each public key to its peer."
  @type t :: %__MODULE__{
          name: atom() | {:global, term()} | {:via, module(), term()} | nil,
          private_key: <<_::256>>,
          public_key: <<_::256>>,
          listen: %{address: :inet.ip_address(), port: :inet.port_number()},
          stack: [
            addresses: [{:inet.ip_address(), non_neg_integer()}],
            routes: [{:inet.ip_address(), non_neg_integer(), :inet.ip_address()}],
            mtu: pos_integer()
          ],
          peers: %{optional(<<_::256>>) => Peer.t()},
          allowed_ips: AllowedIPs.t()
        }

  @typedoc "The location of an invalid option."
  @type path :: [atom() | non_neg_integer()]

  @type reason ::
          :missing
          | :unknown
          | :reserved
          | :invalid
          | :invalid_length
          | :out_of_range
          | :too_many
          | :family_mismatch
          | :duplicate
          | :local_key

  @type error :: :unsupported_preshared_key | {:invalid_option, path(), reason()}

  @doc """
  Validates interface options.

  ## Examples

      iex> {:ok, config} = Wagyu.Config.new(private_key: :binary.copy(<<1>>, 32))
      iex> config.stack
      [addresses: [], routes: [], mtu: 1420]

      iex> Wagyu.Config.new(private_key: <<1, 2, 3>>)
      {:error, {:invalid_option, [:private_key], :invalid_length}}
  """
  @spec new(keyword()) :: {:ok, t()} | {:error, error()}
  def new(options) do
    with :ok <- keyword(options, [], @options),
         {:ok, name} <- name(Keyword.get(options, :name)),
         {:ok, private_key} <- private_key(Keyword.fetch(options, :private_key)),
         public_key = public_key(private_key),
         {:ok, listen} <- listen(Keyword.get(options, :listen, @default_listen)),
         {:ok, listen_family} <- family(listen.address),
         {:ok, stack} <- stack(Keyword.get(options, :stack, [])),
         {:ok, peers} <- peers(Keyword.get(options, :peers, []), listen_family, public_key),
         {:ok, allowed_ips} <- allowed_ips(peers) do
      {:ok,
       %__MODULE__{
         name: name,
         private_key: private_key,
         public_key: public_key,
         listen: listen,
         stack: stack,
         peers: Map.new(peers, &{&1.public_key, &1}),
         allowed_ips: allowed_ips
       }}
    end
  end

  @doc """
  Looks up a configured peer by public key.

  Only configured keys may create peer state, so an unknown key returns
  `{:error, :unknown_peer}`.
  """
  @spec fetch_peer(t(), term()) :: {:ok, Peer.t()} | {:error, :unknown_peer}
  def fetch_peer(%__MODULE__{peers: peers}, public_key) do
    case Map.fetch(peers, public_key) do
      {:ok, _peer} = found -> found
      :error -> {:error, :unknown_peer}
    end
  end

  # Top level

  defp name(nil), do: {:ok, nil}
  defp name(name) when is_atom(name), do: {:ok, name}
  defp name({:global, _term} = name), do: {:ok, name}
  defp name({:via, module, _term} = name) when is_atom(module), do: {:ok, name}
  defp name(_name), do: invalid([:name], :invalid)

  defp private_key(:error), do: invalid([:private_key], :missing)
  defp private_key({:ok, key}), do: key(key, [:private_key])

  defp public_key(private_key) do
    {public_key, _private_key} = :crypto.generate_key(:ecdh, :x25519, private_key)
    public_key
  end

  defp listen(value) do
    path = [:listen]

    with :ok <- map(value, path, @endpoint_options, @endpoint_options),
         {:ok, _family} <- address(value.address, path ++ [:address]),
         :ok <- port(value.port, 0, path ++ [:port]) do
      {:ok, value}
    end
  end

  # Stack

  defp stack(options) do
    with :ok <- keyword(options, [:stack], @stack_options, @reserved_stack_options),
         {:ok, addresses} <- stack_addresses(Keyword.get(options, :addresses, [])),
         {:ok, routes} <- stack_routes(Keyword.get(options, :routes, [])),
         {:ok, mtu} <- mtu(Keyword.get(options, :mtu, @default_mtu)) do
      {:ok, [addresses: addresses, routes: routes, mtu: mtu]}
    end
  end

  defp stack_addresses(addresses) do
    path = [:stack, :addresses]

    with :ok <- list(addresses, path, @max_addresses),
         {:ok, addresses} <- map_indexed(addresses, path, fn address, _path -> stack_address(address) end),
         :ok <- unique(Enum.map(addresses, &elem(&1, 0)), &(path ++ [&1])) do
      {:ok, addresses}
    end
  end

  defp stack_address({address, length}) do
    with {:ok, bits} <- prefix_length(address, length),
         true <- smolnet_address?(address, bits) and not broadcast?(address) do
      {:ok, {address, length}}
    else
      _invalid -> :error
    end
  end

  defp stack_address(_address), do: :error

  defp stack_routes(routes) do
    path = [:stack, :routes]

    with :ok <- list(routes, path, @max_routes),
         {:ok, routes} <- map_indexed(routes, path, &stack_route/2),
         destinations = Enum.map(routes, fn {destination, length, _gateway} -> {destination, length} end),
         :ok <- unique(destinations, &(path ++ [&1])) do
      {:ok, routes}
    end
  end

  defp stack_route({destination, length, gateway}, path) do
    with {:ok, destination_bits} <- prefix_length(destination, length),
         {:ok, gateway_bits} <- family(gateway),
         {:same_family, true} <- {:same_family, destination_bits == gateway_bits},
         true <- smolnet_address?(destination, destination_bits),
         true <- smolnet_address?(gateway, gateway_bits) and not broadcast?(gateway) and not unspecified?(gateway) do
      {:ok, {normalized, ^length}} = AllowedIPs.normalize({destination, length})
      {:ok, {normalized, length, gateway}}
    else
      {:same_family, false} -> invalid(path, :family_mismatch)
      _invalid -> invalid(path, :invalid)
    end
  end

  defp stack_route(_route, path), do: invalid(path, :invalid)

  # SmolNet rejects IPv4-mapped IPv6 addresses and multicast addresses
  # anywhere in its address and route configuration. Its multicast test looks
  # only at the first byte (0xFF, or 224 to 239) in either family, and this
  # mirrors it exactly so that validation here never passes an address that
  # SmolNet would refuse.
  defp smolnet_address?(address, bits) do
    {:ok, value, ^bits} = IP.to_integer(address)
    first_byte = value >>> (bits - 8)
    first_byte != 0xFF and first_byte not in 224..239 and not ipv4_mapped?(address)
  end

  defp mtu(mtu) when is_integer(mtu) and mtu in @mtu_range, do: {:ok, mtu}
  defp mtu(mtu) when is_integer(mtu), do: invalid([:stack, :mtu], :out_of_range)
  defp mtu(_mtu), do: invalid([:stack, :mtu], :invalid)

  # Peers

  defp peers(peers, listen_family, local_key) do
    with :ok <- list(peers, [:peers], @max_peers),
         {:ok, peers} <- map_indexed(peers, [:peers], &peer(&1, &2, listen_family, local_key)),
         :ok <- unique(Enum.map(peers, & &1.public_key), &[:peers, &1, :public_key]) do
      {:ok, peers}
    end
  end

  defp peer(value, path, listen_family, local_key) do
    with :ok <- map(value, path, @peer_options, [:public_key]),
         {:ok, public_key} <- peer_public_key(value.public_key, path ++ [:public_key], local_key),
         {:ok, endpoint} <- endpoint(Map.get(value, :endpoint), path ++ [:endpoint], listen_family),
         {:ok, allowed_ips} <- peer_allowed_ips(Map.get(value, :allowed_ips, []), path ++ [:allowed_ips]),
         {:ok, preshared_key} <- preshared_key(Map.fetch(value, :preshared_key), path ++ [:preshared_key]) do
      {:ok, %Peer{public_key: public_key, endpoint: endpoint, allowed_ips: allowed_ips, preshared_key: preshared_key}}
    end
  end

  defp peer_public_key(value, path, local_key) do
    case key(value, path) do
      {:ok, ^local_key} -> invalid(path, :local_key)
      result -> result
    end
  end

  defp endpoint(nil, _path, _listen_family), do: {:ok, nil}

  defp endpoint(value, path, listen_family) do
    with :ok <- map(value, path, @endpoint_options, @endpoint_options),
         {:ok, family} <- address(value.address, path ++ [:address]),
         :ok <- endpoint_address(value.address, family, listen_family, path ++ [:address]),
         :ok <- port(value.port, 1, path ++ [:port]) do
      {:ok, value}
    end
  end

  defp endpoint_address(_address, family, listen_family, path) when family != listen_family,
    do: invalid(path, :family_mismatch)

  defp endpoint_address(address, _family, _listen_family, path) do
    if unspecified?(address), do: invalid(path, :invalid), else: :ok
  end

  defp peer_allowed_ips(prefixes, path) do
    if proper_list?(prefixes),
      do: map_indexed(prefixes, path, fn prefix, _path -> AllowedIPs.normalize(prefix) end),
      else: invalid(path, :invalid)
  end

  # An omitted preshared key is the protocol's all-zero key. A nonzero key is
  # an explicit error until preshared keys are supported: it must never fall
  # back to zero. `nil` is rejected too, because an unset variable that was
  # meant to hold a key would otherwise silently disable it.
  defp preshared_key(:error, _path), do: {:ok, @zero_key}
  defp preshared_key({:ok, @zero_key}, _path), do: {:ok, @zero_key}
  defp preshared_key({:ok, <<_::binary-32>>}, _path), do: {:error, :unsupported_preshared_key}
  defp preshared_key({:ok, value}, path), do: key(value, path)

  # Every exact prefix may appear once across all peers.
  defp allowed_ips(peers) do
    entries =
      for {peer, index} <- Enum.with_index(peers), {prefix, prefix_index} <- Enum.with_index(peer.allowed_ips) do
        {prefix, peer.public_key, [:peers, index, :allowed_ips, prefix_index]}
      end

    with :ok <- unique(Enum.map(entries, &elem(&1, 0)), &(entries |> Enum.at(&1) |> elem(2))) do
      entries
      |> Enum.map(fn {prefix, public_key, _path} -> {prefix, public_key} end)
      |> AllowedIPs.new()
    end
  end

  # Shared validators

  defp keyword(options, path, allowed, reserved \\ []) do
    if Keyword.keyword?(options) do
      keys = Keyword.keys(options)

      case Enum.find(keys, &(&1 not in allowed)) do
        nil -> unique(keys, &(path ++ [Enum.at(keys, &1)]))
        key -> invalid(path ++ [key], unknown_reason(key, reserved))
      end
    else
      invalid(path, :invalid)
    end
  end

  defp unknown_reason(key, reserved), do: if(key in reserved, do: :reserved, else: :unknown)

  defp map(value, path, allowed, required) when is_map(value) and not is_struct(value) do
    case {Enum.find(Map.keys(value), &(&1 not in allowed)), Enum.find(required, &(not Map.has_key?(value, &1)))} do
      {nil, nil} -> :ok
      {nil, key} -> invalid(path ++ [key], :missing)
      {key, _missing} -> invalid(path ++ [key], :unknown)
    end
  end

  defp map(_value, path, _allowed, _required), do: invalid(path, :invalid)

  defp list(value, path, max) do
    cond do
      not proper_list?(value) -> invalid(path, :invalid)
      length(value) > max -> invalid(path, :too_many)
      true -> :ok
    end
  end

  defp proper_list?([]), do: true
  defp proper_list?([_head | tail]), do: proper_list?(tail)
  defp proper_list?(_value), do: false

  # Validates each item in order and stops at the first error. A validator
  # returns `:error` for an item that is simply invalid at its own path.
  defp map_indexed(items, path, validate) do
    items
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, []}, fn {item, index}, {:ok, acc} ->
      case validate.(item, path ++ [index]) do
        {:ok, value} -> {:cont, {:ok, [value | acc]}}
        :error -> {:halt, invalid(path ++ [index], :invalid)}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, values} -> {:ok, Enum.reverse(values)}
      {:error, _reason} = error -> error
    end
  end

  # Fails at `path_for.(index)` for the first key that repeats an earlier one.
  defp unique(keys, path_for) do
    keys
    |> Enum.with_index()
    |> Enum.reduce_while(MapSet.new(), fn {key, index}, seen ->
      if MapSet.member?(seen, key),
        do: {:halt, invalid(path_for.(index), :duplicate)},
        else: {:cont, MapSet.put(seen, key)}
    end)
    |> case do
      {:error, _reason} = error -> error
      _seen -> :ok
    end
  end

  defp key(<<_::binary-32>> = key, _path), do: {:ok, key}
  defp key(key, path) when is_binary(key), do: invalid(path, :invalid_length)
  defp key(_key, path), do: invalid(path, :invalid)

  defp address(address, path) do
    case family(address) do
      {:ok, _bits} = ok -> ok
      :error -> invalid(path, :invalid)
    end
  end

  defp prefix_length(address, length) when is_integer(length) do
    case family(address) do
      {:ok, bits} when length >= 0 and length <= bits -> {:ok, bits}
      _invalid -> :error
    end
  end

  defp prefix_length(_address, _length), do: :error

  defp family(address) do
    case IP.to_integer(address) do
      {:ok, _value, bits} -> {:ok, bits}
      :error -> :error
    end
  end

  defp port(port, min, _path) when is_integer(port) and port >= min and port <= 65_535, do: :ok
  defp port(port, _min, path) when is_integer(port), do: invalid(path, :out_of_range)
  defp port(_port, _min, path), do: invalid(path, :invalid)

  defp unspecified?(address), do: address |> Tuple.to_list() |> Enum.all?(&(&1 == 0))
  defp broadcast?(address), do: address == {255, 255, 255, 255}
  defp ipv4_mapped?(address), do: match?({0, 0, 0, 0, 0, 0xFFFF, _g, _h}, address)

  defp invalid(path, reason), do: {:error, {:invalid_option, path, reason}}
end
