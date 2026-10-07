defmodule Wagyu.Config do
  @moduledoc """
  Validated configuration for one Wagyu interface.

  `new/1` validates the options of `Wagyu.start_link/1`. It returns a
  `Wagyu.Config` struct, or an error that identifies the first invalid
  option. `Wagyu.start_link/1` and `Wagyu.child_spec/1` call `new/1` for
  you. Call it yourself only to check options before you start an
  interface.

  `put_peers/2` validates a new peer set against a configuration. `new/1`
  uses it for the `:peers` option. `Wagyu.replace_peers/2` applies the same
  checks to the peer set of a running interface.

  ## Options

    * `:private_key` (required) - the X25519 private key of the interface,
      as a raw 32-byte binary. To decode a key from `wg genkey`, use
      `Base.decode64!/1`. Wagyu derives the public key from this key.

    * `:name` - a name for the registration of the interface: an atom,
      `{:global, term}` or `{:via, module, term}`.

    * `:listen` - the local address and port of the UDP socket of the
      interface, as `%{address: address, port: port}`. If the port is `0`,
      the OS selects the port. The default is
      `%{address: {0, 0, 0, 0}, port: 0}`. Peer endpoints must use the same
      address family.

    * `:stack` - options for the SmolNet stack of the interface:

      * `:addresses` - up to 8 `{address, prefix_length}` pairs. The
        default is `[]`.
      * `:routes` - up to 4 `{destination, prefix_length, gateway}` routes.
        The gateway must be in the same address family as the destination.
        Wagyu clears the host bits in the destination. The default is `[]`.
      * `:mtu` - from 1280 to 65,475. The default is 1420, the same as
        wg-quick.
      * `:sockets` - the maximum number of open sockets, from 1 to 512.
        The default is 64. If you open a socket when all slots are in use,
        the open returns `{:error, :system_limit}`.

        * Each TCP or UDP socket uses one slot. Each connection in the
          accept pool of a TCP listener (up to 4) also uses one slot. A UDP
          socket that is bound to a wildcard address uses one slot for each
          interface address on which it listens.
        * A TCP socket that closes first keeps its slot through TIME-WAIT,
          for about 10 seconds. Thus an application that opens and closes
          connections continuously can open about `sockets / 10` each
          second.
        * Each slot holds the buffers of its socket. At the default sizes of
          SmolNet, these are 512 KiB for TCP and 32 KiB for UDP. SmolNet
          also limits the buffers of a stack to a total of 128 MiB. This
          total holds 256 TCP sockets at the default sizes. If you open a
          socket after that limit, the open also returns
          `{:error, :system_limit}`.

      Wagyu sets the SmolNet options `:egress`, `:egress_credit`, `:limits`
      and `:link_down` itself, and does not accept them here. Addresses and
      routes must also pass the checks of SmolNet. SmolNet does not accept
      these values:

        * multicast addresses
        * IPv4-mapped IPv6 addresses
        * `255.255.255.255` as an address or a gateway
        * `0.0.0.0` or `::` as a gateway

    * `:peers` - up to 1024 peers. Each peer is a map with these keys:

      * `:public_key` (required) - the X25519 public key of the peer, as a
        raw 32-byte binary. The key of each peer must be unique, and it
        must be different from the key of the interface. Wagyu does not
        accept keys that can never complete a handshake, for example 32
        zero bytes.
      * `:endpoint` - the address and port of the peer, as
        `%{address: address, port: port}`. The port must be from 1 to
        65535. The address must be in the family of the listen address, and
        it must not be `0.0.0.0` or `::`. For a peer that always connects
        to this interface, do not set the endpoint, or set it to `nil`. The
        interface then replies to the source of the handshakes of the peer.
      * `:allowed_ips` - the `{address, prefix_length}` prefixes from which
        the peer can send. Packets to these addresses go to the peer. When
        prefixes overlap, the most specific prefix wins. But two peers
        cannot have the same prefix. Wagyu clears the host bits. The default
        is `[]`.
      * `:preshared_key` - a 32-byte key from `wg genpsk`. Wagyu adds it to
        each handshake with the peer. Both sides must configure the same
        key, or their handshakes fail. For no key, do not set this option,
        or give 32 zero bytes. Wagyu does not accept `nil`. Thus an unset
        variable cannot turn off the key without an error.
      * `:persistent_keepalive` - the number of seconds without traffic
        after which the interface sends a keepalive to the peer. The
        keepalive keeps NAT and firewall mappings open. The range is from 1
        to 65,535, and 25 is correct for most NATs. The default is `0`,
        which turns off the keepalive. A peer with a keepalive starts when
        the interface starts.

  Wagyu does not accept unknown or repeated options at any level.

  ## Errors

  `new/1` returns `{:error, {:invalid_option, path, reason}}`. `path` shows
  the location of the option, with zero-based indices for list positions,
  for example `[:peers, 1, :allowed_ips, 0]`. Errors never include option
  values. Thus you can safely log them. `reason` is one of these values:

    * `:missing` - a required option is not there
    * `:unknown` - an option that Wagyu does not know
    * `:reserved` - a stack option that Wagyu sets itself
    * `:invalid` - the wrong type or shape, or a value that is not allowed,
      for example a multicast address or an unusable peer public key
    * `:invalid_length` - a key that is not exactly 32 bytes
    * `:out_of_range` - a port, MTU, socket limit or persistent keepalive
      outside its range
    * `:too_many` - more addresses, routes or peers than the limit
    * `:family_mismatch` - an endpoint or gateway in the wrong address family
    * `:duplicate` - a repeated option, public key, address, route or prefix
    * `:local_key` - a peer public key that is equal to the key of the
      interface

  ## Secrets

  The `Inspect` implementation of the struct hides the private key and the
  preshared keys. Other ways to print the struct show the keys:
  `inspect(config, structs: false)`, the `~p` format of Erlang, and direct
  access to the fields. Do not use these ways to log a configuration.
  """

  import Bitwise

  alias Wagyu.AllowedIPs
  alias Wagyu.Config.Peer
  alias Wagyu.IP

  @options [:name, :private_key, :listen, :stack, :peers]
  @stack_options [:addresses, :routes, :mtu, :sockets]
  @reserved_stack_options [:egress, :egress_credit, :limits, :link_down]
  @peer_options [:public_key, :endpoint, :allowed_ips, :preshared_key, :persistent_keepalive]
  @endpoint_options [:address, :port]

  @default_listen %{address: {0, 0, 0, 0}, port: 0}
  @default_mtu 1420
  # 65,535 minus the IPv4 and UDP headers (28) and the transport header and
  # tag (32). Padding cannot make a packet larger than the MTU. Thus
  # padding adds nothing at the limit.
  @mtu_range 1280..65_475
  @default_sockets 64
  @sockets_range 1..512
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
    stack: [addresses: [], routes: [], mtu: @default_mtu, sockets: @default_sockets],
    peers: %{},
    allowed_ips: %AllowedIPs{}
  ]

  # The internal AllowedIPs routing table, which Wagyu builds from the peers.
  @typep allowed_ips :: AllowedIPs.t()

  @typedoc "A validated interface configuration. `:peers` maps each public key to its peer."
  @type t :: %__MODULE__{
          name: atom() | {:global, term()} | {:via, module(), term()} | nil,
          private_key: <<_::256>>,
          public_key: <<_::256>>,
          listen: %{address: :inet.ip_address(), port: :inet.port_number()},
          stack: [
            addresses: [{:inet.ip_address(), non_neg_integer()}],
            routes: [{:inet.ip_address(), non_neg_integer(), :inet.ip_address()}],
            mtu: pos_integer(),
            sockets: pos_integer()
          ],
          peers: %{optional(<<_::256>>) => Peer.t()},
          allowed_ips: allowed_ips()
        }

  @typedoc "The location of an invalid option."
  @type path :: [atom() | non_neg_integer()]

  @typedoc "The reason that an option is not valid. See the Errors section."
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

  @typedoc "The error that `new/1` returns. You can safely log it."
  @type error :: {:invalid_option, path(), reason()}

  @doc """
  Validates interface options.

  ## Examples

      iex> {:ok, config} = Wagyu.Config.new(private_key: :binary.copy(<<1>>, 32))
      iex> config.stack
      [addresses: [], routes: [], mtu: 1420, sockets: 64]

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
         {:ok, stack} <- stack(Keyword.get(options, :stack, [])) do
      put_peers(
        %__MODULE__{name: name, private_key: private_key, public_key: public_key, listen: listen, stack: stack},
        Keyword.get(options, :peers, []),
        %{family: listen_family, keys: {public_key, private_key}}
      )
    end
  end

  @doc """
  Validates `peers` for the interface of `config`, and returns `config` with
  these peers in place of its peers.

  `peers` has the same form as the `:peers` option, and gets the same
  checks. The checks include the checks that need the interface: the
  address family of each endpoint, and the public key of each peer. The
  errors are the same as for `new/1`. Their paths start with
  `[:peers, index]`.

  ## Examples

      iex> {:ok, config} = Wagyu.Config.new(private_key: :binary.copy(<<1>>, 32))
      iex> peer = %{public_key: :binary.copy(<<9>>, 32), allowed_ips: [{{10, 0, 0, 1}, 24}]}
      iex> {:ok, config} = Wagyu.Config.put_peers(config, [peer])
      iex> config.peers[peer.public_key].allowed_ips
      [{{10, 0, 0, 0}, 24}]

      iex> {:ok, config} = Wagyu.Config.new(private_key: :binary.copy(<<1>>, 32))
      iex> Wagyu.Config.put_peers(config, [%{public_key: config.public_key}])
      {:error, {:invalid_option, [:peers, 0, :public_key], :local_key}}
  """
  @spec put_peers(t(), term()) :: {:ok, t()} | {:error, error()}
  def put_peers(%__MODULE__{} = config, peers) do
    {:ok, family} = family(config.listen.address)
    put_peers(config, peers, %{family: family, keys: {config.public_key, config.private_key}})
  end

  # `Wagyu.replace_peers/2` calls this function in the calling process. It
  # does the checks that do not need the interface, and builds the peers.
  # Thus only `Wagyu.Config.Peer` structs go to the interface, and raw
  # preshared keys do not appear in a message to it. The interface then
  # completes the checks with `put_peers/2`.
  @doc false
  @spec build_peers(term()) :: {:ok, [Peer.t()]} | {:error, error()}
  def build_peers(peers) do
    with {:ok, peers} <- peers(peers, nil),
         {:ok, _allowed_ips} <- allowed_ips(peers),
         do: {:ok, peers}
  end

  # Applies all checks again to peers from `build_peers/1`, with the
  # identity of the interface of `config`.
  @doc false
  @spec put_built_peers(t(), [Peer.t()]) :: {:ok, t()} | {:error, error()}
  def put_built_peers(%__MODULE__{} = config, peers) when is_list(peers),
    do: put_peers(config, Enum.map(peers, fn %Peer{} = peer -> Map.from_struct(peer) end))

  defp put_peers(config, peers, local) do
    with {:ok, peers} <- peers(peers, local),
         {:ok, allowed_ips} <- allowed_ips(peers) do
      {:ok, %{config | peers: Map.new(peers, &{&1.public_key, &1}), allowed_ips: allowed_ips}}
    end
  end

  # Finds a configured peer by its public key. Only configured keys can
  # create peer state. Thus an unknown key returns
  # `{:error, :unknown_peer}`.
  @doc false
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
         {:ok, mtu} <- mtu(Keyword.get(options, :mtu, @default_mtu)),
         {:ok, sockets} <- sockets(Keyword.get(options, :sockets, @default_sockets)) do
      {:ok, [addresses: addresses, routes: routes, mtu: mtu, sockets: sockets]}
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

  # SmolNet does not accept IPv4-mapped IPv6 addresses or multicast
  # addresses in its address and route configuration. Its multicast test
  # examines only the first byte (0xFF, or 224 to 239) in each family. This
  # function does exactly the same test. Thus this validation never accepts
  # an address that SmolNet refuses.
  defp smolnet_address?(address, bits) do
    {:ok, value, ^bits} = IP.to_integer(address)
    first_byte = value >>> (bits - 8)
    first_byte != 0xFF and first_byte not in 224..239 and not ipv4_mapped?(address)
  end

  defp mtu(mtu) when is_integer(mtu) and mtu in @mtu_range, do: {:ok, mtu}
  defp mtu(mtu) when is_integer(mtu), do: invalid([:stack, :mtu], :out_of_range)
  defp mtu(_mtu), do: invalid([:stack, :mtu], :invalid)

  defp sockets(sockets) when is_integer(sockets) and sockets in @sockets_range, do: {:ok, sockets}
  defp sockets(sockets) when is_integer(sockets), do: invalid([:stack, :sockets], :out_of_range)
  defp sockets(_sockets), do: invalid([:stack, :sockets], :invalid)

  # Peers

  # `local` holds the address family and the key pair of the interface.
  # Without it (`nil`), the checks that need them do not occur.
  defp peers(peers, local) do
    with :ok <- list(peers, [:peers], @max_peers),
         {:ok, peers} <- map_indexed(peers, [:peers], &peer(&1, &2, local)),
         :ok <- unique(Enum.map(peers, & &1.public_key), &[:peers, &1, :public_key]) do
      {:ok, peers}
    end
  end

  defp peer(value, path, local) do
    with :ok <- map(value, path, @peer_options, [:public_key]),
         {:ok, public_key} <- peer_public_key(value.public_key, path ++ [:public_key], local),
         {:ok, endpoint} <- endpoint(Map.get(value, :endpoint), path ++ [:endpoint], local),
         {:ok, allowed_ips} <- peer_allowed_ips(Map.get(value, :allowed_ips, []), path ++ [:allowed_ips]),
         {:ok, preshared_key} <- preshared_key(Map.fetch(value, :preshared_key), path ++ [:preshared_key]),
         {:ok, keepalive} <-
           persistent_keepalive(Map.get(value, :persistent_keepalive, 0), path ++ [:persistent_keepalive]) do
      {:ok,
       %Peer{
         public_key: public_key,
         endpoint: endpoint,
         allowed_ips: allowed_ips,
         preshared_key: preshared_key,
         persistent_keepalive: keepalive
       }}
    end
  end

  defp peer_public_key(value, path, nil), do: key(value, path)

  defp peer_public_key(value, path, %{keys: {local_key, private_key}}) do
    case key(value, path) do
      {:ok, ^local_key} -> invalid(path, :local_key)
      {:ok, key} -> if usable?(key, private_key), do: {:ok, key}, else: invalid(path, :invalid)
      error -> error
    end
  end

  # X25519 with a low-order point, for example all zeros, gives all zeros
  # for each private key. Decibel does not accept this result. Thus a
  # handshake with such a peer can never complete.
  defp usable?(public_key, private_key) do
    _shared = :crypto.compute_key(:ecdh, public_key, private_key, :x25519)
    true
  rescue
    ErlangError -> false
  end

  defp endpoint(nil, _path, _local), do: {:ok, nil}

  defp endpoint(value, path, local) do
    with :ok <- map(value, path, @endpoint_options, @endpoint_options),
         {:ok, family} <- address(value.address, path ++ [:address]),
         :ok <- endpoint_address(value.address, family, local, path ++ [:address]),
         :ok <- port(value.port, 1, path ++ [:port]) do
      {:ok, value}
    end
  end

  # The family check needs the interface. Thus the check of an unspecified
  # address also waits for it, and the two checks keep their sequence.
  defp endpoint_address(_address, _family, nil, _path), do: :ok

  defp endpoint_address(_address, family, %{family: listen_family}, path) when family != listen_family,
    do: invalid(path, :family_mismatch)

  defp endpoint_address(address, _family, _local, path) do
    if unspecified?(address), do: invalid(path, :invalid), else: :ok
  end

  defp peer_allowed_ips(prefixes, path) do
    if proper_list?(prefixes),
      do: map_indexed(prefixes, path, fn prefix, _path -> AllowedIPs.normalize(prefix) end),
      else: invalid(path, :invalid)
  end

  # If the preshared key is not set, Wagyu uses the all-zero key of the
  # protocol. Wagyu does not accept `nil`. If it did, an unset variable that
  # was to hold a key would turn off the key without an error.
  defp preshared_key(:error, _path), do: {:ok, @zero_key}
  defp preshared_key({:ok, value}, path), do: key(value, path)

  defp persistent_keepalive(seconds, _path) when is_integer(seconds) and seconds in 0..65_535, do: {:ok, seconds}
  defp persistent_keepalive(seconds, path) when is_integer(seconds), do: invalid(path, :out_of_range)
  defp persistent_keepalive(_seconds, path), do: invalid(path, :invalid)

  # Each exact prefix can occur only one time across all peers.
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

  # Validates each item in sequence and stops at the first error. A
  # validator returns `:error` when the item itself is not valid, at its own
  # path.
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

  # Fails at `path_for.(index)` for the first key that is the same as an
  # earlier key.
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
