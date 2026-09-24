defmodule Wagyu.ConfigTest do
  use ExUnit.Case, async: true

  alias Wagyu.AllowedIPs
  alias Wagyu.Config
  alias Wagyu.Config.Peer

  doctest Wagyu.Config

  defp keypair do
    {public_key, private_key} = :crypto.generate_key(:ecdh, :x25519)
    {public_key, private_key}
  end

  defp public_key, do: elem(keypair(), 0)

  defp peer(overrides \\ %{}) do
    Map.merge(
      %{
        public_key: public_key(),
        endpoint: %{address: {192, 0, 2, 1}, port: 51_820},
        allowed_ips: [{{0, 0, 0, 0}, 0}]
      },
      overrides
    )
  end

  # The example configuration from the design.
  defp options(overrides \\ []) do
    {_public_key, private_key} = keypair()

    Keyword.merge(
      [
        name: :wg0,
        private_key: private_key,
        listen: %{address: {0, 0, 0, 0}, port: 51_820},
        stack: [
          addresses: [{{10, 13, 0, 2}, 32}],
          routes: [{{0, 0, 0, 0}, 0, {10, 13, 0, 1}}],
          mtu: 1280
        ],
        peers: [peer()]
      ],
      overrides
    )
  end

  defp invalid(path, reason), do: {:error, {:invalid_option, path, reason}}

  describe "a valid configuration" do
    test "validates the design's example" do
      options = options()
      [%{public_key: peer_key} = peer_options] = options[:peers]

      assert {:ok, %Config{} = config} = Config.new(options)
      assert config.name == :wg0
      assert config.private_key == options[:private_key]
      assert {config.public_key, config.private_key} == :crypto.generate_key(:ecdh, :x25519, options[:private_key])
      assert config.listen == %{address: {0, 0, 0, 0}, port: 51_820}
      assert config.stack == [addresses: [{{10, 13, 0, 2}, 32}], routes: [{{0, 0, 0, 0}, 0, {10, 13, 0, 1}}], mtu: 1280]

      assert config.peers == %{
               peer_key => %Peer{
                 public_key: peer_key,
                 endpoint: peer_options.endpoint,
                 allowed_ips: [{{0, 0, 0, 0}, 0}],
                 preshared_key: <<0::256>>
               }
             }

      assert AllowedIPs.lookup(config.allowed_ips, {10, 13, 0, 1}) == {:ok, peer_key}
    end

    test "applies defaults" do
      {_public_key, private_key} = keypair()

      assert {:ok, config} = Config.new(private_key: private_key)
      assert config.name == nil
      assert config.listen == %{address: {0, 0, 0, 0}, port: 0}
      assert config.stack == [addresses: [], routes: [], mtu: 1420]
      assert config.peers == %{}
      assert AllowedIPs.to_list(config.allowed_ips) == []
    end

    test "accepts a responder-only peer and a peer with no allowed IPs" do
      responder_only = Map.delete(peer(), :endpoint)
      explicit_nil = peer(%{endpoint: nil, allowed_ips: [{{10, 13, 0, 3}, 32}]})

      no_routes =
        Map.delete(peer(%{allowed_ips: []}), :allowed_ips) |> Map.put(:endpoint, %{address: {192, 0, 2, 9}, port: 1})

      assert {:ok, config} = Config.new(options(peers: [responder_only, explicit_nil, no_routes]))
      assert config.peers[responder_only.public_key].endpoint == nil
      assert config.peers[explicit_nil.public_key].endpoint == nil
      assert config.peers[no_routes.public_key].allowed_ips == []
    end

    test "supports IPv6 listen addresses and endpoints" do
      endpoint = %{address: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, port: 51_820}

      assert {:ok, config} =
               Config.new(
                 options(
                   listen: %{address: {0, 0, 0, 0, 0, 0, 0, 0}, port: 0},
                   peers: [peer(%{endpoint: endpoint, allowed_ips: [{{0xFD00, 0, 0, 0, 0, 0, 0, 0}, 8}]})]
                 )
               )

      assert [%Peer{endpoint: ^endpoint}] = Map.values(config.peers)
    end

    test "accepts every standard name form" do
      for name <- [nil, :wg0, {:global, {:wagyu, 1}}, {:via, Registry, {Wagyu.Registry, :wg0}}] do
        assert {:ok, %Config{name: ^name}} = Config.new(options(name: name))
      end
    end
  end

  describe "top-level options" do
    test "must be a keyword list without unknown or repeated keys" do
      options = options()

      assert Config.new(Map.new(options)) == invalid([], :invalid)
      assert Config.new([{"private_key", options[:private_key]}]) == invalid([], :invalid)
      assert Config.new(options ++ [mtu: 1420]) == invalid([:mtu], :unknown)
      assert Config.new(options ++ [peers: []]) == invalid([:peers], :duplicate)
    end

    test "reject invalid names" do
      for name <- ["wg0", {:local, :wg0}, {:via, "Registry", :wg0}, {:global}] do
        assert Config.new(options(name: name)) == invalid([:name], :invalid)
      end
    end
  end

  describe "keys" do
    test "require a 32-byte private key" do
      assert Config.new(Keyword.delete(options(), :private_key)) == invalid([:private_key], :missing)

      for key <- [<<>>, :binary.copy(<<1>>, 31), :binary.copy(<<1>>, 33)] do
        assert Config.new(options(private_key: key)) == invalid([:private_key], :invalid_length)
      end

      assert Config.new(options(private_key: nil)) == invalid([:private_key], :invalid)

      assert Config.new(options(private_key: Base.encode64(:binary.copy(<<1>>, 32)))) ==
               invalid([:private_key], :invalid_length)
    end

    test "require 32-byte peer public keys" do
      assert Config.new(options(peers: [Map.delete(peer(), :public_key)])) ==
               invalid([:peers, 0, :public_key], :missing)

      for key <- [:binary.copy(<<1>>, 31), :binary.copy(<<1>>, 33)] do
        assert Config.new(options(peers: [peer(%{public_key: key})])) ==
                 invalid([:peers, 0, :public_key], :invalid_length)
      end

      assert Config.new(options(peers: [peer(%{public_key: :key})])) == invalid([:peers, 0, :public_key], :invalid)
    end

    test "reject a peer key that repeats another peer's or the interface's own" do
      repeated = public_key()
      options = options()
      {own_key, _private_key} = :crypto.generate_key(:ecdh, :x25519, options[:private_key])

      assert Config.new(
               Keyword.put(options, :peers, [
                 peer(%{public_key: repeated, allowed_ips: []}),
                 peer(%{public_key: repeated, allowed_ips: []})
               ])
             ) == invalid([:peers, 1, :public_key], :duplicate)

      assert Config.new(Keyword.put(options, :peers, [peer(%{public_key: own_key})])) ==
               invalid([:peers, 0, :public_key], :local_key)
    end

    test "reject a peer key that no handshake can use" do
      # Low-order points, of orders 4, 1, 2 and 8: X25519 with any of them
      # yields all zeros.
      order_8 = Base.decode16!("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", case: :lower)

      for key <- [<<0::256>>, <<1::little-256>>, <<2 ** 255 - 20::little-256>>, order_8] do
        assert Config.new(options(peers: [peer(%{public_key: key})])) == invalid([:peers, 0, :public_key], :invalid)
      end
    end
  end

  describe "preshared keys" do
    test "accept an omitted or all-zero key as the zero key" do
      assert {:ok, config} = Config.new(options(peers: [peer(%{preshared_key: <<0::256>>})]))
      assert [%Peer{preshared_key: <<0::256>>}] = Map.values(config.peers)
    end

    test "reject every nonzero key instead of replacing it with zeros" do
      for bit <- 0..255 do
        key = <<0::size(bit), 1::1, 0::size(255 - bit)>>
        assert Config.new(options(peers: [peer(%{preshared_key: key})])) == {:error, :unsupported_preshared_key}
      end

      for key <- [:binary.copy(<<0xFF>>, 32), :crypto.strong_rand_bytes(32)] do
        assert Config.new(options(peers: [peer(%{preshared_key: key})])) == {:error, :unsupported_preshared_key}
      end
    end

    test "reject a nonzero key on any peer" do
      peers = [peer(%{allowed_ips: []}), peer(%{allowed_ips: []}), peer(%{preshared_key: :binary.copy(<<7>>, 32)})]
      assert Config.new(options(peers: peers)) == {:error, :unsupported_preshared_key}
    end

    test "reject nil and mis-sized keys" do
      path = [:peers, 0, :preshared_key]

      assert Config.new(options(peers: [peer(%{preshared_key: nil})])) == invalid(path, :invalid)
      assert Config.new(options(peers: [peer(%{preshared_key: <<0::248>>})])) == invalid(path, :invalid_length)
      assert Config.new(options(peers: [peer(%{preshared_key: <<0::264>>})])) == invalid(path, :invalid_length)
    end
  end

  describe "listen" do
    test "requires an address and a port in 0..65535" do
      for {listen, path, reason} <- [
            {[address: {0, 0, 0, 0}, port: 0], [:listen], :invalid},
            {nil, [:listen], :invalid},
            {%{address: {0, 0, 0, 0}}, [:listen, :port], :missing},
            {%{port: 1}, [:listen, :address], :missing},
            {%{address: {0, 0, 0, 0}, port: 1, reuse: true}, [:listen, :reuse], :unknown},
            {%{address: "0.0.0.0", port: 1}, [:listen, :address], :invalid},
            {%{address: {0, 0, 0, 256}, port: 1}, [:listen, :address], :invalid},
            {%{address: {0, 0, 0, 0}, port: -1}, [:listen, :port], :out_of_range},
            {%{address: {0, 0, 0, 0}, port: 65_536}, [:listen, :port], :out_of_range},
            {%{address: {0, 0, 0, 0}, port: "51820"}, [:listen, :port], :invalid}
          ] do
        assert Config.new(options(listen: listen)) == invalid(path, reason), inspect(listen)
      end

      assert {:ok, _config} = Config.new(options(listen: %{address: {127, 0, 0, 1}, port: 65_535}))
    end
  end

  describe "peer endpoints" do
    test "must be a specified address in the listen family with a nonzero port" do
      for {endpoint, path, reason} <- [
            {%{address: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, port: 1}, [:address], :family_mismatch},
            {%{address: {0, 0, 0, 0}, port: 1}, [:address], :invalid},
            {%{address: {192, 0, 2}, port: 1}, [:address], :invalid},
            {%{address: {192, 0, 2, 1}, port: 0}, [:port], :out_of_range},
            {%{address: {192, 0, 2, 1}, port: 65_536}, [:port], :out_of_range},
            {%{address: {192, 0, 2, 1}}, [:port], :missing},
            {%{address: {192, 0, 2, 1}, port: 1, host: "example.com"}, [:host], :unknown},
            {{{192, 0, 2, 1}, 51_820}, [], :invalid}
          ] do
        assert Config.new(options(peers: [peer(%{endpoint: endpoint})])) ==
                 invalid([:peers, 0, :endpoint] ++ path, reason),
               inspect(endpoint)
      end
    end

    test "must use IPv6 when the listen address does" do
      options = options(listen: %{address: {0, 0, 0, 0, 0, 0, 0, 0}, port: 0})

      assert Config.new(options) == invalid([:peers, 0, :endpoint, :address], :family_mismatch)

      unspecified = peer(%{endpoint: %{address: {0, 0, 0, 0, 0, 0, 0, 0}, port: 1}})

      assert Config.new(Keyword.put(options, :peers, [unspecified])) ==
               invalid([:peers, 0, :endpoint, :address], :invalid)
    end
  end

  describe "peers" do
    test "must be a list of at most 1024 maps with known keys" do
      assert Config.new(options(peers: %{})) == invalid([:peers], :invalid)
      assert Config.new(options(peers: [peer() | :tail])) == invalid([:peers], :invalid)
      assert Config.new(options(peers: [Keyword.new(peer())])) == invalid([:peers, 0], :invalid)
      assert Config.new(options(peers: [peer(%{keepalive: 25})])) == invalid([:peers, 0, :keepalive], :unknown)

      many = for _index <- 1..1025, do: %{public_key: public_key()}
      assert Config.new(options(peers: many)) == invalid([:peers], :too_many)
      assert {:ok, config} = Config.new(options(peers: Enum.take(many, 1024)))
      assert map_size(config.peers) == 1024
    end

    test "fetch_peer/2 finds configured keys and rejects unknown ones" do
      assert {:ok, config} = Config.new(options())
      [known] = Map.keys(config.peers)

      assert {:ok, %Peer{public_key: ^known}} = Config.fetch_peer(config, known)
      assert Config.fetch_peer(config, public_key()) == {:error, :unknown_peer}
      assert Config.fetch_peer(config, config.public_key) == {:error, :unknown_peer}
    end
  end

  describe "allowed IPs" do
    test "are normalized and routed by longest prefix" do
      gateway = peer(%{allowed_ips: [{{10, 13, 99, 1}, 16}, {{0xFD00, 0, 0, 0, 0, 0, 0, 1}, 8}]})
      laptop = peer(%{allowed_ips: [{{10, 13, 0, 7}, 32}]})

      assert {:ok, config} = Config.new(options(peers: [gateway, laptop]))
      assert config.peers[gateway.public_key].allowed_ips == [{{10, 13, 0, 0}, 16}, {{0xFD00, 0, 0, 0, 0, 0, 0, 0}, 8}]
      assert AllowedIPs.lookup(config.allowed_ips, {10, 13, 0, 7}) == {:ok, laptop.public_key}
      assert AllowedIPs.lookup(config.allowed_ips, {10, 13, 0, 8}) == {:ok, gateway.public_key}
      assert AllowedIPs.lookup(config.allowed_ips, {10, 14, 0, 8}) == :error
    end

    test "reject duplicate exact prefixes within and across peers" do
      within = peer(%{allowed_ips: [{{10, 0, 0, 0}, 8}, {{10, 1, 1, 1}, 8}]})
      assert Config.new(options(peers: [within])) == invalid([:peers, 0, :allowed_ips, 1], :duplicate)

      first = peer(%{allowed_ips: [{{10, 0, 0, 0}, 8}, {{10, 13, 0, 0}, 16}]})
      second = peer(%{allowed_ips: [{{192, 168, 0, 0}, 16}, {{10, 13, 7, 7}, 16}]})
      assert Config.new(options(peers: [first, second])) == invalid([:peers, 1, :allowed_ips, 1], :duplicate)
    end

    test "reject malformed prefixes" do
      for {allowed_ips, path} <- [
            {{{10, 0, 0, 0}, 8}, []},
            {[{{10, 0, 0, 0}, 33}], [0]},
            {[{{10, 0, 0, 0}, 8}, {"10.1.0.0", 16}], [1]},
            {[{{10, 0, 0, 0}, 8, :extra}], [0]}
          ] do
        assert Config.new(options(peers: [peer(%{allowed_ips: allowed_ips})])) ==
                 invalid([:peers, 0, :allowed_ips] ++ path, :invalid)
      end
    end
  end

  describe "stack" do
    test "must be a keyword list of known options" do
      assert Config.new(options(stack: %{mtu: 1420})) == invalid([:stack], :invalid)
      assert Config.new(options(stack: [mtu: 1420, mtu: 1500])) == invalid([:stack, :mtu], :duplicate)
      assert Config.new(options(stack: [name: :stack])) == invalid([:stack, :name], :unknown)

      for key <- [:egress, :limits, :link_down] do
        assert Config.new(options(stack: [{key, :stop}])) == invalid([:stack, key], :reserved)
      end
    end

    test "limits the MTU to 1280..65475" do
      for mtu <- [1280, 1420, 65_475] do
        assert {:ok, config} = Config.new(options(stack: [mtu: mtu]))
        assert config.stack[:mtu] == mtu
      end

      for mtu <- [0, 1279, 65_476, 65_575] do
        assert Config.new(options(stack: [mtu: mtu])) == invalid([:stack, :mtu], :out_of_range)
      end

      assert Config.new(options(stack: [mtu: 1420.0])) == invalid([:stack, :mtu], :invalid)
    end

    test "allows at most 8 addresses" do
      addresses = for host <- 1..9, do: {{10, 13, 0, host}, 24}

      assert {:ok, config} = Config.new(options(stack: [addresses: Enum.take(addresses, 8)]))
      assert length(config.stack[:addresses]) == 8
      assert Config.new(options(stack: [addresses: addresses])) == invalid([:stack, :addresses], :too_many)
    end

    test "allows at most 4 routes" do
      routes = for net <- 1..5, do: {{10, net, 0, 0}, 16, {10, 13, 0, 1}}

      assert {:ok, config} = Config.new(options(stack: [routes: Enum.take(routes, 4)]))
      assert length(config.stack[:routes]) == 4
      assert Config.new(options(stack: [routes: routes])) == invalid([:stack, :routes], :too_many)
    end

    test "keeps interface addresses as given and rejects addresses SmolNet refuses" do
      assert {:ok, config} =
               Config.new(options(stack: [addresses: [{{10, 13, 0, 2}, 24}, {{0xFD00, 0, 0, 0, 0, 0, 0, 2}, 64}]]))

      assert config.stack[:addresses] == [{{10, 13, 0, 2}, 24}, {{0xFD00, 0, 0, 0, 0, 0, 0, 2}, 64}]

      for address <- [
            {{10, 13, 0, 2}, 33},
            {{0xFD00, 0, 0, 0, 0, 0, 0, 2}, 129},
            {{224, 0, 0, 1}, 32},
            {{255, 255, 255, 255}, 32},
            {{0xFF02, 0, 0, 0, 0, 0, 0, 1}, 128},
            {{0, 0, 0, 0, 0, 0xFFFF, 0x0A0D, 2}, 128},
            {{10, 13, 0, 2}, "24"},
            {10, 13, 0, 2}
          ] do
        assert Config.new(options(stack: [addresses: [address]])) == invalid([:stack, :addresses, 0], :invalid),
               inspect(address)
      end

      assert Config.new(options(stack: [addresses: [{{10, 13, 0, 2}, 24}, {{10, 13, 0, 2}, 32}]])) ==
               invalid([:stack, :addresses, 1], :duplicate)
    end

    test "normalizes route destinations and rejects routes SmolNet refuses" do
      assert {:ok, config} = Config.new(options(stack: [routes: [{{10, 99, 1, 1}, 16, {10, 13, 0, 1}}]]))
      assert config.stack[:routes] == [{{10, 99, 0, 0}, 16, {10, 13, 0, 1}}]

      v6_gateway = {0xFD00, 0, 0, 0, 0, 0, 0, 1}

      for {route, reason} <- [
            {{{0, 0, 0, 0}, 0, v6_gateway}, :family_mismatch},
            {{{0, 0, 0, 0, 0, 0, 0, 0}, 0, {10, 13, 0, 1}}, :family_mismatch},
            {{{0, 0, 0, 0}, 0, {0, 0, 0, 0}}, :invalid},
            {{{0, 0, 0, 0}, 0, {255, 255, 255, 255}}, :invalid},
            {{{0, 0, 0, 0}, 0, {224, 0, 0, 1}}, :invalid},
            {{{224, 0, 0, 0}, 4, {10, 13, 0, 1}}, :invalid},
            {{{0, 0, 0, 0}, 33, {10, 13, 0, 1}}, :invalid},
            {{{0, 0, 0, 0, 0, 0, 0, 0}, 0, {0, 0, 0, 0, 0, 0, 0, 0}}, :invalid},
            {{{0, 0, 0, 0}, 0}, :invalid}
          ] do
        assert Config.new(options(stack: [routes: [route]])) == invalid([:stack, :routes, 0], reason), inspect(route)
      end

      assert Config.new(
               options(stack: [routes: [{{10, 0, 0, 0}, 8, {10, 13, 0, 1}}, {{10, 1, 0, 0}, 8, {10, 13, 0, 9}}]])
             ) ==
               invalid([:stack, :routes, 1], :duplicate)
    end
  end

  describe "inspect/2" do
    test "omits the private key and preshared keys" do
      {_public_key, private_key} = keypair()

      assert {:ok, config} =
               Config.new(options(private_key: private_key, peers: [peer(%{preshared_key: <<0::256>>})]))

      for opts <- [
            [],
            [limit: :infinity, printable_limit: :infinity],
            [binaries: :as_binaries, limit: :infinity],
            [base: :hex, limit: :infinity],
            [pretty: true, width: 0, limit: :infinity]
          ] do
        output = inspect(config, opts)

        refute output =~ inspect(private_key, opts)
        refute output =~ "private_key"
        refute output =~ "preshared_key"
        assert output =~ "public_key"

        for %Peer{} = peer <- Map.values(config.peers) do
          refute inspect(peer, opts) =~ "preshared_key"
        end
      end

      refute inspect(config, limit: :infinity) =~ Base.encode16(private_key)
      refute inspect(config, limit: :infinity) =~ Base.encode64(private_key)
    end

    test "errors never carry key material" do
      key = :binary.copy(<<0xA5>>, 31)
      assert {:error, reason} = Config.new(options(private_key: key))
      refute inspect(reason, limit: :infinity) =~ inspect(key)
    end
  end
end
