defmodule Wagyu.AllowedIPsTest do
  use ExUnit.Case, async: true

  alias Wagyu.AllowedIPs

  defp table!(entries) do
    {:ok, table} = AllowedIPs.new(entries)
    table
  end

  describe "normalize/1" do
    test "clears host bits" do
      assert AllowedIPs.normalize({{10, 13, 7, 9}, 16}) == {:ok, {{10, 13, 0, 0}, 16}}
      assert AllowedIPs.normalize({{10, 13, 7, 9}, 32}) == {:ok, {{10, 13, 7, 9}, 32}}
      assert AllowedIPs.normalize({{10, 13, 7, 9}, 0}) == {:ok, {{0, 0, 0, 0}, 0}}
      assert AllowedIPs.normalize({{192, 168, 1, 255}, 25}) == {:ok, {{192, 168, 1, 128}, 25}}

      assert AllowedIPs.normalize({{0xFD00, 0x1234, 0x5678, 0x9ABC, 1, 2, 3, 4}, 36}) ==
               {:ok, {{0xFD00, 0x1234, 0x5000, 0, 0, 0, 0, 0}, 36}}

      assert AllowedIPs.normalize({{0xFD00, 0, 0, 0, 0, 0, 0, 1}, 128}) == {:ok, {{0xFD00, 0, 0, 0, 0, 0, 0, 1}, 128}}
    end

    test "rejects invalid addresses and lengths" do
      for prefix <- [
            {{10, 0, 0, 0}, 33},
            {{10, 0, 0, 0}, -1},
            {{0, 0, 0, 0, 0, 0, 0, 0}, 129},
            {{256, 0, 0, 0}, 8},
            {{10, 0, 0}, 8},
            {{10, 0, 0, 0}, "8"},
            {"10.0.0.0", 8},
            {{10, 0, 0, 0}, 8, :extra},
            nil
          ] do
        assert AllowedIPs.normalize(prefix) == :error
      end
    end
  end

  describe "new/1" do
    test "rejects duplicate exact prefixes, including after normalization" do
      assert AllowedIPs.new([{{{10, 0, 0, 0}, 8}, :a}, {{{10, 0, 0, 0}, 8}, :b}]) ==
               {:error, {:duplicate_prefix, {{10, 0, 0, 0}, 8}}}

      assert AllowedIPs.new([{{{10, 0, 0, 0}, 8}, :a}, {{{10, 9, 9, 9}, 8}, :a}]) ==
               {:error, {:duplicate_prefix, {{10, 0, 0, 0}, 8}}}

      assert AllowedIPs.new([{{{0, 0, 0, 0, 0, 0, 0, 0}, 0}, :a}, {{{0xFD00, 0, 0, 0, 0, 0, 0, 0}, 0}, :b}]) ==
               {:error, {:duplicate_prefix, {{0, 0, 0, 0, 0, 0, 0, 0}, 0}}}
    end

    test "treats equal prefixes of different lengths or families as distinct" do
      assert {:ok, _table} =
               AllowedIPs.new([
                 {{{10, 0, 0, 0}, 8}, :a},
                 {{{10, 0, 0, 0}, 16}, :b},
                 {{{0, 0, 0, 0}, 0}, :c},
                 {{{0, 0, 0, 0, 0, 0, 0, 0}, 0}, :d}
               ])
    end

    test "rejects malformed entries" do
      assert AllowedIPs.new([{{{10, 0, 0, 0}, 40}, :a}]) == {:error, {:invalid_prefix, {{10, 0, 0, 0}, 40}}}
      assert AllowedIPs.new([:not_an_entry]) == {:error, {:invalid_prefix, :not_an_entry}}
    end
  end

  describe "lookup/2" do
    setup do
      table =
        table!([
          {{{0, 0, 0, 0}, 0}, :default},
          {{{10, 0, 0, 0}, 8}, :ten},
          {{{10, 13, 0, 0}, 16}, :wg},
          {{{10, 13, 0, 7}, 32}, :host},
          {{{10, 13, 128, 0}, 17}, :upper},
          {{{0xFD00, 0, 0, 0, 0, 0, 0, 0}, 8}, :ula},
          {{{0xFD00, 0x13, 0, 0, 0, 0, 0, 0}, 32}, :wg6},
          {{{0xFD00, 0x13, 0, 0, 0, 0, 0, 7}, 128}, :host6}
        ])

      %{table: table}
    end

    test "selects the longest matching IPv4 prefix", %{table: table} do
      for {address, peer} <- [
            {{10, 13, 0, 7}, :host},
            {{10, 13, 0, 6}, :wg},
            {{10, 13, 0, 8}, :wg},
            {{10, 13, 127, 255}, :wg},
            {{10, 13, 128, 0}, :upper},
            {{10, 13, 255, 255}, :upper},
            {{10, 12, 255, 255}, :ten},
            {{10, 14, 0, 0}, :ten},
            {{10, 255, 255, 255}, :ten},
            {{9, 255, 255, 255}, :default},
            {{11, 0, 0, 0}, :default},
            {{255, 255, 255, 255}, :default}
          ] do
        assert AllowedIPs.lookup(table, address) == {:ok, peer}, inspect(address)
      end
    end

    test "selects the longest matching IPv6 prefix", %{table: table} do
      for {address, peer} <- [
            {{0xFD00, 0x13, 0, 0, 0, 0, 0, 7}, :host6},
            {{0xFD00, 0x13, 0, 0, 0, 0, 0, 8}, :wg6},
            {{0xFD00, 0x13, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF}, :wg6},
            {{0xFD00, 0x14, 0, 0, 0, 0, 0, 0}, :ula},
            {{0xFDFF, 0, 0, 0, 0, 0, 0, 0}, :ula}
          ] do
        assert AllowedIPs.lookup(table, address) == {:ok, peer}, inspect(address)
      end
    end

    test "keeps the families apart", %{table: table} do
      assert AllowedIPs.lookup(table, {0xFE80, 0, 0, 0, 0, 0, 0, 1}) == :error
      assert AllowedIPs.lookup(table, {0, 0, 0, 0, 0, 0xFFFF, 0x0A0D, 7}) == :error

      assert AllowedIPs.lookup(table!([{{{0, 0, 0, 0, 0, 0, 0, 0}, 0}, :v6}]), {10, 13, 0, 7}) == :error
    end

    test "returns :error for no match or a malformed address" do
      table = table!([{{{10, 13, 0, 0}, 16}, :wg}])

      for address <- [{10, 14, 0, 0}, {256, 0, 0, 0}, {10, 13, 0}, "10.13.0.1", nil] do
        assert AllowedIPs.lookup(table, address) == :error
      end

      assert AllowedIPs.lookup(table!([]), {10, 13, 0, 1}) == :error
    end
  end

  describe "allowed?/3" do
    test "accepts a source only when its best match is the decrypting peer" do
      table = table!([{{{10, 13, 0, 0}, 16}, :gateway}, {{{10, 13, 0, 7}, 32}, :laptop}])

      assert AllowedIPs.allowed?(table, {10, 13, 0, 7}, :laptop)
      assert AllowedIPs.allowed?(table, {10, 13, 0, 8}, :gateway)

      # The gateway covers 10.13.0.0/16, but the /32 belongs to the laptop.
      refute AllowedIPs.allowed?(table, {10, 13, 0, 7}, :gateway)
      refute AllowedIPs.allowed?(table, {10, 13, 0, 8}, :laptop)
      refute AllowedIPs.allowed?(table, {10, 14, 0, 1}, :gateway)
      refute AllowedIPs.allowed?(table, :garbage, :gateway)
    end

    test "agrees with outbound lookup for every address" do
      peers = [:a, :b, :c]

      table =
        table!([
          {{{10, 0, 0, 0}, 8}, :a},
          {{{10, 128, 0, 0}, 9}, :b},
          {{{10, 128, 0, 0}, 24}, :c},
          {{{10, 128, 0, 128}, 25}, :a}
        ])

      for _trial <- 1..500 do
        <<a, b, c, d>> = <<10, :crypto.strong_rand_bytes(3)::binary>>
        address = {a, b, c, d}

        allowed = Enum.filter(peers, &AllowedIPs.allowed?(table, address, &1))

        case AllowedIPs.lookup(table, address) do
          {:ok, peer} -> assert allowed == [peer]
          :error -> assert allowed == []
        end
      end
    end
  end

  describe "source_filter/2" do
    test "keeps a peer's prefixes and the longer ones nested in them, and answers allowed?/3 alike" do
      table =
        table!([
          {{{10, 0, 0, 0}, 8}, :a},
          {{{10, 13, 5, 0}, 24}, :b},
          {{{10, 13, 5, 7}, 32}, :a},
          {{{192, 168, 0, 0}, 16}, :b},
          {{{0, 0, 0, 0}, 0}, :c},
          {{{0xFD00, 0, 0, 0, 0, 0, 0, 0}, 16}, :a},
          {{{0xFD00, 0, 0, 0, 0, 0, 0, 5}, 128}, :b},
          # IPv4 bits that match the IPv6 prefix's leading bits.
          {{{253, 0, 0, 1}, 32}, :b}
        ])

      filter = AllowedIPs.source_filter(table, :a)

      assert AllowedIPs.to_list(filter) == [
               {{{10, 13, 5, 7}, 32}, :a},
               {{{10, 13, 5, 0}, 24}, :b},
               {{{10, 0, 0, 0}, 8}, :a},
               {{{0xFD00, 0, 0, 0, 0, 0, 0, 5}, 128}, :b},
               {{{0xFD00, 0, 0, 0, 0, 0, 0, 0}, 16}, :a}
             ]

      for address <- [
            {10, 1, 1, 1},
            {10, 13, 5, 1},
            {10, 13, 5, 7},
            {192, 168, 1, 1},
            {8, 8, 8, 8},
            {253, 0, 0, 1},
            {0xFD00, 0, 0, 0, 0, 0, 0, 1},
            {0xFD00, 0, 0, 0, 0, 0, 0, 5},
            {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}
          ] do
        assert AllowedIPs.allowed?(filter, address, :a) == AllowedIPs.allowed?(table, address, :a)
      end
    end

    test "is empty for a peer with no prefixes" do
      table = table!([{{{10, 0, 0, 0}, 8}, :a}])
      assert AllowedIPs.to_list(AllowedIPs.source_filter(table, :b)) == []
    end
  end

  test "to_list/1 returns normalized entries, longest prefix first" do
    table =
      table!([
        {{{10, 1, 2, 3}, 8}, :a},
        {{{0xFD00, 0, 0, 0, 0, 0, 0, 9}, 64}, :b},
        {{{10, 13, 0, 0}, 16}, :c}
      ])

    assert AllowedIPs.to_list(table) == [
             {{{10, 13, 0, 0}, 16}, :c},
             {{{10, 0, 0, 0}, 8}, :a},
             {{{0xFD00, 0, 0, 0, 0, 0, 0, 0}, 64}, :b}
           ]
  end
end
