defmodule Wagyu.GoldenVectors do
  @moduledoc false

  # A WireGuard handshake transcript from fixed keys, as `wgpeer vectors`
  # (test/interop) prints it. That program computes it step by step from the
  # WireGuard whitepaper with golang.org/x/crypto, sharing no code with
  # Decibel or Wagyu; the interop tests check that it still prints exactly
  # this. Keys are hex, the initiator's index is 0x11223344 and the
  # responder's 0x55667788, and each keepalive is the first transport
  # message its sender sends.

  @vectors [
    initiator_private: "30f840b57759f1b03f2881d249d8440535438013bb60c4e3ca186eec5baa6543",
    initiator_public: "6de814225a4cea710ede659be1cae9968700fe06ded3cb48017012fda4a6d72a",
    initiator_ephemeral_private: "182b58c93fad2340de69fb6d0552da2e49076dd4234cebb83bec468a55ec7158",
    responder_private: "d029badf266e850d35eba96e36f9e4715915c2fdc87b4acdddeae3a18f02cb42",
    responder_public: "d3a425474ec8108b84396bcd7e6359173967a977a5f1683cd63d8a48508ad03b",
    responder_ephemeral_private: "e8edd8b94e9e711507abccf605273ce332f67e122a9572e79d2e07b0ba7bd45d",
    timestamp: "400000006553f10a05000000",
    initiation:
      "01000000443322116753afd63220b4bc669fc51be6a98c4ca498dc9f07cfa599ccb1ab60585ebf26ff4daeda1210129a7ae289f2" <>
        "e08f2d67ed6b3a29d9036cb70c1fefb746ef68122d380bc41954fe0663c66a116b36156f32eac6f967e7188dc05c671220d9bcb2" <>
        "4061d5e7461c776abe65f75912946c06a2130e38f001eeef43fca8f100000000000000000000000000000000",
    response:
      "0200000088776655443322119fecf3a3b59f4db692fc60bd80be4db76e002477fea089cf63780509e3b0fd01bbbc7e06808d05e4" <>
        "a8c65bd79edc09e52d38a7e43a219f4ff72f6cc2b7f930c600000000000000000000000000000000",
    initiator_keepalive: "04000000887766550000000000000000c4bfa7e570337f89d91edf4828f132e4",
    responder_keepalive: "04000000443322110000000000000000885cbca697398d78d5f38da2cb2c92dc"
  ]

  @doc "The vectors in the order `wgpeer vectors` prints them, as hex."
  def hex, do: @vectors

  @doc "One vector, decoded."
  def fetch!(name), do: @vectors |> Keyword.fetch!(name) |> Base.decode16!(case: :lower)
end
