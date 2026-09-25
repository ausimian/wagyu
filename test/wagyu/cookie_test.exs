defmodule Wagyu.CookieTest do
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.Cookie
  alias Wagyu.Packet
  alias Wagyu.Packet.CookieReply

  @source {{127, 0, 0, 1}, 51_820}

  defp vector(name), do: Wagyu.GoldenVectors.fetch!(name)

  defp decode(frame) do
    {:ok, message} = Packet.decode(frame)
    message
  end

  defp mac1(frame) do
    {:ok, mac1} = Packet.mac1(frame)
    mac1
  end

  # The cookie in a reply to `frame`, sent to the holder of `public_key`.
  defp opened(reply, public_key, frame), do: Cookie.open(decode(reply), Cookie.key(public_key), mac1(frame))

  describe "the golden transcript" do
    test "reproduces the cookie, the cookie reply and the initiation's MAC2" do
      responder_public = vector(:responder_public)
      initiation = vector(:initiation)

      cookie = Cookie.make(vector(:cookie_secret), @source)
      assert cookie == vector(:cookie)
      assert Cookie.key(responder_public) == :crypto.hash(:blake2s, "cookie--" <> responder_public)

      reply = Cookie.seal(Cookie.key(responder_public), cookie, 0x11223344, vector(:cookie_nonce), mac1(initiation))
      assert reply == vector(:cookie_reply)
      assert %CookieReply{receiver_index: 0x11223344} = decode(reply)
      assert opened(reply, responder_public, initiation) == {:ok, cookie}

      with_mac2 = Packet.put_macs(initiation, Packet.mac1_key(responder_public), cookie)
      assert with_mac2 == vector(:initiation_mac2)
      assert Packet.valid_mac1?(with_mac2, Packet.mac1_key(responder_public))
      assert Packet.valid_mac2?(with_mac2, cookie)
      refute Packet.valid_mac2?(initiation, cookie)
    end

    test "refuses the reply with another MAC1, another public key or a changed byte" do
      responder_public = vector(:responder_public)
      reply = vector(:cookie_reply)
      <<head::binary-32, first, rest::binary>> = reply

      assert opened(reply, responder_public, vector(:response)) == :error
      assert opened(reply, vector(:initiator_public), vector(:initiation)) == :error

      assert opened(<<head::binary, Bitwise.bxor(first, 1), rest::binary>>, responder_public, vector(:initiation)) ==
               :error
    end
  end

  describe "a receiver's cookies" do
    setup do
      {public_key, _private_key} = keypair()
      frame = initiation(public_key)
      %{public_key: public_key, checker: Cookie.checker(public_key), frame: frame}
    end

    # A cookie reply to `frame` from `source` at `now`, and the cookie in it.
    defp reply(context, checker, source, now) do
      {reply, checker} = Cookie.reply(checker, context.frame, 7, source, now)
      assert %CookieReply{receiver_index: 7} = decode(reply)
      {:ok, cookie} = opened(reply, context.public_key, context.frame)
      {cookie, checker}
    end

    defp with_mac2(context, cookie), do: Packet.put_macs(context.frame, Packet.mac1_key(context.public_key), cookie)

    test "no MAC2 is valid before the first reply makes a secret", context do
      refute Cookie.valid_mac2?(context.checker, context.frame, @source, 0)
      refute Cookie.valid_mac2?(context.checker, with_mac2(context, <<0::128>>), @source, 0)
    end

    test "a cookie is bound to the address and port the message came from", context do
      {cookie, checker} = reply(context, context.checker, @source, 0)
      frame = with_mac2(context, cookie)

      assert Cookie.valid_mac2?(checker, frame, @source, 1)
      refute Cookie.valid_mac2?(checker, frame, {{127, 0, 0, 1}, 51_821}, 1)
      refute Cookie.valid_mac2?(checker, frame, {{127, 0, 0, 2}, 51_820}, 1)
      refute Cookie.valid_mac2?(checker, context.frame, @source, 1)

      # The address is 4 or 16 bytes, so IPv4 and IPv6 cookies never collide.
      v6 = {{0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 1}, 51_820}
      {v6_cookie, checker} = reply(context, checker, v6, 2)
      refute v6_cookie == cookie
      assert Cookie.valid_mac2?(checker, with_mac2(context, v6_cookie), v6, 3)
      refute Cookie.valid_mac2?(checker, frame, v6, 3)
    end

    test "the secret, and every cookie from it, expires 120 seconds after it was made", context do
      {cookie, checker} = reply(context, context.checker, @source, 1_000)
      frame = with_mac2(context, cookie)

      # A reply within the secret's lifetime reuses it.
      {same, checker} = reply(context, checker, @source, 60_000)
      assert same == cookie

      assert Cookie.valid_mac2?(checker, frame, @source, 120_999)
      refute Cookie.valid_mac2?(checker, frame, @source, 121_000)

      # The next reply makes a new secret, and the old cookie stays invalid.
      {fresh, checker} = reply(context, checker, @source, 121_000)
      refute fresh == cookie
      refute Cookie.valid_mac2?(checker, frame, @source, 121_000)
      assert Cookie.valid_mac2?(checker, with_mac2(context, fresh), @source, 121_000)
    end

    test "each reply has a fresh nonce, and the secret is not in the checker's inspection", context do
      {first, checker} = Cookie.reply(context.checker, context.frame, 7, @source, 0)
      {second, checker} = Cookie.reply(checker, context.frame, 7, @source, 0)
      refute decode(first).nonce == decode(second).nonce

      refute inspect(checker) =~ inspect(checker.secret)
      refute inspect(checker) =~ "secret"
    end
  end
end
