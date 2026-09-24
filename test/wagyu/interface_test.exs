defmodule Wagyu.InterfaceTest do
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.Admission
  alias Wagyu.Packet

  setup context do
    {public_key, private_key} = keypair()
    interface = start_supervised!({Wagyu, options([private_key: private_key] ++ Map.get(context, :options, []))})
    {:ok, %{listen: %{port: port}, peers: [%{public_key: peer_key}]}} = Wagyu.info(interface)
    {:ok, client} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}, active: false])
    {:ok, stack} = Wagyu.stack(interface)

    %{
      interface: interface,
      public_key: public_key,
      peer_key: peer_key,
      port: port,
      client: client,
      stack: stack
    }
  end

  defp send_datagrams(%{client: client, port: port}, datagrams) do
    for datagram <- datagrams, do: :ok = :gen_udp.send(client, {127, 0, 0, 1}, port, datagram)
    :ok
  end

  defp running_peers(interface) do
    {:ok, %{peers: peers}} = Wagyu.info(interface)
    for %{running: true, public_key: key} <- peers, do: key
  end

  defp peer(interface, key), do: :sys.get_state(child(interface, :interface)).peers[key]

  describe "inbound datagrams" do
    test "drops datagrams that are not WireGuard messages", context do
      send_datagrams(context, ["", "hi", <<1, 0, 0, 0>>, <<9, 0, 0, 0, 0::256>>, <<4, 1, 0, 0, 0::256>>])
      assert %{datagrams: 5, invalid_datagrams: 5} = counters(context.interface, &(&1.datagrams == 5))
    end

    test "drops initiations and responses whose MAC1 is not for this interface", context do
      {other_key, _private_key} = keypair()
      response = Packet.put_mac1(<<2, 0, 0, 0, 0::size(88 * 8)>>, Packet.mac1_key(other_key))
      send_datagrams(context, [initiation(other_key), response])

      assert %{invalid_mac1: 2, initiations: 0} = counters(context.interface, &(&1.datagrams == 2))
    end

    test "hands an initiation with a valid MAC1 to a handshake worker", context do
      send_datagrams(context, [initiation(context.public_key)])

      assert %{initiations: 1, initiations_dropped: 0} = counters(context.interface, &(&1.initiations == 1))
      supervisor = child(context.interface, :handshake_supervisor)
      assert eventually(fn -> DynamicSupervisor.count_children(supervisor).active == 0 end)
      assert running_peers(context.interface) == []
    end

    test "drops indexed messages, since no receiver index is live", context do
      response = Packet.put_mac1(<<2, 0, 0, 0, 0::size(88 * 8)>>, Packet.mac1_key(context.public_key))
      cookie_reply = <<3, 0, 0, 0, 1::little-32, 0::448>>
      transport = <<4, 0, 0, 0, 1::little-32, 0::little-64, 0::128>>
      send_datagrams(context, [response, cookie_reply, transport])

      assert %{unknown_index: 3} = counters(context.interface, &(&1.datagrams == 3))
      assert running_peers(context.interface) == []
    end

    test "a flood queues bounded work and accounts for every datagram", context do
      interface = child(context.interface, :interface)
      supervisor = child(context.interface, :handshake_supervisor)
      sampler = Task.async(fn -> sample(interface, supervisor, %{mailbox: 0, workers: 0}) end)

      datagrams =
        for n <- 1..3000 do
          case rem(n, 3) do
            0 -> initiation(context.public_key)
            1 -> <<4, 0, 0, 0, n::little-32, 0::little-64, 0::128>>
            2 -> "junk #{n}"
          end
        end

      send_datagrams(context, datagrams)
      send(sampler.pid, :stop)
      maxima = Task.await(sampler)

      # The socket hands over at most 32 datagrams before it is re-armed, and
      # the only other messages are the exits of at most 8 workers.
      assert maxima.mailbox <= 48
      assert maxima.workers <= 8

      # Datagrams may still be arriving, so wait until nothing changes and no
      # handshake work is left.
      counters =
        eventually(fn ->
          before = counters(context.interface)
          Process.sleep(50)
          %{handshakes: handshakes} = :sys.get_state(interface)
          {:ok, %{counters: counters}} = Wagyu.info(context.interface)
          if counters == before and handshakes.active == 0 and handshakes.queued == 0, do: counters
        end)

      assert counters.datagrams > 0
      assert counters.invalid_mac1 == 0

      assert counters.datagrams ==
               counters.invalid_datagrams + counters.initiations + counters.initiations_dropped +
                 counters.unknown_index

      assert eventually(fn -> DynamicSupervisor.count_children(supervisor).active == 0 end)
    end

    test "refuses initiations beyond the waiting queue while every worker is busy", context do
      # Workers exit at once until responder processing exists, so occupy
      # every worker slot directly.
      interface = child(context.interface, :interface)
      :sys.replace_state(interface, &put_in(&1.handshakes.active, 8))

      send_datagrams(context, for(_n <- 1..100, do: initiation(context.public_key)))

      assert %{initiations: 0, initiations_dropped: 36} =
               counters(context.interface, &(&1.initiations_dropped == 36))

      assert :sys.get_state(interface).handshakes.queued == 64
    end
  end

  defp sample(interface, supervisor, maxima) do
    receive do
      :stop -> maxima
    after
      0 ->
        {:message_queue_len, mailbox} = Process.info(interface, :message_queue_len)
        %{active: workers} = DynamicSupervisor.count_children(supervisor)
        sample(interface, supervisor, %{mailbox: max(maxima.mailbox, mailbox), workers: max(maxima.workers, workers)})
    end
  end

  describe "egress" do
    test "the example /32 address and off-subnet gateway send egress to the peer", context do
      assert running_peers(context.interface) == []
      send_egress(open_udp(context.stack), 1)

      assert %{egress: 1, egress_routed: 1, egress_dropped: 0} =
               counters(context.interface, &(&1.egress_routed == 1))

      assert running_peers(context.interface) == [context.peer_key]
      assert [_one] = DynamicSupervisor.which_children(child(context.interface, :peer_supervisor))
    end

    test "starts one peer process per key, however much traffic it gets", context do
      send_egress(open_udp(context.stack), 20)

      assert %{egress_routed: 20} = counters(context.interface, &(&1.egress_routed == 20))
      assert [_one] = DynamicSupervisor.which_children(child(context.interface, :peer_supervisor))
    end

    @tag options: [
           peers: [%{public_key: elem(:crypto.generate_key(:ecdh, :x25519), 0), allowed_ips: [{{10, 0, 0, 0}, 8}]}]
         ]
    test "counts egress with no AllowedIPs route as unroutable", context do
      socket = open_udp(context.stack)
      send_egress(socket, 1, {10, 1, 2, 3})
      send_egress(socket, 2, {192, 0, 2, 9})

      assert %{egress_routed: 1, egress_unroutable: 2} =
               counters(context.interface, &(&1.egress_routed + &1.egress_unroutable == 3))
    end

    test "bounds each peer's outbound queue", context do
      socket = open_udp(context.stack)
      send_egress(socket, 1)
      counters(context.interface, &(&1.egress_routed == 1))
      %{pid: peer, outbound: outbound} = peer(context.interface, context.peer_key)
      assert eventually(fn -> Admission.usage(outbound) == {0, 0} end)

      :ok = :sys.suspend(peer)
      send_egress(socket, 200)

      assert %{egress_routed: 129, egress_peer_dropped: 72} =
               counters(context.interface, &(&1.egress_routed + &1.egress_peer_dropped == 201))

      assert {128, _bytes} = Admission.usage(outbound)

      :ok = :sys.resume(peer)
      assert eventually(fn -> Admission.usage(outbound) == {0, 0} end)
    end

    test "the link drops egress beyond what the interface has queued", context do
      interface = child(context.interface, :interface)
      %{egress: egress} = :sys.get_state(interface)

      :ok = :sys.suspend(interface)
      send_egress(open_udp(context.stack), 300)

      assert eventually(fn ->
               match?({:ok, %{egress: 300, egress_dropped: 44}}, Wagyu.Link.counters(context.interface))
             end)

      assert {256, _bytes} = Admission.usage(egress)

      :ok = :sys.resume(interface)

      counters =
        counters(context.interface, &(&1.egress_routed + &1.egress_peer_dropped == 256))

      assert counters.egress_unroutable == 0
      assert Admission.usage(egress) == {0, 0}
    end
  end
end
