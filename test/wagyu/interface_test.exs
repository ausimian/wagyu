defmodule Wagyu.InterfaceTest do
  use ExUnit.Case, async: true

  import Wagyu.TestHelpers

  alias Wagyu.Admission
  alias Wagyu.EgressCredit
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

  # Waits until the counters stop changing, and returns them.
  defp settled(interface) do
    eventually(fn ->
      before = counters(interface)
      Process.sleep(50)
      if counters(interface) == before, do: before
    end)
  end

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

    test "hands an initiation with a valid MAC1 to a handshake worker, which drops a forged one", context do
      send_datagrams(context, [initiation(context.public_key)])

      assert %{initiations: 1, initiations_dropped: 0, initiations_failed: 1} =
               counters(context.interface, &(&1.initiations_failed == 1))

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

      # The socket gives a maximum of 32 datagrams before the interface arms
      # it again. The only other messages are the exits of a maximum of 8
      # workers.
      assert maxima.mailbox <= 48
      assert maxima.workers <= 8

      # More datagrams can arrive. Thus, wait until nothing changes and no
      # handshake work remains.
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
                 counters.unknown_index + counters.cookie_replies_sent

      # The Noise fields of each initiation are random, so all of them fail.
      assert counters.initiations_failed == counters.initiations

      assert eventually(fn -> DynamicSupervisor.count_children(supervisor).active == 0 end)
    end

    test "while every worker is busy, 8 initiations wait and the rest get cookie replies", context do
      # Workers complete quickly. Thus, fill all worker slots directly.
      interface = child(context.interface, :interface)
      :sys.replace_state(interface, &put_in(&1.handshakes.active, 8))

      send_datagrams(context, for(_n <- 1..100, do: initiation(context.public_key)))

      # When 8 initiations wait, the interface is under load. Then an
      # initiation without a MAC2 gets a cookie reply, not a place in the
      # queue. UDP can lose some of the burst. Thus, compare with the
      # datagrams that arrived.
      counters = settled(context.interface)
      assert counters.datagrams > 8
      assert counters.initiations == 0
      assert counters.initiations_dropped == 0
      assert counters.cookie_replies_sent == counters.datagrams - 8
      assert :sys.get_state(interface).handshakes.queued == 8
    end

    test "refuses initiations beyond the waiting queue, even with a valid MAC2", context do
      interface = child(context.interface, :interface)
      waiting = for _n <- 1..63, do: %{frame: initiation(context.public_key), source: {{127, 0, 0, 1}, 9}}

      :sys.replace_state(interface, fn state ->
        %{state | handshakes: %{state.handshakes | active: 8, queued: 63, queue: :queue.from_list(waiting)}}
      end)

      frame = initiation(context.public_key)
      send_datagrams(context, [frame])
      assert {:ok, {{127, 0, 0, 1}, _port, reply}} = :gen_udp.recv(context.client, 0, 1_000)
      cookie = cookie(reply, context.public_key, frame)

      # With the cookie, one more initiation waits, and the interface refuses
      # the next initiation.
      send_datagrams(
        context,
        for(_n <- 1..2, do: with_mac2(initiation(context.public_key), context.public_key, cookie))
      )

      assert %{initiations_dropped: 1, cookie_replies_sent: 1} = settled(context.interface)
      assert :sys.get_state(interface).handshakes.queued == 64
    end

    test "reads whole datagrams of any size and buffers bursts", context do
      %{socket: socket} = :sys.get_state(child(context.interface, :interface))
      {:ok, options} = :inet.getopts(socket, [:buffer, :recbuf])

      assert options[:buffer] >= 65_507
      assert options[:recbuf] >= 65_536
    end

    test "stops when its socket closes", context do
      interface = child(context.interface, :interface)
      %{socket: socket} = :sys.get_state(interface)
      monitor = Process.monitor(interface)

      :ok = :gen_udp.close(socket)

      assert_receive {:DOWN, ^monitor, :process, ^interface, {:shutdown, {:socket_closed, :closed}}}
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

    test "a peer that falls behind holds egress back in the stack instead of dropping it", context do
      %{credit: credit} = :sys.get_state(child(context.interface, :interface))
      socket = open_udp(context.stack)
      send_egress(socket, 1)
      counters(context.interface, &(&1.egress_routed == 1))
      %{pid: peer, outbound: outbound} = peer(context.interface, context.peer_key)
      assert eventually(fn -> Admission.usage(outbound) == {0, 0} end)
      assert eventually(fn -> EgressCredit.outstanding(credit) == {0, 0} end)

      # The stack sends only the quantity that the credit of the link allows.
      # That quantity fits in the queue of the peer. The remaining data waits
      # in the socket.
      :ok = :sys.suspend(peer)
      sender = Task.async(fn -> send_egress(socket, 200) end)
      assert eventually(fn -> match?({128, _bytes}, Admission.usage(outbound)) end)
      assert {128, _bytes} = EgressCredit.outstanding(credit)
      assert {:ok, %{egress: 129, egress_dropped: 0}} = Wagyu.Link.counters(context.interface)
      assert %{egress_routed: 129, egress_peer_dropped: 0} = counters(context.interface)

      # The peer has no key. Thus it stages the packets that it takes, in the
      # limit of its own bound. Each packet that it takes releases credit for
      # the next packet.
      :ok = :sys.resume(peer)
      assert :ok = Task.await(sender)

      assert %{egress_routed: 201, egress_peer_dropped: 0, staged_dropped: 73} =
               counters(context.interface, &(&1.egress_routed == 201 and &1.staged_dropped == 73))

      assert eventually(fn -> Admission.usage(outbound) == {0, 0} end)
      assert eventually(fn -> EgressCredit.outstanding(credit) == {0, 0} end)
    end

    # When the test kills the peer, the peer logs its exit.
    @tag :capture_log
    test "counts what a peer never took as dropped when it exits", context do
      socket = open_udp(context.stack)
      send_egress(socket, 1)
      counters(context.interface, &(&1.egress_routed == 1))
      %{pid: peer, outbound: outbound} = peer(context.interface, context.peer_key)
      assert eventually(fn -> Admission.usage(outbound) == {0, 0} end)

      :ok = :sys.suspend(peer)
      send_egress(socket, 10)
      assert eventually(fn -> match?({10, _bytes}, Admission.usage(outbound)) end)

      Process.exit(peer, :kill)

      # The peer took the first packet, which waited for a key. Thus the
      # packet is also lost with the peer. The ten packets that the peer did
      # not take release their credit.
      assert %{egress_routed: 11, egress_peer_dropped: 11} =
               counters(context.interface, &(&1.egress_peer_dropped == 11))

      assert running_peers(context.interface) == []
      %{credit: credit} = :sys.get_state(child(context.interface, :interface))
      assert EgressCredit.outstanding(credit) == {0, 0}
      send_egress(socket, 1)
      assert %{egress_routed: 12} = counters(context.interface, &(&1.egress_routed == 12))
    end

    # When the test kills the interface, the interface logs its exit.
    @tag :capture_log
    test "counts egress lost with an interface that dies part-way through routing it", context do
      interface = child(context.interface, :interface)
      %{egress: egress} = :sys.get_state(interface)

      # The peer supervisor is suspended. Thus the interface blocks when it
      # starts the peer for the first packet. It holds that packet before
      # the route is complete.
      :ok = :sys.suspend(child(context.interface, :peer_supervisor))
      send_egress(open_udp(context.stack), 3)
      assert eventually(fn -> match?({3, _bytes}, Admission.usage(egress)) end)

      Process.exit(interface, :kill)

      assert eventually(fn ->
               match?({:ok, %{egress: 3, egress_dropped: 3}}, Wagyu.Link.counters(context.interface))
             end)
    end

    test "an interface that falls behind holds egress back in the stack instead of dropping it", context do
      interface = child(context.interface, :interface)
      %{egress: egress, credit: credit} = :sys.get_state(interface)

      :ok = :sys.suspend(interface)
      sender = Task.async(fn -> send_egress(open_udp(context.stack), 300) end)

      assert eventually(fn -> match?({128, _bytes}, Admission.usage(egress)) end)
      assert {128, _bytes} = EgressCredit.outstanding(credit)
      assert {:ok, %{egress: 128, egress_dropped: 0}} = Wagyu.Link.counters(context.interface)

      :ok = :sys.resume(interface)
      assert :ok = Task.await(sender)

      counters = counters(context.interface, &(&1.egress_routed == 300))
      assert %{egress_peer_dropped: 0, egress_unroutable: 0} = counters
      assert {:ok, %{egress: 300, egress_dropped: 0}} = Wagyu.Link.counters(context.interface)
      assert eventually(fn -> Admission.usage(egress) == {0, 0} end)
      assert eventually(fn -> EgressCredit.outstanding(credit) == {0, 0} end)
    end

    # When the test kills the interface, the interface logs its exit.
    @tag :capture_log
    test "the stack gets back the credit of egress lost with an interface", context do
      interface = child(context.interface, :interface)
      socket = open_udp(context.stack)

      # The suspended interface holds all the credit when the test kills it.
      :ok = :sys.suspend(interface)
      sender = Task.async(fn -> send_egress(socket, 129) end)
      assert eventually(fn -> match?({:ok, %{egress: 128}}, Wagyu.Link.counters(context.interface)) end)
      Process.exit(interface, :kill)
      assert :ok = Task.await(sender)

      # The 129th packet goes out after the link grants the lost credit
      # again. It goes to the new interface. If the new interface is not yet
      # registered, the link drops the packet.
      assert eventually(fn ->
               match?(
                 {:ok, %{egress: 129, egress_dropped: dropped}} when dropped >= 128,
                 Wagyu.Link.counters(context.interface)
               )
             end)

      assert eventually(fn -> child(context.interface, :interface) != interface end)
      send_egress(socket, 1)
      assert counters(context.interface, &(&1.egress_routed >= 1))
    end
  end
end
