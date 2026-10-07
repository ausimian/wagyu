# Helpers for the scripts in bench/. Each script loads this file with
# `Code.require_file/2`.

defmodule Wagyu.Bench.Throughput do
  @moduledoc false

  @chunk 64 * 1024
  @tunnel_a {10, 13, 0, 2}
  @tunnel_b {10, 13, 0, 1}
  @drops [:egress_peer_dropped, :inbound_peer_dropped, :staged_dropped]

  @doc "Starts two interfaces that are peers of each other, and completes their handshake."
  def tunnel(mtu) do
    {a_public, a_private} = :crypto.generate_key(:ecdh, :x25519)
    {b_public, b_private} = :crypto.generate_key(:ecdh, :x25519)
    {a_port, b_port} = {free_port(), free_port()}

    a = interface(a_private, a_port, @tunnel_a, @tunnel_b, b_public, b_port, mtu)
    b = interface(b_private, b_port, @tunnel_b, @tunnel_a, a_public, a_port, mtu)
    {:ok, a_stack} = Wagyu.stack(a)
    {:ok, b_stack} = Wagyu.stack(b)

    tunnel = %{interface: a, peer_interface: b, from: a_stack, to: b_stack, address: @tunnel_b}
    connections = connect(tunnel, 1)
    :ok = transfer(connections, 1024 * 1024)
    close(connections)
    tunnel
  end

  @doc "Starts a SmolNet loopback stack. The egress of this stack goes to its own ingress."
  def loopback(mtu) do
    {:ok, _link, stack} = SmolNet.Loopback.start_link(addresses: [{{127, 0, 0, 1}, 8}], mtu: mtu)
    %{from: stack, to: stack, address: {127, 0, 0, 1}}
  end

  @doc """
  Opens `streams` connections from `from` to a listener on `to`. Each end of
  a connection has its own process. All runs use the same connections. The
  reason is that the socket that closes first keeps its slot through
  TIME_WAIT, for about 10 seconds. A stack has 64 slots by default. Thus, a
  new connection for each run would soon use all the slots.
  """
  def connect(%{from: from, to: to, address: address}, streams) do
    port = 10_000 + rem(System.unique_integer([:positive, :monotonic]), 50_000)
    {:ok, listener} = :gen_tcp.listen(port, tcp_options(to) ++ [ip: address, backlog: streams])
    # Open one connection at a time. A listener does one accept at a time,
    # and a burst of connects can overflow its backlog. Each accepted socket
    # goes to the process that receives on it.
    pairs =
      for _stream <- 1..streams do
        sender = spawn_link(fn -> sender(from, address, port) end)
        {:ok, socket} = :gen_tcp.accept(listener, 30_000)
        receiver = spawn_link(fn -> receive(do: ({:socket, socket} -> receiver(socket))) end)
        :ok = :gen_tcp.controlling_process(socket, receiver)
        send(receiver, {:socket, socket})
        {sender, receiver}
      end

    {senders, receivers} = Enum.unzip(pairs)
    %{streams: streams, senders: senders, receivers: receivers, listener: listener}
  end

  @doc "Sends `bytes` through `connections`, divided equally, and waits until all of it arrives."
  def transfer(%{senders: senders, receivers: receivers}, bytes) do
    per_stream = div(bytes, length(senders))
    for pid <- senders ++ receivers, do: send(pid, {:transfer, per_stream, self()})
    for pid <- senders ++ receivers, do: receive(do: ({:done, ^pid} -> :ok))
    :ok
  end

  @doc "Closes the connections and their listener."
  def close(%{senders: senders, receivers: receivers, listener: listener}) do
    for pid <- senders ++ receivers, do: send(pid, {:close, self()})
    for pid <- senders ++ receivers, do: receive(do: ({:done, ^pid} -> :ok))
    :gen_tcp.close(listener)
  end

  @doc "Returns the drop counters of the interface."
  def drops(interface) do
    {:ok, %{counters: counters}} = Wagyu.info(interface)
    Map.take(counters, @drops)
  end

  defp interface(private_key, port, address, gateway, peer_key, peer_port, mtu) do
    {:ok, interface} =
      Wagyu.start_link(
        private_key: private_key,
        listen: %{address: {127, 0, 0, 1}, port: port},
        stack: [addresses: [{address, 32}], routes: [{{0, 0, 0, 0}, 0, gateway}], mtu: mtu],
        peers: [
          %{
            public_key: peer_key,
            endpoint: %{address: {127, 0, 0, 1}, port: peer_port},
            allowed_ips: [{{0, 0, 0, 0}, 0}]
          }
        ]
      )

    interface
  end

  defp free_port do
    {:ok, socket} = :gen_udp.open(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(socket)
    :ok = :gen_udp.close(socket)
    port
  end

  defp tcp_options(stack), do: [{:tcp_module, SmolNet.Inet.Tcp}, {:smolnet_stack, stack}, :inet, :binary, active: false]

  defp sender(stack, address, port) do
    {:ok, socket} = :gen_tcp.connect(address, port, tcp_options(stack), 30_000)
    chunk = :crypto.strong_rand_bytes(@chunk)
    serve(socket, fn bytes -> send_bytes(socket, chunk, bytes) end)
  end

  defp receiver(socket), do: serve(socket, fn bytes -> receive_bytes(socket, bytes) end)

  defp serve(socket, transfer) do
    receive do
      {:transfer, bytes, from} ->
        transfer.(bytes)
        send(from, {:done, self()})
        serve(socket, transfer)

      {:close, from} ->
        :gen_tcp.close(socket)
        send(from, {:done, self()})
    end
  end

  defp send_bytes(_socket, _chunk, bytes) when bytes <= 0, do: :ok

  defp send_bytes(socket, chunk, bytes) do
    :ok = :gen_tcp.send(socket, binary_part(chunk, 0, min(bytes, @chunk)))
    send_bytes(socket, chunk, bytes - @chunk)
  end

  defp receive_bytes(_socket, bytes) when bytes <= 0, do: :ok

  defp receive_bytes(socket, bytes) do
    {:ok, data} = :gen_tcp.recv(socket, 0, 30_000)
    receive_bytes(socket, bytes - byte_size(data))
  end
end
