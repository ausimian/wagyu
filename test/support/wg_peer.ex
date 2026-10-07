defmodule Wagyu.WgPeer do
  @moduledoc false

  # Controls `wgpeer` (test/interop), which is a wireguard-go device on the
  # userspace network stack of gVisor. That stack does not need a TUN device
  # or root. The device sends and receives WireGuard on a real UDP socket.
  # The calling process owns the port. When that process exits, the stdin of
  # wgpeer closes, and wgpeer also exits.

  @source Path.expand("../interop", __DIR__)
  @timeout 10_000

  @doc "Builds wgpeer with the `go` on the PATH, and returns the path of the binary."
  def build! do
    binary = Path.join([Mix.Project.build_path(), "interop", "wgpeer"])
    go = System.find_executable("go") || raise "the interop tests need go on the PATH"

    case System.cmd(go, ["build", "-o", binary, "."], cd: @source, stderr_to_stdout: true) do
      {_output, 0} -> binary
      {output, status} -> raise "go build exited with #{status}:\n" <> output
    end
  end

  @doc "Runs `wgpeer vectors` and returns the golden handshake transcript as `[{name, hex}]`."
  def vectors!(binary) do
    {output, 0} = System.cmd(binary, ["vectors"])

    for line <- String.split(output, "\n", trim: true) do
      [name, hex] = String.split(line, " ")
      {String.to_atom(name), hex}
    end
  end

  @doc """
  Starts a device whose netstack has `address`, and configures it with
  `uapi`. `uapi` is a keyword list of UAPI keys and values, in sequence. The
  function then brings up the device. It returns the Erlang port and the UDP
  port of the device.

  The options are:

    * `:mtu` - the MTU (default 1280)
    * `:delay` - the milliseconds that the device holds each datagram before
      it sends it (default 0)
  """
  def start!(binary, address, uapi, options \\ []) do
    mtu = Keyword.get(options, :mtu, 1280)
    delay = Keyword.get(options, :delay, 0)

    port =
      Port.open({:spawn_executable, binary}, [
        :binary,
        :exit_status,
        {:line, 65_536},
        args: ["peer", :inet.ntoa(address) |> to_string(), Integer.to_string(mtu), Integer.to_string(delay)]
      ])

    :ok = set(port, uapi)
    :ok = command(port, ["up"])
    %{"listen_port" => listen_port} = get(port).device
    {port, String.to_integer(listen_port)}
  end

  @doc """
  Changes the configuration of a running device with `uapi`, a keyword list
  of UAPI keys and values, in sequence.
  """
  def set(port, uapi), do: command(port, ["set" | Enum.map(uapi, &uapi_line/1)] ++ [""])

  @doc """
  Returns the UAPI state of the device as `%{device: fields, peers: [fields]}`.
  The fields of each peer start at its `public_key`.
  """
  def get(port) do
    Port.command(port, "get\n")

    port
    |> read_until_end([])
    |> Enum.reduce(%{device: %{}, peers: []}, fn
      {"public_key", _value} = field, acc -> %{acc | peers: [Map.new([field]) | acc.peers]}
      {key, value}, %{peers: []} = acc -> %{acc | device: Map.put(acc.device, key, value)}
      {key, value}, %{peers: [peer | peers]} = acc -> %{acc | peers: [Map.put(peer, key, value) | peers]}
    end)
    |> Map.update!(:peers, &Enum.reverse/1)
  end

  @doc "Sends one UDP datagram from the netstack of the device."
  def send_udp(port, address, udp_port, payload) do
    command(port, ["send #{:inet.ntoa(address)} #{udp_port} #{payload}"])
  end

  @doc "Echoes the UDP datagrams or TCP streams that arrive on a netstack port."
  def echo(port, protocol, netstack_port) when protocol in [:udp, :tcp],
    do: command(port, ["echo #{protocol} #{netstack_port}"])

  @doc """
  Reads each TCP connection on a netstack port until the client shuts down
  its side. Then it replies with the number of bytes that it read, in
  decimal.
  """
  def sink(port, netstack_port), do: command(port, ["sink #{netstack_port}"])

  defp command(port, lines) do
    Port.command(port, Enum.map(lines, &[&1, "\n"]))

    case read_line(port) do
      "ok" -> :ok
      "error " <> reason -> {:error, reason}
    end
  end

  defp read_until_end(port, fields) do
    case read_line(port) do
      "end" ->
        Enum.reverse(fields)

      line ->
        [key, value] = String.split(line, "=", parts: 2)
        read_until_end(port, [{key, value} | fields])
    end
  end

  defp read_line(port) do
    receive do
      {^port, {:data, {:eol, line}}} -> line
      {^port, {:exit_status, status}} -> raise "wgpeer exited with #{status}"
    after
      @timeout -> raise "wgpeer did not answer"
    end
  end

  defp uapi_line({key, <<_::binary-32>> = value}) when key in [:private_key, :public_key, :preshared_key],
    do: "#{key}=#{Base.encode16(value, case: :lower)}"

  defp uapi_line({key, value}), do: "#{key}=#{value}"
end
