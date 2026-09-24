defmodule Wagyu.Interface.Supervisor do
  @moduledoc false

  # The root of one interface, and the PID that `Wagyu.start_link/1`
  # returns. `:rest_for_one` over the children in this order sets the
  # failure domains:
  #
  #   * the link, and the SmolNet stack it owns, comes first, so a link or
  #     stack failure restarts everything and invalidates application
  #     sockets;
  #   * an interface failure restarts the interface, the handshake workers
  #     and the peers, but keeps the link, the stack and open sockets;
  #   * a peer supervisor failure restarts only the peers.
  #
  # Children find one another through `Wagyu.Registry`, keyed by this
  # supervisor's PID. The link is the first child, so if the registry
  # restarts and loses their registrations, the link's exit rebuilds the
  # whole interface and the children register again.
  #
  # The start argument is the validated configuration, whose `Inspect`
  # implementation hides its keys, so supervisor reports never print them
  # raw.

  use Supervisor

  alias Wagyu.AllowedIPs
  alias Wagyu.Config

  @spec start_link(Config.t()) :: Supervisor.on_start()
  def start_link(%Config{} = config), do: Supervisor.start_link(__MODULE__, config, name: config.name)

  @impl true
  def init(%Config{} = config) do
    root = self()

    # Workers and peers need the local key pair and stack settings, not the
    # peer table, which only the interface consults. Leaving it out keeps
    # each child's copy small.
    identity = %Config{config | peers: %{}, allowed_ips: %AllowedIPs{}}

    children = [
      {Wagyu.Link, root: root, stack: config.stack},
      {Wagyu.Interface, {root, config}},
      {Wagyu.HandshakeSupervisor, {root, identity}},
      {Wagyu.PeerSupervisor, {root, identity}}
    ]

    Supervisor.init(children, strategy: :rest_for_one)
  end
end
