defmodule Wagyu.Interface.Supervisor do
  @moduledoc false

  # The root of one interface, and the PID that `Wagyu.start_link/1`
  # returns. The strategy is `:rest_for_one`, and the sequence of the
  # children sets the failure domains:
  #
  #   * The link and the SmolNet stack that it owns come first. Thus a
  #     failure of the link or the stack restarts all children, and the
  #     application sockets become invalid.
  #   * A failure of the interface restarts the interface, the handshake
  #     workers and the peers. The link, the stack and the open sockets
  #     stay.
  #   * A failure of the peer supervisor restarts only the peers.
  #
  # Children find one another through `Wagyu.Registry`, with the PID of this
  # supervisor as the key. The link is the first child. Thus, if the
  # registry restarts and loses the registrations, the exit of the link
  # starts the complete interface again, and the children register again.
  #
  # The start argument is the validated configuration. Its `Inspect`
  # implementation hides its keys. Thus supervisor reports never show the
  # raw keys.

  use Supervisor

  alias Wagyu.AllowedIPs
  alias Wagyu.Config

  @spec start_link(Config.t()) :: Supervisor.on_start()
  def start_link(%Config{} = config), do: Supervisor.start_link(__MODULE__, config, name: config.name)

  @impl true
  def init(%Config{} = config) do
    root = self()

    # Workers and peers need the local key pair and the stack settings. They
    # do not need the peer table, because only the interface uses it.
    # Without the table, the copy for each child stays small.
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
