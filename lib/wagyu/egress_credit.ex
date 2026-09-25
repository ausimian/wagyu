defmodule Wagyu.EgressCredit do
  @moduledoc false

  # Counts the egress one interface incarnation holds on the stack's behalf:
  # packets the link has handed it and that have yet to be sent, staged or
  # dropped, in the interface's mailbox or a peer's.
  #
  # The link starts the stack with a fixed egress credit and grants back only
  # what has left the interface, so the stack's credit, its batches on their
  # way to the link and this count together never exceed that credit. Only
  # the link adds to the count, as it hands packets over; the interface and
  # the peers retire them, then tell the link (`Wagyu.Link.retired/1`), which
  # reads the count again and grants the difference. The counts live in
  # `:counters`, so a count the link reads can only be stale by being too
  # high, and it never grants credit that is still held. The one exception
  # is a peer killed while it takes a packet, which may have that packet
  # retired twice (see `Wagyu.Peer`): a packet's worth too much credit,
  # which the queues' own bounds still hold, rather than credit lost for
  # good.
  #
  # The count belongs to one interface incarnation, as `Wagyu.Admission` does
  # to one receiver. When the interface exits, its peers exit with it, and
  # whatever it held is lost; its replacement starts from zero with a new
  # count, and the link stops reading the old one.

  @packets 1
  @bytes 2

  @enforce_keys [:counters]
  defstruct [:counters]

  @type t :: %__MODULE__{counters: :counters.counters_ref()}

  @spec new() :: t()
  def new, do: %__MODULE__{counters: :counters.new(2, [:atomics])}

  @doc "Adds packets the link hands the interface."
  @spec take(t(), [binary()]) :: :ok
  def take(credit, packets), do: add(credit, length(packets), Wagyu.Admission.bytes(packets))

  @doc "Retires packets that were sent, staged or dropped."
  @spec retire(t(), non_neg_integer(), non_neg_integer()) :: :ok
  def retire(credit, packets, bytes), do: add(credit, -packets, -bytes)

  @doc "Retires a list of packets."
  @spec retire_all(t(), [binary()]) :: :ok
  def retire_all(credit, packets), do: retire(credit, length(packets), Wagyu.Admission.bytes(packets))

  @doc "Returns the packets and bytes taken and not yet retired."
  @spec outstanding(t()) :: {integer(), integer()}
  def outstanding(%__MODULE__{counters: counters}),
    do: {:counters.get(counters, @packets), :counters.get(counters, @bytes)}

  defp add(%__MODULE__{counters: counters}, packets, bytes) do
    :ok = :counters.add(counters, @packets, packets)
    :ok = :counters.add(counters, @bytes, bytes)
  end
end
