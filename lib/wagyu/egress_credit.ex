defmodule Wagyu.EgressCredit do
  @moduledoc false

  # Counts the egress that one interface incarnation holds for the stack.
  # These are the packets that the link gave to the interface and that are
  # not yet sent, staged or dropped. The packets are in the mailbox of the
  # interface or of a peer.
  #
  # The link starts the stack with a fixed egress credit. It grants back
  # only the credit for packets that left the interface. Thus the credit of
  # the stack, its batches in transit to the link and this count together
  # never exceed that credit. Only the link adds to the count, when it gives
  # packets to the interface. The interface retires the packets and then
  # tells the link (`Wagyu.Link.retired/1`). The link then reads the count
  # again and grants the difference.
  #
  # The counts are in `:counters` that both processes share. Only the link
  # adds to them. Thus a value that the link reads can be old in only one
  # way: it can be too high. As a result, the link never grants credit that
  # is still in use.
  #
  # The count belongs to one interface incarnation, the same as a
  # `Wagyu.Admission` belongs to one receiver. When the interface exits, its
  # peers also exit, and the interface loses all packets that it held. Its
  # replacement starts from zero with a new count, and the link no longer
  # reads the old count.

  @packets 1
  @bytes 2

  @enforce_keys [:counters]
  defstruct [:counters]

  @type t :: %__MODULE__{counters: :counters.counters_ref()}

  @spec new() :: t()
  def new, do: %__MODULE__{counters: :counters.new(2, [:atomics])}

  @doc "Adds the packets that the link gives to the interface."
  @spec take(t(), [binary()]) :: :ok
  def take(credit, packets), do: add(credit, length(packets), Wagyu.Admission.bytes(packets))

  @doc "Retires packets that were sent, staged or dropped."
  @spec retire(t(), non_neg_integer(), non_neg_integer()) :: :ok
  def retire(credit, packets, bytes), do: add(credit, -packets, -bytes)

  @doc "Retires a list of packets."
  @spec retire_all(t(), [binary()]) :: :ok
  def retire_all(credit, packets), do: retire(credit, length(packets), Wagyu.Admission.bytes(packets))

  @doc "Returns the packets and bytes that are taken but not retired."
  @spec outstanding(t()) :: {non_neg_integer(), non_neg_integer()}
  def outstanding(%__MODULE__{counters: counters}),
    do: {:counters.get(counters, @packets), :counters.get(counters, @bytes)}

  defp add(%__MODULE__{counters: counters}, packets, bytes) do
    :ok = :counters.add(counters, @packets, packets)
    :ok = :counters.add(counters, @bytes, bytes)
  end
end
