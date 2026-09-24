defmodule Wagyu.Admission do
  @moduledoc false

  # Bounds one process's mailbox in packets and bytes.
  #
  # A sender admits a message before sending it, and the receiver releases it
  # when it takes the message off its mailbox, so the mailbox never holds
  # more than the bound. The counts live in `:counters`, which both sides
  # update without messaging each other. A sender adds first and backs out
  # when the total is over the bound, so concurrent senders may refuse
  # needlessly near the limit but never overshoot it.
  #
  # The counts belong to one receiver incarnation. A receiver that exits
  # with admitted messages unread takes its counts with it; its replacement
  # starts from zero with a new `Admission`.

  @packets 1
  @bytes 2

  @enforce_keys [:counters, :max_packets, :max_bytes]
  defstruct [:counters, :max_packets, :max_bytes]

  @type t :: %__MODULE__{
          counters: :counters.counters_ref(),
          max_packets: pos_integer(),
          max_bytes: pos_integer()
        }

  @spec new(pos_integer(), pos_integer()) :: t()
  def new(max_packets, max_bytes) when max_packets > 0 and max_bytes > 0 do
    %__MODULE__{counters: :counters.new(2, [:atomics]), max_packets: max_packets, max_bytes: max_bytes}
  end

  @doc "Admits one message of `packets` packets and `bytes` bytes, or returns `:full`."
  @spec admit(t(), pos_integer(), non_neg_integer()) :: :ok | :full
  def admit(%__MODULE__{counters: counters} = admission, packets, bytes) do
    :ok = :counters.add(counters, @packets, packets)
    :ok = :counters.add(counters, @bytes, bytes)

    if :counters.get(counters, @packets) > admission.max_packets or
         :counters.get(counters, @bytes) > admission.max_bytes do
      release(admission, packets, bytes)
      :full
    else
      :ok
    end
  end

  @doc """
  Admits `packets` in order until one does not fit, and returns the admitted
  prefix and the number refused. The caller sends the prefix as one message
  and the receiver releases it with `release_all/2`.
  """
  @spec admit_prefix(t(), [binary()]) :: {[binary()], non_neg_integer()}
  def admit_prefix(admission, packets), do: admit_prefix(admission, packets, [])

  defp admit_prefix(_admission, [], admitted), do: {Enum.reverse(admitted), 0}

  defp admit_prefix(admission, [packet | rest] = packets, admitted) do
    case admit(admission, 1, byte_size(packet)) do
      :ok -> admit_prefix(admission, rest, [packet | admitted])
      :full -> {Enum.reverse(admitted), length(packets)}
    end
  end

  @doc "Releases a message the receiver has taken off its mailbox."
  @spec release(t(), non_neg_integer(), non_neg_integer()) :: :ok
  def release(%__MODULE__{counters: counters}, packets, bytes) do
    :ok = :counters.sub(counters, @packets, packets)
    :ok = :counters.sub(counters, @bytes, bytes)
  end

  @doc "Releases a list of packets admitted with `admit_prefix/2`."
  @spec release_all(t(), [binary()]) :: :ok
  def release_all(admission, packets), do: release(admission, length(packets), bytes(packets))

  @doc "Returns the packets and bytes admitted and not yet released."
  @spec usage(t()) :: {non_neg_integer(), non_neg_integer()}
  def usage(%__MODULE__{counters: counters}), do: {:counters.get(counters, @packets), :counters.get(counters, @bytes)}

  @spec bytes([binary()]) :: non_neg_integer()
  def bytes(packets), do: Enum.reduce(packets, 0, &(byte_size(&1) + &2))
end
