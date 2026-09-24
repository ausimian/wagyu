defmodule Wagyu.TAI64N do
  @moduledoc false

  # TAI64N timestamps for WireGuard handshake initiations.
  #
  # A timestamp is 12 bytes: an 8-byte big-endian TAI64 label (the base
  # 0x400000000000000a plus Unix seconds) followed by a 4-byte big-endian
  # nanosecond count. Responders keep the greatest timestamp they have
  # accepted from each peer and compare new ones byte by byte, so the value
  # must come from the wall clock: a monotonic source restarts lower after a
  # node restart, and every responder would then reject it as a replay.
  #
  # Like wireguard-go and Linux, nanoseconds are rounded down to a multiple of
  # 2^24 (about 16.8 ms) so that initiations do not leak fine-grained timing.

  import Bitwise

  @base 0x400000000000000A
  @nanos_per_second 1_000_000_000
  @step 0x1000000
  @reserved_label 0x8000000000000000

  @typedoc "A 12-byte TAI64N timestamp."
  @type t :: <<_::96>>

  @doc "Returns the current wall-clock timestamp."
  @spec now() :: t()
  def now, do: from_unix(System.os_time(:nanosecond))

  @doc """
  Encodes nanoseconds since the Unix epoch, rounding down to a multiple of 2^24
  nanoseconds within the second.
  """
  @spec from_unix(integer()) :: t()
  def from_unix(nanoseconds) when is_integer(nanoseconds) do
    seconds = Integer.floor_div(nanoseconds, @nanos_per_second)
    nanos = Integer.mod(nanoseconds, @nanos_per_second)
    <<@base + seconds::64, round_down(nanos)::32>>
  end

  @doc """
  Decodes a timestamp to nanoseconds since the Unix epoch.

  Returns `{:error, :invalid_timestamp}` for anything that is not 12 bytes, has
  a nanosecond field of a second or more, or uses a reserved TAI64 label
  (2^63 and above). It never raises.
  """
  @spec to_unix(term()) :: {:ok, integer()} | {:error, :invalid_timestamp}
  def to_unix(<<label::64, nanos::32>>) when label < @reserved_label and nanos < @nanos_per_second do
    {:ok, (label - @base) * @nanos_per_second + nanos}
  end

  def to_unix(_timestamp), do: {:error, :invalid_timestamp}

  @doc """
  Returns `true` when `timestamp` is strictly later than `previous`.

  This is the responder's replay rule: the 12 bytes compare as one big-endian
  number. Anything that is not a pair of 12-byte timestamps returns `false`,
  so a malformed value is never accepted as newer.
  """
  @spec after?(term(), term()) :: boolean()
  def after?(<<timestamp::binary-size(12)>>, <<previous::binary-size(12)>>), do: timestamp > previous
  def after?(_timestamp, _previous), do: false

  @doc """
  Returns the timestamp for this peer's next initiation, given the one it sent
  last (or `nil` if it has sent none).

  The result is `current`, the wall-clock timestamp by default, when that is
  later than `previous`. Otherwise, for initiations within one 2^24 ns window
  or after the wall clock steps backwards, it is the next rounded value after
  `previous`, so the timestamps a peer sends are strictly increasing.
  """
  @spec next(t() | nil, t()) :: t()
  def next(previous, current \\ now())

  def next(nil, <<_::binary-size(12)>> = current), do: current

  def next(<<label::64, nanos::32>> = previous, <<_::binary-size(12)>> = current) do
    if current > previous do
      current
    else
      case round_down(nanos) + @step do
        nanos when nanos < @nanos_per_second -> <<label::64, nanos::32>>
        _overflow -> <<label + 1::64, 0::32>>
      end
    end
  end

  defp round_down(nanos), do: nanos &&& bnot(@step - 1)
end
