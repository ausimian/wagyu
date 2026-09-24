defmodule Wagyu.HandshakeQueue do
  @moduledoc false

  # Admission for inbound handshake initiations.
  #
  # Responder Noise work is the only expensive thing an unauthenticated
  # sender can trigger, so it is bounded twice: at most `max_active` workers
  # run at once, and at most `max_queued` fixed-size frames wait for a free
  # worker. Anything beyond that is refused, failing closed under load. The
  # interface keeps this structure in its state; a worker's slot is released
  # when the worker exits or fails to start.

  @max_active 8
  @max_queued 64

  defstruct active: 0, queued: 0, queue: :queue.new(), max_active: @max_active, max_queued: @max_queued

  @type t :: %__MODULE__{
          active: non_neg_integer(),
          queued: non_neg_integer(),
          queue: :queue.queue(term()),
          max_active: pos_integer(),
          max_queued: non_neg_integer()
        }

  @spec new(keyword()) :: t()
  def new(options \\ []), do: struct!(__MODULE__, options)

  @doc """
  Admits a candidate. Returns `{:start, candidate, queue}` when a worker slot
  is free, `{:queued, queue}` when it must wait, and `:full` when it is
  refused.
  """
  @spec admit(t(), term()) :: {:start, term(), t()} | {:queued, t()} | :full
  def admit(%__MODULE__{active: active, max_active: max} = queue, candidate) when active < max,
    do: {:start, candidate, %{queue | active: active + 1}}

  def admit(%__MODULE__{queued: queued, max_queued: max} = queue, candidate) when queued < max,
    do: {:queued, %{queue | queued: queued + 1, queue: :queue.in(candidate, queue.queue)}}

  def admit(%__MODULE__{}, _candidate), do: :full

  @doc """
  Releases a worker slot. The oldest waiting candidate takes it, as
  `{:start, candidate, queue}`; with none waiting the slot is freed.
  """
  @spec release(t()) :: {:start, term(), t()} | {:idle, t()}
  def release(%__MODULE__{active: active} = queue) when active > 0 do
    case :queue.out(queue.queue) do
      {{:value, candidate}, rest} -> {:start, candidate, %{queue | queued: queue.queued - 1, queue: rest}}
      {:empty, _rest} -> {:idle, %{queue | active: active - 1}}
    end
  end
end
