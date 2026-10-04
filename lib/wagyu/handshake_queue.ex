defmodule Wagyu.HandshakeQueue do
  @moduledoc false

  # Admission for inbound handshake initiations.
  #
  # Responder Noise work is the only expensive work that an unauthenticated
  # sender can cause. Thus it has two bounds:
  #
  #   * At most `max_active` workers run at the same time.
  #   * At most `max_queued` fixed-size frames wait for a free worker.
  #
  # The queue refuses all other candidates, so under load it fails closed.
  # The interface keeps this structure in its state. A worker's slot is
  # released when the worker exits or does not start.

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
  Admits a candidate. Returns one of these values:

    * `{:start, candidate, queue}` if a worker slot is free.
    * `{:queued, queue}` if the candidate must wait.
    * `:full` if the queue refuses the candidate.
  """
  @spec admit(t(), term()) :: {:start, term(), t()} | {:queued, t()} | :full
  def admit(%__MODULE__{active: active, max_active: max} = queue, candidate) when active < max,
    do: {:start, candidate, %{queue | active: active + 1}}

  def admit(%__MODULE__{queued: queued, max_queued: max} = queue, candidate) when queued < max,
    do: {:queued, %{queue | queued: queued + 1, queue: :queue.in(candidate, queue.queue)}}

  def admit(%__MODULE__{}, _candidate), do: :full

  @doc """
  Returns whether candidates fill at least an eighth of the waiting room (8
  of 64 by default). At this load, wireguard-go and Linux start to require
  cookies. Candidates wait only while every worker is busy.
  """
  @spec loaded?(t()) :: boolean()
  def loaded?(%__MODULE__{queued: queued, max_queued: max}), do: queued > 0 and queued * 8 >= max

  @doc """
  Releases a worker slot. The oldest waiting candidate takes it, as
  `{:start, candidate, queue}`. If no candidate waits, the slot becomes
  free.
  """
  @spec release(t()) :: {:start, term(), t()} | {:idle, t()}
  def release(%__MODULE__{active: active} = queue) when active > 0 do
    case :queue.out(queue.queue) do
      {{:value, candidate}, rest} -> {:start, candidate, %{queue | queued: queue.queued - 1, queue: rest}}
      {:empty, _rest} -> {:idle, %{queue | active: active - 1}}
    end
  end
end
