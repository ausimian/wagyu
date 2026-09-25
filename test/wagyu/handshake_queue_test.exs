defmodule Wagyu.HandshakeQueueTest do
  use ExUnit.Case, async: true

  alias Wagyu.HandshakeQueue

  defp admit_all(queue, candidates) do
    Enum.map_reduce(candidates, queue, fn candidate, queue ->
      case HandshakeQueue.admit(queue, candidate) do
        {:start, ^candidate, queue} -> {:start, queue}
        {:queued, queue} -> {:queued, queue}
        :full -> {:full, queue}
      end
    end)
  end

  test "defaults to 8 workers and 64 waiting initiations" do
    {results, queue} = admit_all(HandshakeQueue.new(), 1..100)

    assert Enum.frequencies(results) == %{start: 8, queued: 64, full: 28}
    assert %{active: 8, queued: 64} = queue
  end

  test "is loaded once an eighth of the waiting room is taken" do
    {_results, queue} = admit_all(HandshakeQueue.new(), 1..15)
    assert %{active: 8, queued: 7} = queue
    refute HandshakeQueue.loaded?(queue)

    {:queued, queue} = HandshakeQueue.admit(queue, 16)
    assert HandshakeQueue.loaded?(queue)

    {:start, 9, queue} = HandshakeQueue.release(queue)
    refute HandshakeQueue.loaded?(queue)

    # Busy workers alone, with no room to wait, are not load by this measure.
    {_results, queue} = admit_all(HandshakeQueue.new(max_queued: 0), 1..9)
    refute HandshakeQueue.loaded?(queue)
  end

  test "a released slot goes to the oldest waiting candidate" do
    {_results, queue} = admit_all(HandshakeQueue.new(max_active: 1, max_queued: 2), [:a, :b, :c])

    assert {:start, :b, queue} = HandshakeQueue.release(queue)
    assert {:queued, queue} = HandshakeQueue.admit(queue, :d)
    assert HandshakeQueue.admit(queue, :e) == :full
    assert {:start, :c, queue} = HandshakeQueue.release(queue)
    assert {:start, :d, queue} = HandshakeQueue.release(queue)
    assert {:idle, %{active: 0, queued: 0} = queue} = HandshakeQueue.release(queue)
    assert {:start, :f, _queue} = HandshakeQueue.admit(queue, :f)
  end
end
