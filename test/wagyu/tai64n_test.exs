defmodule Wagyu.TAI64NTest do
  use ExUnit.Case, async: true

  alias Wagyu.TAI64N

  @base 0x400000000000000A
  @second 1_000_000_000
  @step 0x1000000
  # The largest nanosecond value that survives rounding: 59 * 2^24.
  @last_step 989_855_744

  defp stamp(seconds, nanos), do: <<@base + seconds::64, nanos::32>>

  describe "from_unix/1" do
    test "offsets Unix seconds by the TAI64 base" do
      assert TAI64N.from_unix(0) == stamp(0, 0)
      assert TAI64N.from_unix(1_767_225_600 * @second) == <<0x400000006955B90A::64, 0::32>>
    end

    test "rounds nanoseconds down to a multiple of 2^24" do
      for {nanos, rounded} <- [
            {0, 0},
            {1, 0},
            {@step - 1, 0},
            {@step, @step},
            {@step + 1, @step},
            {500_000_000, 29 * @step},
            {@last_step, @last_step},
            {@second - 1, @last_step}
          ] do
        assert TAI64N.from_unix(42 * @second + nanos) == stamp(42, rounded), "nanos #{nanos}"
      end
    end

    test "handles times before the epoch" do
      assert TAI64N.from_unix(-1) == stamp(-1, @last_step)
      assert TAI64N.from_unix(-@second) == stamp(-1, 0)
    end

    test "is ordered across rounding windows and second boundaries" do
      times = [
        0,
        @step - 1,
        @step,
        2 * @step,
        @last_step,
        @second - 1,
        @second,
        @second + @step,
        10 * @second
      ]

      stamps = Enum.map(times, &TAI64N.from_unix/1)

      for {earlier, later} <- Enum.zip(stamps, tl(stamps)), earlier != later do
        assert TAI64N.after?(later, earlier)
        refute TAI64N.after?(earlier, later)
      end

      # Times inside one window are indistinguishable, by design.
      assert TAI64N.from_unix(@step) == TAI64N.from_unix(2 * @step - 1)
      assert TAI64N.from_unix(@last_step) == TAI64N.from_unix(@second - 1)
    end
  end

  describe "to_unix/1" do
    test "round-trips rounded times" do
      for time <- [0, @step, 42 * @second + 29 * @step, -@second, 1_767_225_600 * @second + @last_step] do
        assert TAI64N.to_unix(TAI64N.from_unix(time)) == {:ok, time}
      end
    end

    test "fails closed on malformed timestamps" do
      assert TAI64N.to_unix(stamp(0, @second)) == {:error, :invalid_timestamp}
      assert TAI64N.to_unix(<<0x8000000000000000::64, 0::32>>) == {:error, :invalid_timestamp}
      assert TAI64N.to_unix(<<0::88>>) == {:error, :invalid_timestamp}
      assert TAI64N.to_unix(<<0::104>>) == {:error, :invalid_timestamp}
      assert TAI64N.to_unix(nil) == {:error, :invalid_timestamp}
    end
  end

  describe "after?/2" do
    test "compares timestamps as big-endian numbers" do
      assert TAI64N.after?(stamp(1, 0), stamp(0, @last_step))
      assert TAI64N.after?(stamp(0, @step), stamp(0, 0))
      refute TAI64N.after?(stamp(0, @step), stamp(0, @step))
      refute TAI64N.after?(stamp(0, 0), stamp(0, @step))
    end

    test "never treats a malformed value as newer" do
      refute TAI64N.after?(<<0xFF::104>>, stamp(0, 0))
      refute TAI64N.after?(stamp(0, 0), <<0::88>>)
      refute TAI64N.after?(nil, stamp(0, 0))
    end
  end

  describe "now/0" do
    test "reads the wall clock" do
      before = System.os_time(:nanosecond)
      {:ok, now} = TAI64N.to_unix(TAI64N.now())
      later = System.os_time(:nanosecond)

      assert now >= before - @step and now <= later
    end
  end

  describe "next/2" do
    test "uses the current time when there is no previous timestamp" do
      assert TAI64N.next(nil, stamp(10, @step)) == stamp(10, @step)
    end

    test "uses the current time when it is later" do
      assert TAI64N.next(stamp(10, 0), stamp(10, @step)) == stamp(10, @step)
      assert TAI64N.next(stamp(10, @last_step), stamp(11, 0)) == stamp(11, 0)
    end

    test "steps past the previous timestamp within one rounding window" do
      assert TAI64N.next(stamp(10, @step), stamp(10, @step)) == stamp(10, 2 * @step)
    end

    test "steps past the previous timestamp when the wall clock moves back" do
      assert TAI64N.next(stamp(10, 3 * @step), stamp(9, 0)) == stamp(10, 4 * @step)
    end

    test "carries into the next second from the last window" do
      assert TAI64N.next(stamp(10, @last_step), stamp(10, 0)) == stamp(11, 0)
    end

    test "steps to a rounded value after an unrounded previous timestamp" do
      assert TAI64N.next(stamp(10, @step + 5), stamp(10, 0)) == stamp(10, 2 * @step)
      assert TAI64N.next(stamp(10, @second - 1), stamp(10, 0)) == stamp(11, 0)
    end

    test "is strictly increasing under rapid retriggering" do
      stamps = Enum.scan(1..200, TAI64N.next(nil), fn _index, previous -> TAI64N.next(previous) end)

      for {earlier, later} <- Enum.zip(stamps, tl(stamps)) do
        assert TAI64N.after?(later, earlier)
      end

      assert Enum.all?(stamps, &match?({:ok, _nanos}, TAI64N.to_unix(&1)))
    end
  end
end
