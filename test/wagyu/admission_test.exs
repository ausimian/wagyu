defmodule Wagyu.AdmissionTest do
  use ExUnit.Case, async: true

  alias Wagyu.Admission

  test "admits within both bounds and refuses beyond either" do
    admission = Admission.new(2, 100)

    assert Admission.admit(admission, 1, 60) == :ok
    assert Admission.admit(admission, 1, 41) == :full
    assert Admission.admit(admission, 1, 40) == :ok
    assert Admission.admit(admission, 1, 0) == :full
    assert Admission.usage(admission) == {2, 100}

    assert Admission.release(admission, 1, 60) == :ok
    assert Admission.usage(admission) == {1, 40}
    assert Admission.admit(admission, 1, 60) == :ok
  end

  test "admits the prefix of a list that fits, in order" do
    admission = Admission.new(3, 10)
    packets = ["aaaa", "bbbb", "cc", "d"]

    assert Admission.admit_prefix(admission, packets) == {["aaaa", "bbbb", "cc"], 1}
    assert Admission.usage(admission) == {3, 10}
    assert Admission.admit_prefix(admission, ["e"]) == {[], 1}

    assert Admission.release_all(admission, ["aaaa", "bbbb", "cc"]) == :ok
    assert Admission.usage(admission) == {0, 0}
  end

  test "concurrent senders never overshoot the bound" do
    admission = Admission.new(100, 1_000_000)

    admitted =
      1..8
      |> Task.async_stream(fn _sender -> Enum.count(1..100, fn _n -> Admission.admit(admission, 1, 1) == :ok end) end)
      |> Enum.reduce(0, fn {:ok, count}, total -> total + count end)

    assert admitted <= 100
    assert Admission.usage(admission) == {admitted, admitted}
  end
end
