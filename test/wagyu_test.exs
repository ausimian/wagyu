defmodule WagyuTest do
  use ExUnit.Case

  test "starts an empty supervision tree" do
    assert {:ok, _applications} = Application.ensure_all_started(:wagyu)
    assert is_pid(Process.whereis(Wagyu.Supervisor))
    assert Supervisor.which_children(Wagyu.Supervisor) == []
  end
end
