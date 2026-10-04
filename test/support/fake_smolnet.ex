defmodule Wagyu.FakeSmolNet do
  @moduledoc false

  # Replaces SmolNet so that link tests can monitor and control the calls of
  # the link. Each call goes in a message to the controller, which is the
  # process registered under the name of this module. The controller also
  # selects the result of each ingress call. The "stack" is a bare process
  # that tests can kill.

  def start_stack(options) do
    controller = Process.whereis(__MODULE__)
    stack = spawn(fn -> receive(do: (:stop -> :ok)) end)
    send(controller, {:start_stack, self(), options})
    {:ok, %{stack: stack, controller: controller}}
  end

  def monitor(%{stack: stack}), do: Process.monitor(stack)

  def ingress(%{controller: controller}, packets) do
    ref = make_ref()
    send(controller, {:ingress, self(), ref, packets})

    receive do
      {^ref, result} -> result
    after
      5_000 -> raise "the test did not answer an ingress call"
    end
  end

  def grant_egress(%{controller: controller}, packets, bytes) do
    send(controller, {:grant_egress, self(), packets, bytes})
    :ok
  end

  def stop_stack(%{stack: stack, controller: controller}) do
    send(controller, {:stop_stack, self()})
    send(stack, :stop)
    :ok
  end
end
