defmodule Wagyu.FakeSmolNet do
  @moduledoc false

  # Stands in for SmolNet so that link tests can watch and script the link's
  # calls. Every call is reported to the process registered under this
  # module's name, the controller, which also chooses each ingress result.
  # The "stack" is a bare process that tests can kill.

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

  def stop_stack(%{stack: stack, controller: controller}) do
    send(controller, {:stop_stack, self()})
    send(stack, :stop)
    :ok
  end
end
