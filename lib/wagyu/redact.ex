defmodule Wagyu.Redact do
  @moduledoc false

  # `format_status/1` for processes that hold keys.
  #
  # `Wagyu.Config` and `Wagyu.Config.Peer` hide their keys from `Inspect`,
  # which covers Elixir's own log formatting. Status formatting goes further
  # and drops the key-holding fields entirely, so `:sys.get_status/1`, crash
  # reports and Erlang's own term formatting show `:redacted` instead. The
  # `sys` debug log records states too, so those entries are redacted the
  # same way, and the replies it records pass through `redact_reply`, for
  # processes whose replies carry keys.

  @spec format_status(map(), [atom()], (term() -> term())) :: map()
  def format_status(status, fields, redact_reply \\ & &1) do
    status
    |> Map.replace_lazy(:state, &redact(&1, fields))
    |> Map.replace_lazy(:log, fn log -> Enum.map(log, &redact_event(&1, fields, redact_reply)) end)
  end

  defp redact(state, fields) when is_map(state), do: Enum.reduce(fields, state, &Map.replace(&2, &1, :redacted))
  defp redact(_state, _fields), do: :redacted

  # OTP keeps each entry with the process name and formatter it was
  # logged with.
  defp redact_event({event, name, formatter}, fields, redact_reply) when is_function(formatter, 3),
    do: {redact_event(event, fields, redact_reply), name, formatter}

  defp redact_event({:noreply, state}, fields, _redact_reply), do: {:noreply, redact(state, fields)}

  defp redact_event({:out, reply, to, state}, fields, redact_reply),
    do: {:out, redact_reply.(reply), to, redact(state, fields)}

  defp redact_event(event, _fields, _redact_reply), do: event
end
