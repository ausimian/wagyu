defmodule Wagyu.Redact do
  @moduledoc false

  # `format_status/1` for processes that hold keys.
  #
  # `Wagyu.Config` and `Wagyu.Config.Peer` hide their keys from `Inspect`.
  # This covers the log format of Elixir. Status formatting does more: it
  # replaces the complete value of each field that holds keys. Thus
  # `:sys.get_status/1`, crash reports and the term format of Erlang show
  # `:redacted` instead. The `sys` debug log also records states, and the
  # same redaction applies to those entries.
  #
  # Some processes also get keys in their messages or send keys in their
  # replies. The `sys` debug log records messages and replies, and a crash
  # report shows the last message. For these processes, the options give
  # the functions that redact them:
  #
  #   * `:message` - for each message, and for the request of each call
  #   * `:reply` - for each reply

  @spec format_status(map(), [atom()], keyword()) :: map()
  def format_status(status, fields, options \\ []) do
    redact = %{
      fields: fields,
      message: Keyword.get(options, :message, & &1),
      reply: Keyword.get(options, :reply, & &1)
    }

    status
    |> Map.replace_lazy(:state, &redact_state(&1, redact))
    |> Map.replace_lazy(:message, &redact_message(&1, redact))
    |> Map.replace_lazy(:log, fn log -> Enum.map(log, &redact_event(&1, redact)) end)
  end

  defp redact_state(state, %{fields: fields}) when is_map(state),
    do: Enum.reduce(fields, state, &Map.replace(&2, &1, :redacted))

  defp redact_state(_state, _redact), do: :redacted

  defp redact_message({:"$gen_call", from, request}, redact), do: {:"$gen_call", from, redact.message.(request)}
  defp redact_message(message, redact), do: redact.message.(message)

  # OTP keeps each entry with the process name and the formatter that
  # applied when the entry was logged.
  defp redact_event({event, name, formatter}, redact) when is_function(formatter, 3),
    do: {redact_event(event, redact), name, formatter}

  defp redact_event({:in, message}, redact), do: {:in, redact_message(message, redact)}
  defp redact_event({:in, message, from}, redact), do: {:in, redact_message(message, redact), from}
  defp redact_event({:noreply, state}, redact), do: {:noreply, redact_state(state, redact)}

  defp redact_event({:out, reply, to, state}, redact),
    do: {:out, redact.reply.(reply), to, redact_state(state, redact)}

  defp redact_event(event, _redact), do: event
end
