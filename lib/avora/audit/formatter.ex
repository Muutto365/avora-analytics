defmodule Avora.Audit.Formatter do
  @moduledoc """
  `:logger` formatter for the audit file handler (fork addition): writes
  the record built by `Avora.Audit` as one JSON object per line, and
  nothing else (no level, no metadata).
  """

  @doc false
  def check_config(_config), do: :ok

  @doc false
  def format(%{msg: {:report, record}}, _config) when is_map(record) do
    [Jason.encode_to_iodata!(record), ?\n]
  end

  # Only records from Avora.Audit reach this handler (its domain filter);
  # anything else is dropped rather than written in another shape.
  def format(_event, _config), do: []
end
