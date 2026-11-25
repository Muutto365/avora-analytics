defmodule Avora.Audit do
  @moduledoc """
  Audit records of administrative actions (fork addition).

  Each record is one flat map in the `loop.audit` v1 shape and is written
  as one JSON line to the file named by `AUDIT_LOG_FILE`, by a dedicated
  handler of the standard `:logger` (`:logger_std_h`, rotating at 10 MB,
  five archives `<file>.0` … `<file>.4`). A log collector next to the
  application ships the file; nothing here sends over the network.

    * **Off unless configured:** with `AUDIT_LOG_FILE` unset, records are
      built (and emitted as the telemetry event `[:avora, :audit]`) but not
      written anywhere.
    * **Best effort:** upstream Community Edition keeps no audit table, so
      this file is the only copy until it is shipped. A failed write never
      fails the action it describes.
    * **No personal data:** a person appears only as `oidc:<subject>` (the
      identity provider's subject identifier, when it is a UUID), or as
      `unbound`. No names, email addresses, domains or free text. Sites,
      teams and API keys appear by numeric id. Every field is checked
      against its shape; a value of the wrong shape is left out.
  """

  require Logger

  @schema 1
  @source "avora-analytics"
  @event_name "loop.audit"
  @handler :avora_audit
  @domain [:avora_audit]
  @telemetry_event [:avora, :audit]

  @max_file_bytes 10_000_000
  @max_files 5

  @actions ~w(
    site.create site.delete
    role.sync team.role_change team.member_remove team.invitation_create
    site.invitation_create
    api_key.create api_key.delete
    export.csv export.schedule export.download
    oidc.binding_change
  )
  @outcomes ~w(success refused failure)
  @principal_kinds ~w(human service system)
  @target_types ~w(site tenant api_key team user export)
  @roles ~w(owner admin editor viewer billing guest none)
  @vias ~w(provisioning ui sign_in task api)

  @uuid ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/
  @numeric_id ~r/\A[0-9]{1,19}\z/
  @reason ~r/\A[a-z][a-z0-9_]{0,63}\z/

  @doc "The closed list of actions."
  @spec actions() :: [String.t()]
  def actions, do: @actions

  @doc "The principal of a service calling the provisioning API with its token."
  def provisioning_principal, do: {"service", "service:provisioning"}

  @doc "The principal of a release task run by an operator."
  def task_principal, do: {"system", "system:task"}

  @doc """
  The principal of a person: `{"human", "oidc:<subject>"}` when the account
  is bound to the configured issuer with a UUID subject, else
  `{"human", "unbound"}`.
  """
  @spec person_principal(Plausible.Auth.User.t() | nil) :: {String.t(), String.t()}
  def person_principal(user), do: {"human", person_id(user)}

  @doc "A person as a target or principal id (see `person_principal/1`)."
  @spec person_id(Plausible.Auth.User.t() | nil) :: String.t()
  def person_id(%{oidc_issuer: issuer, oidc_subject: subject})
      when is_binary(issuer) and is_binary(subject) do
    subject = String.downcase(subject)

    if issuer == configured_issuer() and Regex.match?(@uuid, subject) do
      "oidc:" <> subject
    else
      "unbound"
    end
  end

  def person_id(_), do: "unbound"

  @doc """
  Records an action. `fields`:

    * `:action` (required, one of `actions/0`), `:outcome` (default
      `"success"`), `:reason`;
    * `:principal`, a `{kind, id}` pair from the helpers above (required);
    * `:target_type` and `:target_id` (an integer id, a tenant UUID or a
      person id);
    * `:tenant_id` (a UUID, written as `loop.org`);
    * `:role`, `:previous_role` (atoms or strings), `:via`.

  Always returns `:ok`.
  """
  @spec record(keyword() | map()) :: :ok
  def record(fields) do
    case build(Map.new(fields)) do
      {:ok, record} ->
        :telemetry.execute(@telemetry_event, %{count: 1}, record)
        write(record)

      {:error, problem} ->
        Logger.warning("audit record not written: #{problem}")
    end

    :ok
  rescue
    error ->
      Logger.warning("audit record not written: #{inspect(error.__struct__)}")
      :ok
  end

  @doc false
  @spec build(map()) :: {:ok, map()} | {:error, String.t()}
  def build(fields) do
    action = fields[:action]
    outcome = fields[:outcome] || "success"
    {kind, principal_id} = fields[:principal] || {nil, nil}

    cond do
      action not in @actions ->
        {:error, "unknown action"}

      outcome not in @outcomes ->
        {:error, "unknown outcome"}

      kind not in @principal_kinds or not principal_id?(principal_id) ->
        {:error, "invalid principal"}

      true ->
        record =
          %{
            "time" => timestamp(),
            "event.name" => @event_name,
            "audit.schema" => @schema,
            "audit.event_id" => Ecto.UUID.generate(),
            "audit.source" => @source,
            "audit.action" => action,
            "audit.outcome" => outcome,
            "principal.kind" => kind,
            "principal.id" => principal_id
          }
          |> put_shaped("audit.reason", fields[:reason], &reason?/1)
          |> put_shaped("loop.org", lower(fields[:tenant_id]), &uuid?/1)
          |> put_target(fields[:target_type], fields[:target_id])
          |> put_shaped("avora.role", to_str(fields[:role]), &(&1 in @roles))
          |> put_shaped("avora.previous_role", to_str(fields[:previous_role]), &(&1 in @roles))
          |> put_shaped("avora.via", fields[:via], &(&1 in @vias))
          |> put_trace()

        {:ok, record}
    end
  end

  # --- the file handler --------------------------------------------------

  @doc """
  Adds the file handler when `AUDIT_LOG_FILE` is configured and the handler
  is not there yet. Called at application start, and again before each
  write so that release tasks (which do not start the application) write
  too.
  """
  @spec ensure_handler() :: :ok | :off
  def ensure_handler do
    case configured_file() do
      nil ->
        :off

      file ->
        case :logger.get_handler_config(@handler) do
          {:ok, _} -> :ok
          {:error, _} -> add_handler(file)
        end
    end
  end

  @doc false
  def remove_handler do
    _ = :logger.remove_handler(@handler)
    _ = :logger.unset_module_level(__MODULE__)
    :ok
  end

  defp add_handler(file) do
    config = %{
      config: %{
        file: String.to_charlist(file),
        max_no_bytes: @max_file_bytes,
        max_no_files: @max_files,
        # Write in the caller, so a record is in the file (or has failed)
        # before the action's response goes out; never drop under load.
        sync_mode_qlen: 0,
        drop_mode_qlen: 100_000,
        flush_qlen: 200_000,
        burst_limit_enable: false,
        overload_kill_enable: false
      },
      level: :all,
      filter_default: :stop,
      filters: [avora_audit: {&:logger_filters.domain/2, {:log, :equal, @domain}}],
      formatter: {Avora.Audit.Formatter, %{}}
    }

    case :logger.add_handler(@handler, :logger_std_h, config) do
      :ok ->
        keep_out_of_other_handlers()
        # Records are written whatever the application's log level is.
        :ok = :logger.set_module_level(__MODULE__, :all)
        :ok

      {:error, {:already_exist, _}} ->
        :ok

      {:error, reason} ->
        Logger.error("audit log file handler could not be added: #{inspect(reason)}")
        :off
    end
  end

  defp keep_out_of_other_handlers do
    for handler <- :logger.get_handler_ids(), handler != @handler do
      _ =
        :logger.add_handler_filter(
          handler,
          :avora_audit_stop,
          {&:logger_filters.domain/2, {:stop, :equal, @domain}}
        )
    end

    :ok
  end

  defp write(record) do
    if ensure_handler() == :ok do
      :logger.macro_log(
        %{mfa: {__MODULE__, :record, 1}, file: ~c"avora/audit.ex", line: 0},
        :notice,
        record,
        %{domain: @domain}
      )

      # The handler buffers writes (up to 64 KB or 2 s); records are rare,
      # so each one is flushed and synced to disk before the action returns.
      _ = :logger_std_h.filesync(@handler)
    end

    :ok
  end

  # --- shapes ------------------------------------------------------------

  defp put_shaped(record, _key, nil, _check), do: record

  defp put_shaped(record, key, value, check) when is_binary(value) do
    if check.(value), do: Map.put(record, key, value), else: record
  end

  defp put_shaped(record, _key, _value, _check), do: record

  defp put_target(record, type, id) when type in @target_types do
    id = target_id(type, id)

    if id do
      record |> Map.put("target.type", type) |> Map.put("target.id", id)
    else
      Map.put(record, "target.type", type)
    end
  end

  defp put_target(record, _type, _id), do: record

  defp target_id(type, id)
       when type in ~w(site api_key team export) and is_integer(id) and id >= 0,
       do: Integer.to_string(id)

  defp target_id(type, id) when type in ~w(site api_key team export) and is_binary(id) do
    if Regex.match?(@numeric_id, id), do: id
  end

  defp target_id("tenant", id) when is_binary(id) do
    id = String.downcase(id)
    if uuid?(id), do: id
  end

  defp target_id("user", id) when is_binary(id) do
    if principal_id?(id) and (id == "unbound" or String.starts_with?(id, "oidc:")), do: id
  end

  defp target_id(_type, _id), do: nil

  defp principal_id?("unbound"), do: true
  defp principal_id?("service:provisioning"), do: true
  defp principal_id?("system:task"), do: true
  defp principal_id?("oidc:" <> subject), do: uuid?(subject)
  defp principal_id?(_), do: false

  defp uuid?(value), do: is_binary(value) and Regex.match?(@uuid, value)
  defp reason?(value), do: Regex.match?(@reason, value)

  defp lower(value) when is_binary(value), do: String.downcase(value)
  defp lower(value), do: value

  defp to_str(value) when is_atom(value) and not is_nil(value), do: Atom.to_string(value)
  defp to_str(value), do: value

  defp put_trace(record) do
    case OpenTelemetry.Tracer.current_span_ctx() do
      :undefined ->
        record

      span_ctx ->
        trace_id = :otel_span.hex_trace_id(span_ctx)
        span_id = :otel_span.hex_span_id(span_ctx)

        if valid_hex?(trace_id, 32) and valid_hex?(span_id, 16) do
          record |> Map.put("trace_id", trace_id) |> Map.put("span_id", span_id)
        else
          record
        end
    end
  end

  defp valid_hex?(value, length) when is_binary(value) do
    byte_size(value) == length and value != String.duplicate("0", length) and
      Regex.match?(~r/\A[0-9a-f]+\z/, value)
  end

  defp valid_hex?(_, _), do: false

  defp timestamp do
    DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
  end

  defp configured_file do
    case Keyword.get(Application.get_env(:plausible, __MODULE__, []), :file) do
      file when is_binary(file) and file != "" -> file
      _ -> nil
    end
  end

  defp configured_issuer, do: Keyword.get(Plausible.Auth.OIDC.config(), :issuer)
end
