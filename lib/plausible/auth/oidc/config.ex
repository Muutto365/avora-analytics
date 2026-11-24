defmodule Plausible.Auth.OIDC.Config do
  @moduledoc """
  Parses the OIDC single sign-on settings (fork addition).

  The feature is off unless `OIDC_ISSUER` is set. See the README section
  "Single sign-on (OIDC)" for the variables.
  """

  @default_button_label "Sign in with SSO"
  @default_session_hours 12
  @session_hours_range 1..72

  @doc """
  Builds the keyword list stored under `config :plausible, Plausible.Auth.OIDC`.

  `get` is called with a variable name and returns its raw string value or
  `nil`. Raises on incomplete or invalid settings, so a misconfigured
  instance fails at boot rather than at the first login.
  """
  @spec parse!((String.t() -> String.t() | nil)) :: Keyword.t()
  def parse!(get) when is_function(get, 1) do
    value = fn name ->
      case get.(name) do
        nil -> nil
        raw -> raw |> String.trim() |> blank_to_nil()
      end
    end

    issuer = value.("OIDC_ISSUER")

    disable_password_login =
      parse_bool!("OIDC_DISABLE_PASSWORD_LOGIN", value.("OIDC_DISABLE_PASSWORD_LOGIN"), false)

    if issuer do
      enabled_config!(issuer, value, disable_password_login)
    else
      disabled_config!(value, disable_password_login)
    end
  end

  defp disabled_config!(value, disable_password_login) do
    if disable_password_login do
      raise ArgumentError,
            "OIDC_DISABLE_PASSWORD_LOGIN is set but OIDC_ISSUER is not: " <>
              "nobody would be able to log in"
    end

    stray =
      Enum.filter(
        ~w(OIDC_CLIENT_ID OIDC_CLIENT_SECRET_FILE OIDC_ROLE_MAP OIDC_INTERNAL_ISSUER_URL
           OIDC_INTERNAL_ISSUER_ALLOW_HTTP OIDC_SESSION_HOURS),
        &value.(&1)
      )

    if stray != [] do
      raise ArgumentError,
            "#{Enum.join(stray, ", ")} set without OIDC_ISSUER; set OIDC_ISSUER or unset them"
    end

    [enabled: false, disable_password_login: false]
  end

  defp enabled_config!(issuer, value, disable_password_login) do
    issuer = validate_url!("OIDC_ISSUER", issuer)

    for replaced <- ~w(OIDC_ALLOWED_GROUPS OIDC_GROUPS_CLAIM), value.(replaced) do
      raise ArgumentError,
            "#{replaced} is no longer supported: access comes from client roles " <>
              "through OIDC_ROLE_MAP; unset #{replaced}"
    end

    client_id = value.("OIDC_CLIENT_ID") || raise ArgumentError, "OIDC_CLIENT_ID is required"

    secret_file =
      value.("OIDC_CLIENT_SECRET_FILE") ||
        raise ArgumentError, "OIDC_CLIENT_SECRET_FILE is required"

    allow_internal_http =
      parse_bool!(
        "OIDC_INTERNAL_ISSUER_ALLOW_HTTP",
        value.("OIDC_INTERNAL_ISSUER_ALLOW_HTTP"),
        false
      )

    internal_issuer_url =
      case value.("OIDC_INTERNAL_ISSUER_URL") do
        nil ->
          if allow_internal_http do
            raise ArgumentError,
                  "OIDC_INTERNAL_ISSUER_ALLOW_HTTP is set without OIDC_INTERNAL_ISSUER_URL"
          end

          nil

        url ->
          validate_url!("OIDC_INTERNAL_ISSUER_URL", url,
            allow_http: allow_internal_http,
            http_hint: "set OIDC_INTERNAL_ISSUER_ALLOW_HTTP=true for a trusted network path"
          )
      end

    [
      enabled: true,
      issuer: issuer,
      internal_issuer_url: internal_issuer_url,
      client_id: client_id,
      client_secret: read_secret!(secret_file),
      role_map: parse_role_map!(value.("OIDC_ROLE_MAP")),
      session_hours: parse_session_hours!(value.("OIDC_SESSION_HOURS")),
      button_label: value.("OIDC_BUTTON_LABEL") || @default_button_label,
      disable_password_login: disable_password_login
    ]
  end

  @doc """
  Plain `http` is accepted only for loopback hosts (local development and
  tests); any other issuer must use `https`.
  """
  @spec loopback?(String.t()) :: boolean()
  def loopback?(url) do
    URI.parse(url).host in ["localhost", "127.0.0.1", "::1", "[::1]"]
  end

  defp validate_url!(name, url, opts \\ []) do
    uri = URI.parse(url)

    cond do
      uri.scheme not in ["http", "https"] or uri.host in [nil, ""] ->
        raise ArgumentError, "#{name} must be an absolute http(s) URL"

      uri.query != nil or uri.fragment != nil ->
        raise ArgumentError, "#{name} must not have a query or fragment"

      uri.scheme == "http" and !opts[:allow_http] and not loopback?(url) ->
        hint = if opts[:http_hint], do: " (or #{opts[:http_hint]})", else: ""
        raise ArgumentError, "#{name} must use https#{hint}"

      true ->
        url
    end
  end

  defp read_secret!(path) do
    case File.read(path) do
      {:ok, contents} ->
        case String.trim(contents) do
          "" -> raise ArgumentError, "OIDC_CLIENT_SECRET_FILE points to an empty file"
          secret -> secret
        end

      {:error, reason} ->
        raise ArgumentError,
              "OIDC_CLIENT_SECRET_FILE could not be read: #{:file.format_error(reason)}"
    end
  end

  @provider_role ~r/\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z/

  # Required: who may sign in, and with which role, comes only from the
  # declared table. There is no "anyone" setting.
  defp parse_role_map!(nil) do
    raise ArgumentError,
          "OIDC_ROLE_MAP is required: map the client roles that may sign in to " <>
            "roles here, e.g. analytics-admin=admin,analytics-viewer=viewer"
  end

  defp parse_role_map!(raw) do
    grantable = Enum.map(Avora.Roles.grantable_roles(), &Atom.to_string/1)

    pairs =
      raw
      |> parse_list()
      |> Enum.map(fn entry ->
        with [from, to] <- String.split(entry, "=", parts: 2),
             from = String.trim(from),
             to = to |> String.trim() |> String.downcase(),
             true <- Regex.match?(@provider_role, from),
             true <- to in grantable do
          {from, String.to_existing_atom(to)}
        else
          _ ->
            raise ArgumentError,
                  "OIDC_ROLE_MAP: #{inspect(entry)} must be <client role>=<role>, " <>
                    "with a role of #{Enum.join(grantable, ", ")}"
        end
      end)

    if pairs == [], do: raise(ArgumentError, "OIDC_ROLE_MAP is set but maps no roles")

    duplicates = pairs |> Enum.frequencies_by(&elem(&1, 0)) |> Enum.filter(&(elem(&1, 1) > 1))

    if duplicates != [] do
      raise ArgumentError,
            "OIDC_ROLE_MAP maps #{Enum.map_join(duplicates, ", ", &elem(&1, 0))} more than once"
    end

    Map.new(pairs)
  end

  defp parse_session_hours!(nil), do: @default_session_hours

  defp parse_session_hours!(raw) do
    case Integer.parse(raw) do
      {hours, ""} when hours in @session_hours_range ->
        hours

      _ ->
        raise ArgumentError,
              "OIDC_SESSION_HOURS must be a whole number of hours from " <>
                "#{@session_hours_range.first} to #{@session_hours_range.last}"
    end
  end

  defp parse_list(raw) do
    raw
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  defp parse_bool!(_name, nil, default), do: default

  defp parse_bool!(name, raw, _default) do
    case String.downcase(raw) do
      v when v in ["1", "t", "true", "y", "yes", "on"] -> true
      v when v in ["0", "f", "false", "n", "no", "off"] -> false
      _ -> raise ArgumentError, "#{name} must be true or false"
    end
  end

  defp blank_to_nil(""), do: nil
  defp blank_to_nil(value), do: value
end
