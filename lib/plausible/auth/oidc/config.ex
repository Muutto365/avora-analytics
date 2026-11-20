defmodule Plausible.Auth.OIDC.Config do
  @moduledoc """
  Parses the OIDC single sign-on settings (fork addition).

  The feature is off unless `OIDC_ISSUER` is set. See the README section
  "Single sign-on (OIDC)" for the variables.
  """

  @default_button_label "Sign in with SSO"
  @default_groups_claim "groups"

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
    disable_password_login = parse_bool!(value.("OIDC_DISABLE_PASSWORD_LOGIN"), false)

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
        ~w(OIDC_CLIENT_ID OIDC_CLIENT_SECRET_FILE OIDC_ALLOWED_GROUPS OIDC_INTERNAL_ISSUER_URL),
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

    client_id = value.("OIDC_CLIENT_ID") || raise ArgumentError, "OIDC_CLIENT_ID is required"

    secret_file =
      value.("OIDC_CLIENT_SECRET_FILE") ||
        raise ArgumentError, "OIDC_CLIENT_SECRET_FILE is required"

    internal_issuer_url =
      case value.("OIDC_INTERNAL_ISSUER_URL") do
        nil -> nil
        url -> validate_url!("OIDC_INTERNAL_ISSUER_URL", url, allow_http: true)
      end

    [
      enabled: true,
      issuer: issuer,
      internal_issuer_url: internal_issuer_url,
      client_id: client_id,
      client_secret: read_secret!(secret_file),
      allowed_groups: parse_list(value.("OIDC_ALLOWED_GROUPS")),
      groups_claim: value.("OIDC_GROUPS_CLAIM") || @default_groups_claim,
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
        raise ArgumentError, "#{name} must use https"

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

  defp parse_list(nil), do: []

  defp parse_list(raw) do
    raw
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  defp parse_bool!(nil, default), do: default

  defp parse_bool!(raw, _default) do
    case String.downcase(raw) do
      v when v in ["1", "t", "true", "y", "yes", "on"] -> true
      v when v in ["0", "f", "false", "n", "no", "off"] -> false
      _ -> raise ArgumentError, "OIDC_DISABLE_PASSWORD_LOGIN must be true or false"
    end
  end

  defp blank_to_nil(""), do: nil
  defp blank_to_nil(value), do: value
end
