defmodule Avora.TenantToken.Config do
  @moduledoc """
  Parses the settings of `Avora.TenantToken` (fork addition).

  Off unless an issuer is bound. Variables:

    * `TENANT_STAFF_TENANT_ID`: binds the staff issuer (`OIDC_ISSUER`, which
      must be set) to this one tenant (a UUID).
    * `TENANT_ORG_ISSUER`: binds this issuer to the Organization its tokens
      name; optional `TENANT_ORG_INTERNAL_ISSUER_URL` (and
      `TENANT_ORG_INTERNAL_ISSUER_ALLOW_HTTP`) as for `OIDC_INTERNAL_ISSUER_URL`.
    * `TENANT_TOKEN_AUDIENCE` (required when on): the audience tokens must carry.
    * `TENANT_TOKEN_CLIENTS` (required when on): comma-separated client ids
      (`azp`) whose tokens are accepted, for example `avora-hub`.

  Raises on incomplete or invalid settings, so a misconfigured instance
  fails at boot.
  """

  alias Plausible.Auth.OIDC.Config, as: OIDCConfig

  @uuid ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/

  @doc "The settings of an instance with nothing bound."
  def disabled, do: [enabled: false, bindings: []]

  @spec parse!((String.t() -> String.t() | nil)) :: Keyword.t()
  def parse!(get) when is_function(get, 1) do
    value = fn name ->
      case get.(name) do
        nil -> nil
        raw -> raw |> String.trim() |> then(&if(&1 == "", do: nil, else: &1))
      end
    end

    bindings = Enum.reject([staff_binding!(value), org_binding!(value)], &is_nil/1)

    if bindings == [] do
      stray = Enum.filter(~w(TENANT_TOKEN_AUDIENCE TENANT_TOKEN_CLIENTS), &value.(&1))

      if stray != [] do
        raise ArgumentError,
              "#{Enum.join(stray, ", ")} set without TENANT_STAFF_TENANT_ID or TENANT_ORG_ISSUER"
      end

      disabled()
    else
      [
        enabled: true,
        bindings: bindings,
        audience:
          value.("TENANT_TOKEN_AUDIENCE") ||
            raise(ArgumentError, "TENANT_TOKEN_AUDIENCE is required"),
        clients: parse_clients!(value.("TENANT_TOKEN_CLIENTS"))
      ]
    end
  end

  defp staff_binding!(value) do
    case value.("TENANT_STAFF_TENANT_ID") do
      nil ->
        nil

      tenant_id ->
        issuer =
          value.("OIDC_ISSUER") ||
            raise ArgumentError, "TENANT_STAFF_TENANT_ID is set but OIDC_ISSUER is not"

        tenant_id = String.downcase(tenant_id)

        unless Regex.match?(@uuid, tenant_id) do
          raise ArgumentError, "TENANT_STAFF_TENANT_ID must be a UUID"
        end

        %{kind: :staff, issuer: issuer, mode: {:fixed, tenant_id}}
    end
  end

  defp org_binding!(value) do
    allow_http =
      case value.("TENANT_ORG_INTERNAL_ISSUER_ALLOW_HTTP") do
        nil -> false
        "true" -> true
        "false" -> false
        _ -> raise ArgumentError, "TENANT_ORG_INTERNAL_ISSUER_ALLOW_HTTP must be true or false"
      end

    case value.("TENANT_ORG_ISSUER") do
      nil ->
        stray =
          Enum.filter(
            ~w(TENANT_ORG_INTERNAL_ISSUER_URL TENANT_ORG_INTERNAL_ISSUER_ALLOW_HTTP),
            &value.(&1)
          )

        if stray != [] do
          raise ArgumentError, "#{Enum.join(stray, ", ")} set without TENANT_ORG_ISSUER"
        end

        nil

      issuer ->
        issuer = OIDCConfig.validate_url!("TENANT_ORG_ISSUER", issuer)

        if issuer == value.("OIDC_ISSUER") do
          raise ArgumentError,
                "TENANT_ORG_ISSUER must differ from OIDC_ISSUER (the staff issuer)"
        end

        internal =
          case value.("TENANT_ORG_INTERNAL_ISSUER_URL") do
            nil ->
              if allow_http do
                raise ArgumentError,
                      "TENANT_ORG_INTERNAL_ISSUER_ALLOW_HTTP is set without TENANT_ORG_INTERNAL_ISSUER_URL"
              end

              nil

            url ->
              OIDCConfig.validate_url!("TENANT_ORG_INTERNAL_ISSUER_URL", url,
                allow_http: allow_http,
                http_hint:
                  "set TENANT_ORG_INTERNAL_ISSUER_ALLOW_HTTP=true for a trusted network path"
              )
          end

        %{kind: :organization, issuer: issuer, internal_issuer_url: internal, mode: :organization}
    end
  end

  defp parse_clients!(nil), do: raise(ArgumentError, "TENANT_TOKEN_CLIENTS is required")

  defp parse_clients!(raw) do
    case raw |> String.split(",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == "")) do
      [] -> raise ArgumentError, "TENANT_TOKEN_CLIENTS is required"
      clients -> clients
    end
  end
end
