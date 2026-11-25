defmodule Avora.TenantToken.ConfigTest do
  # Fork addition
  use ExUnit.Case, async: true

  alias Avora.TenantToken.Config

  @staff_issuer "https://auth.example.com/realms/staff"
  @tenant "6f6e0995-6be4-4f29-baa6-10dd3010f867"

  defp parse(vars), do: Config.parse!(&Map.get(vars, &1))

  defp base,
    do: %{
      "OIDC_ISSUER" => @staff_issuer,
      "TENANT_TOKEN_AUDIENCE" => "analytics",
      "TENANT_TOKEN_CLIENTS" => "avora-hub"
    }

  test "off when no issuer is bound" do
    assert parse(%{}) == Config.disabled()
    assert parse(%{"OIDC_ISSUER" => @staff_issuer}) == Config.disabled()
  end

  test "binds the staff issuer to one tenant" do
    config = parse(Map.put(base(), "TENANT_STAFF_TENANT_ID", String.upcase(@tenant)))

    assert config[:enabled]
    assert config[:audience] == "analytics"
    assert config[:clients] == ["avora-hub"]
    assert config[:bindings] == [%{kind: :staff, issuer: @staff_issuer, mode: {:fixed, @tenant}}]
  end

  test "binds a tenant issuer to Organizations, with an internal URL" do
    config =
      base()
      |> Map.merge(%{
        "TENANT_STAFF_TENANT_ID" => @tenant,
        "TENANT_ORG_ISSUER" => "https://auth.example.org/realms/tenants",
        "TENANT_ORG_INTERNAL_ISSUER_URL" => "http://keycloak.internal:8080/realms/tenants",
        "TENANT_ORG_INTERNAL_ISSUER_ALLOW_HTTP" => "true",
        "TENANT_TOKEN_CLIENTS" => " avora-hub , other ,"
      })
      |> parse()

    assert [%{kind: :staff}, org] = config[:bindings]

    assert org == %{
             kind: :organization,
             issuer: "https://auth.example.org/realms/tenants",
             internal_issuer_url: "http://keycloak.internal:8080/realms/tenants",
             mode: :organization
           }

    assert config[:clients] == ["avora-hub", "other"]
  end

  test "refuses incomplete or invalid settings" do
    bad = [
      # staff binding without the staff issuer
      Map.delete(Map.put(base(), "TENANT_STAFF_TENANT_ID", @tenant), "OIDC_ISSUER"),
      Map.put(base(), "TENANT_STAFF_TENANT_ID", "not-a-uuid"),
      Map.delete(Map.put(base(), "TENANT_STAFF_TENANT_ID", @tenant), "TENANT_TOKEN_AUDIENCE"),
      Map.delete(Map.put(base(), "TENANT_STAFF_TENANT_ID", @tenant), "TENANT_TOKEN_CLIENTS"),
      Map.merge(base(), %{"TENANT_STAFF_TENANT_ID" => @tenant, "TENANT_TOKEN_CLIENTS" => " , "}),
      # the tenant issuer must not be the staff issuer, and must be https
      Map.put(base(), "TENANT_ORG_ISSUER", @staff_issuer),
      Map.put(base(), "TENANT_ORG_ISSUER", "http://auth.example.org/realms/tenants"),
      Map.merge(base(), %{
        "TENANT_ORG_ISSUER" => "https://auth.example.org/realms/tenants",
        "TENANT_ORG_INTERNAL_ISSUER_URL" => "http://keycloak.internal:8080/realms/tenants"
      }),
      Map.merge(base(), %{
        "TENANT_ORG_ISSUER" => "https://auth.example.org/realms/tenants",
        "TENANT_ORG_INTERNAL_ISSUER_ALLOW_HTTP" => "true"
      }),
      # stray settings without a binding
      %{"TENANT_TOKEN_AUDIENCE" => "analytics"},
      %{"TENANT_ORG_INTERNAL_ISSUER_URL" => "https://keycloak.internal/realms/tenants"}
    ]

    for vars <- bad do
      assert_raise ArgumentError, fn -> parse(vars) end
    end
  end
end
