defmodule PlausibleWeb.Api.ServiceKeyQueryTest do
  # Fork addition: the service key reads, per request, only the sites of
  # the tenant named by the person's verified access token
  # (Avora.TenantScope, Avora.TenantToken). Tokens are signed with a key
  # generated here; validation runs through oidcc as in production.
  use PlausibleWeb.ConnCase, async: false
  use Plausible.Teams.Test

  alias Plausible.Provisioning
  alias Plausible.Provisioning.ServiceKey

  @key String.duplicate("ab12", 16)
  @staff_issuer "https://auth.example.com/realms/staff"
  @org_issuer "https://auth.example.com/realms/tenants"
  @staff_tenant "6f6e0995-6be4-4f29-baa6-10dd3010f867"
  @other_tenant "9d8c7b6a-5f4e-4d3c-8b2a-1f0e9d8c7b6a"
  @audience "analytics"

  setup do
    original_prov = Application.get_env(:plausible, Plausible.Provisioning)
    original_tt = Application.get_env(:plausible, Avora.TenantToken)

    on_exit(fn ->
      Application.put_env(:plausible, Plausible.Provisioning, original_prov)

      if original_tt,
        do: Application.put_env(:plausible, Avora.TenantToken, original_tt),
        else: Application.delete_env(:plausible, Avora.TenantToken)
    end)

    owner = new_user(email: "provisioner@example.com")
    Application.put_env(:plausible, Plausible.Provisioning, owner_email: owner.email)
    assert {:ok, :created} = ServiceKey.ensure(@key)

    staff_site = provisioned_site(owner, @staff_tenant, "staff.example.com")
    other_site = provisioned_site(owner, @other_tenant, "other.example.com")

    jwk = JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.merge(%{"kid" => "test-key"})
    configure_tokens(jwk)

    {:ok, owner: owner, jwk: jwk, staff_site: staff_site, other_site: other_site}
  end

  defp provisioned_site(owner, tenant, domain) do
    {:ok, :created, site} = Provisioning.put_site(owner, tenant, domain, %{})

    # Stats before the site's creation are hidden; backdate it for the fixture.
    site =
      site
      |> Ecto.Changeset.change(native_stats_start_at: ~N[2020-01-01 00:00:00])
      |> Plausible.Repo.update!()

    populate_stats(site, [
      build(:pageview, user_id: 1, timestamp: ~N[2021-01-01 00:00:00]),
      build(:pageview, user_id: 1, timestamp: ~N[2021-01-01 00:05:00]),
      build(:pageview, user_id: 2, timestamp: ~N[2021-01-02 00:00:00])
    ])

    site
  end

  defp configure_tokens(jwk, opts \\ []) do
    public = JOSE.JWK.to_public(jwk)

    context = fn issuer ->
      fn ->
        {:ok,
         Oidcc.ClientContext.from_manual(
           %Oidcc.ProviderConfiguration{issuer: issuer},
           public,
           @audience,
           :unauthenticated
         )}
      end
    end

    Application.put_env(:plausible, Avora.TenantToken,
      enabled: true,
      audience: @audience,
      clients: Keyword.get(opts, :clients, ["avora-hub"]),
      bindings: [
        %{
          kind: :staff,
          issuer: @staff_issuer,
          mode: {:fixed, @staff_tenant},
          context: context.(@staff_issuer)
        },
        %{
          kind: :organization,
          issuer: @org_issuer,
          mode: :organization,
          context: context.(@org_issuer)
        }
      ]
    )
  end

  defp claims(overrides) do
    now = System.system_time(:second)

    Map.merge(
      %{
        "iss" => @staff_issuer,
        "sub" => "c1a7c3f0-3b5e-4d61-9a42-2b8f8d0e6a11",
        "aud" => [@audience, "account"],
        "exp" => now + 300,
        "iat" => now,
        "typ" => "Bearer",
        "azp" => "avora-hub"
      },
      overrides
    )
  end

  defp sign(jwk, claims) do
    {_, token} =
      jwk
      |> JOSE.JWT.sign(%{"alg" => "RS256", "kid" => "test-key"}, claims)
      |> JOSE.JWS.compact()

    token
  end

  defp org_claims(org_id),
    do: claims(%{"iss" => @org_issuer, "organization" => %{"acme" => %{"id" => org_id}}})

  defp query(conn, site_id, user_token, key \\ @key) do
    conn = put_req_header(conn, "authorization", "Bearer " <> key)
    conn = if user_token, do: put_req_header(conn, "x-avora-user-token", user_token), else: conn

    post(conn, "/api/v2/query", %{
      "site_id" => site_id,
      "metrics" => ["visitors", "pageviews"],
      "date_range" => ["2021-01-01", "2021-01-31"]
    })
  end

  defp refused?(conn), do: conn.status in [401, 403] and not (conn.resp_body =~ "results")

  test "a staff token reads the staff tenant's site", %{conn: conn, jwk: jwk, staff_site: site} do
    conn = query(conn, site.domain, sign(jwk, claims(%{})))

    assert json_response(conn, 200)["results"] == [%{"metrics" => [2, 3], "dimensions" => []}]
  end

  test "an Organization token reads only that tenant's site", %{
    jwk: jwk,
    staff_site: staff_site,
    other_site: other_site
  } do
    token = sign(jwk, org_claims(@other_tenant))

    assert json_response(query(build_conn(), other_site.domain, token), 200)["results"] == [
             %{"metrics" => [2, 3], "dimensions" => []}
           ]

    assert refused?(query(build_conn(), staff_site.domain, token))
  end

  test "another tenant's site is answered like an unknown site", %{
    jwk: jwk,
    other_site: other_site
  } do
    token = sign(jwk, claims(%{}))
    other = query(build_conn(), other_site.domain, token)
    unknown = query(build_conn(), "unknown.example.com", token)

    assert other.status == 401
    assert other.status == unknown.status
    assert other.resp_body == unknown.resp_body
  end

  test "a site of the owner without a tenant is refused", %{owner: owner, jwk: jwk} do
    {:ok, team} = Provisioning.owner_team(owner)
    {:ok, %{site: site}} = Plausible.Sites.create(owner, %{"domain" => "loose.example.com"}, team)
    refute site.tenant_id

    assert refused?(query(build_conn(), site.domain, sign(jwk, claims(%{}))))
  end

  test "refuses a missing, malformed or untrusted token", %{jwk: jwk, staff_site: site} do
    now = System.system_time(:second)
    stranger = JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.merge(%{"kid" => "test-key"})

    tokens = [
      nil,
      "",
      "not-a-jwt",
      # another signing key
      sign(stranger, claims(%{})),
      # expired
      sign(jwk, claims(%{"exp" => now - 60})),
      # not yet valid
      sign(jwk, claims(%{"nbf" => now + 600})),
      # an issuer that is not bound
      sign(jwk, claims(%{"iss" => "https://auth.example.com/realms/other"})),
      # not for this audience
      sign(jwk, claims(%{"aud" => ["account"]})),
      # an ID token, not an access token
      sign(jwk, claims(%{"typ" => "ID"})),
      # a client that may not use this
      sign(jwk, claims(%{"azp" => "someone-else"})),
      # Organization issuer: no, two, or a malformed Organization
      sign(jwk, claims(%{"iss" => @org_issuer})),
      sign(
        jwk,
        claims(%{
          "iss" => @org_issuer,
          "organization" => %{"a" => %{"id" => @staff_tenant}, "b" => %{"id" => @other_tenant}}
        })
      ),
      sign(jwk, org_claims(String.upcase(@other_tenant))),
      sign(jwk, org_claims("not-a-uuid"))
    ]

    for token <- tokens do
      conn = query(build_conn(), site.domain, token)
      assert conn.status == 401, inspect(token)
      refute conn.resp_body =~ "results"
    end
  end

  test "an unsigned token is refused", %{staff_site: site} do
    header = Base.url_encode64(~s({"alg":"none","typ":"JWT"}), padding: false)
    payload = claims(%{}) |> Jason.encode!() |> Base.url_encode64(padding: false)

    assert refused?(query(build_conn(), site.domain, header <> "." <> payload <> "."))
  end

  test "the key reads stats only, never the sites list", %{jwk: jwk, staff_site: site} do
    conn =
      build_conn()
      |> put_req_header("authorization", "Bearer " <> @key)
      |> put_req_header("x-avora-user-token", sign(jwk, claims(%{})))
      |> get("/api/v1/stats/aggregate", %{"site_id" => site.domain, "metrics" => "visitors"})

    # Stats API v1 is a stats read too, and still tenant-scoped.
    assert json_response(conn, 200)

    conn =
      build_conn()
      |> put_req_header("authorization", "Bearer " <> @key)
      |> put_req_header("x-avora-user-token", sign(jwk, claims(%{})))
      |> get("/api/v1/stats/aggregate", %{"site_id" => "other.example.com", "metrics" => "visitors"})

    assert conn.status == 401
  end

  test "with no issuer bound the key answers 403", %{staff_site: site, jwk: jwk} do
    Application.put_env(:plausible, Avora.TenantToken, Avora.TenantToken.Config.disabled())

    conn = query(build_conn(), site.domain, sign(jwk, claims(%{})))
    assert json_response(conn, 403)
  end

  test "other API keys are unaffected", %{conn: conn} do
    user = new_user()
    site = new_site(owner: user, domain: "mine.example.com")
    key = insert(:api_key, user: user, team: team_of(user))

    conn = query(conn, site.domain, nil, key.key)
    assert json_response(conn, 200)
  end

  test "a replaced key is refused", %{owner: owner, jwk: jwk, staff_site: site} do
    Application.put_env(:plausible, Plausible.Provisioning, owner_email: owner.email)
    assert {:ok, :replaced} = ServiceKey.ensure(String.duplicate("cd34", 16))

    assert json_response(query(build_conn(), site.domain, sign(jwk, claims(%{}))), 401)
  end
end
