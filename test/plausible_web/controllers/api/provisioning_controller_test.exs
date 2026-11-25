defmodule PlausibleWeb.Api.ProvisioningControllerTest do
  use PlausibleWeb.ConnCase, async: false
  use Plausible.Teams.Test
  use Oban.Testing, repo: Plausible.Repo

  import Ecto.Query

  alias Plausible.Repo

  @token "provisioning-test-token"
  @tenant "0b6f2a1e-7c3d-4e5f-9a8b-1c2d3e4f5a6b"
  @other_tenant "9d8c7b6a-5f4e-4d3c-8b2a-1f0e9d8c7b6a"

  setup %{conn: conn} do
    original = Application.get_env(:plausible, Plausible.Provisioning)
    on_exit(fn -> Application.put_env(:plausible, Plausible.Provisioning, original) end)

    # The service owner, as the app creates it (Plausible.Provisioning.ensure_owner/0).
    Application.put_env(:plausible, Plausible.Provisioning,
      owner_email: "provisioning@avora-analytics.invalid"
    )

    {:ok, :created} = Plausible.Provisioning.ensure_owner()
    owner = Plausible.Provisioning.owner()
    configure(api_token: @token, owner_email: owner.email)

    conn = put_private(conn, PlausibleWeb.FirstLaunchPlug, :skip)
    {:ok, conn: conn, owner: owner}
  end

  defp configure(opts), do: Application.put_env(:plausible, Plausible.Provisioning, opts)

  defp fresh_conn, do: put_private(build_conn(), PlausibleWeb.FirstLaunchPlug, :skip)

  defp authed(conn, token \\ @token),
    do: put_req_header(conn, "authorization", "Bearer " <> token)

  defp sites_path(tenant \\ @tenant), do: "/internal/avora/v1/tenants/#{tenant}/sites"
  defp site_path(domain, tenant \\ @tenant), do: sites_path(tenant) <> "/" <> domain

  defp tenant_site(owner, domain, tenant \\ @tenant) do
    {:ok, :created, site} = Plausible.Provisioning.put_site(owner, tenant, domain, %{})
    site
  end

  defp tenant_of(domain) do
    case Repo.get_by(Plausible.Site, domain: domain) |> Repo.preload(:team) do
      nil -> nil
      site -> site.team.tenant_id
    end
  end

  defp owns?(user, team_id) do
    Repo.exists?(
      from(m in Plausible.Teams.Membership,
        where: m.team_id == ^team_id and m.user_id == ^user.id and m.role == :owner
      )
    )
  end

  describe "authorization" do
    test "is disabled (404) when no token is configured", %{conn: conn, owner: owner} do
      for token <- [nil, ""] do
        configure(api_token: token, owner_email: owner.email)

        conn = conn |> authed("") |> put(site_path("a.example.com"))
        assert json_response(conn, 404)
        refute Repo.get_by(Plausible.Site, domain: "a.example.com")
      end
    end

    test "rejects a missing token", %{conn: conn} do
      conn = put(conn, site_path("a.example.com"))
      assert json_response(conn, 401)["error"] == "Unauthorized"
      refute Repo.get_by(Plausible.Site, domain: "a.example.com")
    end

    test "rejects a wrong token", %{conn: conn} do
      for token <- ["wrong", "", @token <> "x", String.slice(@token, 0..-2//1)] do
        conn = conn |> authed(token) |> put(site_path("a.example.com"))
        assert json_response(conn, 401)["error"] == "Unauthorized", "token #{inspect(token)}"
      end

      for request <- [&get(&1, sites_path()), &delete(&1, sites_path() |> Path.dirname())] do
        assert conn |> authed("wrong") |> request.() |> json_response(401)
      end

      refute Repo.get_by(Plausible.Site, domain: "a.example.com")
    end

    test "accepts the bearer scheme in any case", %{conn: conn} do
      for {scheme, i} <- Enum.with_index(["bearer", "BEARER", "BeArEr"]) do
        conn =
          conn
          |> put_req_header("authorization", "#{scheme} #{@token}")
          |> put(site_path("site#{i}.example.com"))

        assert json_response(conn, 201)
      end
    end

    test "rejects other authorization schemes", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Basic " <> Base.encode64("u:" <> @token))
        |> put(site_path("a.example.com"))

      assert json_response(conn, 401)
    end

    test "returns 503 when the owner account does not exist", %{conn: conn} do
      configure(api_token: @token, owner_email: "nobody@example.com")
      conn = conn |> authed() |> put(site_path("a.example.com"))
      assert json_response(conn, 503)
    end

    test "refuses a tenant id that is not a UUID", %{conn: conn} do
      for tenant <- ["tenant-a", "123", @tenant <> "0", "#{@tenant}x"] do
        conn = conn |> authed() |> put(site_path("a.example.com", tenant))
        assert json_response(conn, 400) == %{"error" => "Invalid tenant id"}
      end

      refute Repo.get_by(Plausible.Site, domain: "a.example.com")
    end

    test "the old site endpoints are gone", %{conn: conn} do
      conn = conn |> authed() |> post("/api/provisioning/sites", %{domain: "a.example.com"})
      assert conn.status == 404
      refute Repo.get_by(Plausible.Site, domain: "a.example.com")
    end
  end

  describe "PUT /internal/avora/v1/tenants/:tenant_id/sites/:domain" do
    test "creates the tenant's site in the tenant's team, owned by the owner",
         %{conn: conn, owner: owner} do
      conn =
        conn
        |> authed()
        |> put_req_header("idempotency-key", "op-1:step-1")
        |> put(site_path("tenant.example.com"), %{timezone: "Europe/Helsinki"})

      assert json_response(conn, 201) == %{
               "domain" => "tenant.example.com",
               "timezone" => "Europe/Helsinki",
               "tenant_id" => @tenant
             }

      site = Repo.get_by(Plausible.Site, domain: "tenant.example.com") |> Repo.preload(:team)
      assert site.timezone == "Europe/Helsinki"
      assert site.team.tenant_id == @tenant
      assert site.team.setup_complete
      assert owns?(owner, site.team_id)
    end

    test "each tenant has its own team; a tenant's sites share it", %{conn: conn, owner: owner} do
      personal = new_site(domain: "personal.example.com", owner: owner)

      for {domain, tenant} <- [
            {"a1.example.com", @tenant},
            {"a2.example.com", @tenant},
            {"b1.example.com", @other_tenant}
          ] do
        assert conn |> authed() |> put(site_path(domain, tenant)) |> json_response(201)
      end

      team = fn d -> Repo.get_by(Plausible.Site, domain: d).team_id end
      assert team.("a1.example.com") == team.("a2.example.com")
      assert team.("a1.example.com") != team.("b1.example.com")
      refute team.("a1.example.com") == personal.team_id
      assert tenant_of("personal.example.com") == nil
    end

    test "takes the tenant id in any case and stores it lowercase", %{conn: conn} do
      conn
      |> authed()
      |> put(site_path("t.example.com", String.upcase(@tenant)))
      |> json_response(201)

      assert tenant_of("t.example.com") == @tenant
    end

    test "rejects an invalid site", %{conn: conn} do
      conn = conn |> authed() |> put(site_path("tenant.example.com"), %{timezone: "Nowhere"})
      assert %{"details" => %{"timezone" => _}} = json_response(conn, 422)
      refute Repo.get_by(Plausible.Site, domain: "tenant.example.com")
    end

    test "is idempotent: a repeat returns the existing site", %{conn: conn} do
      assert conn
             |> authed()
             |> put(site_path("tenant.example.com"), %{timezone: "Europe/Helsinki"})
             |> json_response(201)

      # a repeated call, also with other parameters, returns the existing site
      assert conn
             |> authed()
             |> put(site_path("tenant.example.com"))
             |> json_response(200) == %{
               "domain" => "tenant.example.com",
               "timezone" => "Europe/Helsinki",
               "tenant_id" => @tenant
             }

      assert [_] = Repo.all(from(s in Plausible.Site, where: s.domain == "tenant.example.com"))
      assert [_] = Repo.all(from(t in Plausible.Teams.Team, where: t.tenant_id == ^@tenant))
    end

    test "a domain of another tenant, of the owner's other teams, or of anyone else is 409",
         %{conn: conn, owner: owner} do
      tenant_site(owner, "other-tenant.example.com", @other_tenant)
      new_site(domain: "owners-own.example.com", owner: owner)
      new_site(domain: "taken.example.com")

      for domain <- ~w(other-tenant.example.com owners-own.example.com taken.example.com) do
        conn = conn |> authed() |> put(site_path(domain))
        assert json_response(conn, 409) == %{"error" => "Domain is already in use"}, domain
      end

      assert tenant_of("other-tenant.example.com") == @other_tenant
      assert tenant_of("owners-own.example.com") == nil
      assert tenant_of("taken.example.com") == nil
    end

    test "a legacy site moves into the adopting tenant's team, and only that tenant's",
         %{conn: conn, owner: owner} do
      legacy = new_user(email: "legacy@example.com")

      configure(
        api_token: @token,
        owner_email: owner.email,
        legacy_owner_email: legacy.email,
        adopting_tenant_id: @tenant
      )

      site = new_site(domain: "legacy.example.com", owner: legacy)

      # another tenant may not adopt it
      conn0 = fresh_conn() |> authed() |> put(site_path("legacy.example.com", @other_tenant))
      assert json_response(conn0, 409) == %{"error" => "Domain is already in use"}
      assert tenant_of("legacy.example.com") == nil

      conn1 = conn |> authed() |> put(site_path("legacy.example.com"))

      assert json_response(conn1, 200) == %{
               "domain" => "legacy.example.com",
               "timezone" => site.timezone,
               "tenant_id" => @tenant
             }

      moved = Repo.get!(Plausible.Site, site.id)
      assert moved.team_id != site.team_id
      assert tenant_of("legacy.example.com") == @tenant
      assert owns?(owner, moved.team_id)

      # repeating is a no-op; another tenant can no longer take it
      assert fresh_conn() |> authed() |> put(site_path("legacy.example.com")) |> json_response(200)

      conn2 = fresh_conn() |> authed() |> put(site_path("legacy.example.com", @other_tenant))
      assert json_response(conn2, 409) == %{"error" => "Domain is already in use"}
      assert tenant_of("legacy.example.com") == @tenant
    end

    test "an adopted site brings no people into the tenant team", %{conn: conn, owner: owner} do
      legacy = new_user(email: "legacy@example.com")

      configure(
        api_token: @token,
        owner_email: owner.email,
        legacy_owner_email: legacy.email,
        adopting_tenant_id: @tenant
      )

      site = new_site(domain: "people.example.com", owner: legacy)
      add_guest(site, role: :editor)
      invite_guest(site, "invitee@example.com", role: :viewer, inviter: legacy)

      assert conn |> authed() |> put(site_path("people.example.com")) |> json_response(200)

      team_id = Repo.get!(Plausible.Site, site.id).team_id

      members =
        Repo.all(
          from(m in Plausible.Teams.Membership, where: m.team_id == ^team_id, select: m.user_id)
        )

      assert members == [owner.id]
      assert Repo.all(from(i in Plausible.Teams.Invitation, where: i.team_id == ^team_id)) == []

      assert Repo.all(from(gm in Plausible.Teams.GuestMembership, where: gm.site_id == ^site.id)) ==
               []
    end

    test "nothing is adopted without the settings, from another owner, or by a former domain",
         %{conn: conn, owner: owner} do
      legacy = new_user(email: "legacy@example.com")
      plain = new_site(domain: "plain.example.com", owner: legacy)

      # no adopting tenant / legacy owner configured
      assert conn |> authed() |> put(site_path("plain.example.com")) |> json_response(409)

      configure(
        api_token: @token,
        owner_email: owner.email,
        legacy_owner_email: legacy.email,
        adopting_tenant_id: @tenant
      )

      # a site of someone other than the legacy owner
      new_site(domain: "stranger.example.com")
      conn1 = fresh_conn() |> authed() |> put(site_path("stranger.example.com"))
      assert json_response(conn1, 409)

      renamed =
        [domain: "new-name.example.com", owner: legacy]
        |> new_site()
        |> Ecto.Changeset.change(domain_changed_from: "old-name.example.com")
        |> Repo.update!()

      conn2 = fresh_conn() |> authed() |> put(site_path("old-name.example.com"))
      assert json_response(conn2, 409) == %{"error" => "Domain is already in use"}

      assert Repo.get!(Plausible.Site, plain.id).team_id == plain.team_id
      assert Repo.get!(Plausible.Site, renamed.id).team_id == renamed.team_id
      assert tenant_of("stranger.example.com") == nil
    end
  end

  describe "GET /internal/avora/v1/tenants/:tenant_id/sites" do
    test "lists only the tenant's sites", %{conn: conn, owner: owner} do
      tenant_site(owner, "b.example.com")
      tenant_site(owner, "a.example.com")
      tenant_site(owner, "other.example.com", @other_tenant)
      new_site(domain: "no-tenant.example.com", owner: owner)

      assert %{"sites" => sites} = conn |> authed() |> get(sites_path()) |> json_response(200)
      assert Enum.map(sites, & &1["domain"]) == ["a.example.com", "b.example.com"]
      assert Enum.all?(sites, &(&1["tenant_id"] == @tenant))

      assert conn |> authed() |> get(sites_path(Ecto.UUID.generate())) |> json_response(200) ==
               %{"sites" => []}
    end
  end

  describe "DELETE /internal/avora/v1/tenants/:tenant_id/sites/:domain" do
    test "deletes the tenant's site", %{conn: conn, owner: owner} do
      tenant_site(owner, "tenant.example.com")

      conn = conn |> authed() |> delete(site_path("tenant.example.com"))
      assert response(conn, 204)
      refute Repo.get_by(Plausible.Site, domain: "tenant.example.com")
    end

    @tag :slow
    test "also deletes the site's ClickHouse data", %{conn: conn, owner: owner} do
      site = tenant_site(owner, "tenant.example.com")
      kept = tenant_site(owner, "kept.example.com")
      populate_stats(site, [build(:pageview), build(:pageview)])
      populate_stats(kept, [build(:pageview)])

      conn = conn |> authed() |> delete(site_path("tenant.example.com"))
      assert response(conn, 204)

      assert_enqueued(worker: Plausible.Workers.ClickhouseCleanSites)
      assert %{success: 1} = Oban.drain_queue(queue: :clickhouse_clean_sites)

      assert event_count(site) == 0
      assert event_count(kept) == 1
    end

    test "never another tenant's site, a site without a tenant or one outside the team",
         %{conn: conn, owner: owner} do
      tenant_site(owner, "other-tenant.example.com", @other_tenant)
      new_site(domain: "no-tenant.example.com", owner: owner)
      new_site(domain: "other.example.com")

      for domain <- ~w(other-tenant.example.com no-tenant.example.com other.example.com) do
        conn = conn |> authed() |> delete(site_path(domain))
        assert json_response(conn, 404), domain
        assert Repo.get_by(Plausible.Site, domain: domain)
      end
    end
  end

  describe "DELETE /internal/avora/v1/tenants/:tenant_id" do
    test "deletes every site of the tenant and nothing else; repeatable",
         %{conn: conn, owner: owner} do
      tenant_site(owner, "a.example.com")
      tenant_site(owner, "b.example.com")
      tenant_site(owner, "other.example.com", @other_tenant)

      path = "/internal/avora/v1/tenants/#{@tenant}"
      assert conn |> authed() |> delete(path) |> response(204)
      refute Repo.get_by(Plausible.Site, domain: "a.example.com")
      refute Repo.get_by(Plausible.Site, domain: "b.example.com")
      assert Repo.get_by(Plausible.Site, domain: "other.example.com")

      # the tenant's team goes too (it is empty); the other tenant's stays
      refute Repo.get_by(Plausible.Teams.Team, tenant_id: @tenant)
      assert Repo.get_by(Plausible.Teams.Team, tenant_id: @other_tenant)

      assert conn |> authed() |> delete(path) |> response(204)
    end
  end

  describe "shared links" do
    test "are not offered by the provisioning API", %{conn: conn, owner: owner} do
      site = tenant_site(owner, "tenant.example.com")

      conn = conn |> authed() |> post(site_path("tenant.example.com") <> "/shared-link")
      assert conn.status == 404

      assert Repo.all(from(l in Plausible.Site.SharedLink, where: l.site_id == ^site.id)) == []
    end
  end

  defp event_count(site) do
    Plausible.ClickhouseRepo.aggregate(
      from(e in "events_v2", where: e.site_id == ^site.id),
      :count
    )
  end
end
