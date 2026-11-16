defmodule PlausibleWeb.Api.ProvisioningControllerTest do
  use PlausibleWeb.ConnCase, async: false
  use Plausible.Teams.Test

  import Ecto.Query

  alias Plausible.Repo
  alias Plausible.Site.SharedLink

  @token "provisioning-test-token"

  setup %{conn: conn} do
    original = Application.get_env(:plausible, Plausible.Provisioning)
    on_exit(fn -> Application.put_env(:plausible, Plausible.Provisioning, original) end)

    owner = new_user(email: "provisioner@example.com")
    configure(api_token: @token, owner_email: owner.email)

    conn = put_private(conn, PlausibleWeb.FirstLaunchPlug, :skip)
    {:ok, conn: conn, owner: owner}
  end

  defp configure(opts), do: Application.put_env(:plausible, Plausible.Provisioning, opts)

  defp authed(conn, token \\ @token),
    do: put_req_header(conn, "authorization", "Bearer " <> token)

  describe "authorization" do
    test "is disabled (404) when no token is configured", %{conn: conn, owner: owner} do
      for token <- [nil, ""] do
        configure(api_token: token, owner_email: owner.email)

        conn = conn |> authed("") |> post("/api/provisioning/sites", %{domain: "a.example.com"})
        assert json_response(conn, 404)
        refute Repo.get_by(Plausible.Site, domain: "a.example.com")
      end
    end

    test "rejects a missing token", %{conn: conn} do
      conn = post(conn, "/api/provisioning/sites", %{domain: "a.example.com"})
      assert json_response(conn, 401)["error"] == "Unauthorized"
      refute Repo.get_by(Plausible.Site, domain: "a.example.com")
    end

    test "rejects a wrong token", %{conn: conn} do
      for token <- ["wrong", "", @token <> "x", String.slice(@token, 0..-2//1)] do
        conn =
          conn
          |> authed(token)
          |> post("/api/provisioning/sites", %{domain: "a.example.com"})

        assert json_response(conn, 401)["error"] == "Unauthorized", "token #{inspect(token)}"
      end

      refute Repo.get_by(Plausible.Site, domain: "a.example.com")
    end

    test "rejects other authorization schemes", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Basic " <> @token)
        |> post("/api/provisioning/sites", %{domain: "a.example.com"})

      assert json_response(conn, 401)
    end

    test "returns 503 when the owner account does not exist", %{conn: conn} do
      configure(api_token: @token, owner_email: "missing@example.com")

      conn = conn |> authed() |> post("/api/provisioning/sites", %{domain: "a.example.com"})
      assert json_response(conn, 503)
    end
  end

  describe "POST /api/provisioning/sites" do
    test "creates a site owned by the configured owner", %{conn: conn, owner: owner} do
      conn =
        conn
        |> authed()
        |> post("/api/provisioning/sites", %{
          domain: "tenant.example.com",
          timezone: "Europe/Helsinki"
        })

      assert json_response(conn, 201) == %{
               "domain" => "tenant.example.com",
               "timezone" => "Europe/Helsinki"
             }

      site = Plausible.Sites.get_for_user(owner, "tenant.example.com", roles: [:owner])
      assert site.timezone == "Europe/Helsinki"
    end

    test "creates every site in the owner's existing team, even once it is set up",
         %{conn: conn, owner: owner} do
      first = new_site(domain: "first.example.com", owner: owner)
      team = Plausible.Teams.complete_setup(first.team)
      add_member(team, role: :viewer)

      conn
      |> authed()
      |> post("/api/provisioning/sites", %{domain: "second.example.com"})
      |> json_response(201)

      second = Repo.get_by(Plausible.Site, domain: "second.example.com")
      assert second.team_id == team.id
      assert {:ok, %{id: team_id}} = Plausible.Teams.get_owned_team(owner)
      assert team_id == team.id
    end

    test "rejects an invalid site", %{conn: conn} do
      conn =
        conn
        |> authed()
        |> post("/api/provisioning/sites", %{domain: "tenant.example.com", timezone: "Nowhere"})

      assert %{"details" => %{"timezone" => _}} = json_response(conn, 422)
    end

    test "rejects a domain that is already taken", %{conn: conn} do
      new_site(domain: "taken.example.com")

      conn = conn |> authed() |> post("/api/provisioning/sites", %{domain: "taken.example.com"})
      assert %{"details" => %{"domain" => _}} = json_response(conn, 422)
    end
  end

  describe "DELETE /api/provisioning/sites/:domain" do
    test "deletes a site of the owner", %{conn: conn, owner: owner} do
      new_site(domain: "tenant.example.com", owner: owner)

      conn = conn |> authed() |> delete("/api/provisioning/sites/tenant.example.com")
      assert response(conn, 204)
      refute Repo.get_by(Plausible.Site, domain: "tenant.example.com")
    end

    test "does not touch sites the owner does not own", %{conn: conn} do
      new_site(domain: "other.example.com")

      conn = conn |> authed() |> delete("/api/provisioning/sites/other.example.com")
      assert json_response(conn, 404)
      assert Repo.get_by(Plausible.Site, domain: "other.example.com")
    end
  end

  describe "POST /api/provisioning/sites/:domain/shared-link" do
    test "creates a shared link and returns its URL", %{conn: conn, owner: owner} do
      site = new_site(domain: "tenant.example.com", owner: owner)

      conn = conn |> authed() |> post("/api/provisioning/sites/tenant.example.com/shared-link")
      %{"url" => url} = json_response(conn, 200)

      [link] = Repo.all(from(l in SharedLink, where: l.site_id == ^site.id))
      assert url == Plausible.Sites.shared_link_url(site, link)
      assert url =~ "/share/tenant.example.com?auth=" <> link.slug
    end

    test "rotating replaces the previous link", %{conn: conn, owner: owner} do
      site = new_site(domain: "tenant.example.com", owner: owner)
      other = insert(:shared_link, site: site, name: "Kept")

      %{"url" => first} =
        conn
        |> authed()
        |> post("/api/provisioning/sites/tenant.example.com/shared-link")
        |> json_response(200)

      %{"url" => second} =
        conn
        |> authed()
        |> post("/api/provisioning/sites/tenant.example.com/shared-link")
        |> json_response(200)

      assert first != second

      links = Repo.all(from(l in SharedLink, where: l.site_id == ^site.id))
      assert length(links) == 2
      assert Enum.any?(links, &(&1.id == other.id))

      [provisioned] =
        Enum.filter(links, &(&1.name == Plausible.Provisioning.shared_link_name()))

      assert second =~ "auth=" <> provisioned.slug
      refute first =~ "auth=" <> provisioned.slug
    end

    test "does not create links for sites the owner does not own", %{conn: conn} do
      site = new_site(domain: "other.example.com")

      conn = conn |> authed() |> post("/api/provisioning/sites/other.example.com/shared-link")
      assert json_response(conn, 404)
      assert Repo.all(from(l in SharedLink, where: l.site_id == ^site.id)) == []
    end
  end
end
