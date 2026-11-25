defmodule PlausibleWeb.Api.ServiceKeyQueryTest do
  # Fork addition: the ensured service key reads a provisioned site's
  # numbers through Stats API v2, and stops working once replaced.
  use PlausibleWeb.ConnCase, async: false
  use Plausible.Teams.Test

  alias Plausible.Provisioning
  alias Plausible.Provisioning.ServiceKey

  @key String.duplicate("ab12", 16)

  setup do
    original = Application.get_env(:plausible, Plausible.Provisioning)
    on_exit(fn -> Application.put_env(:plausible, Plausible.Provisioning, original) end)

    owner = new_user(email: "provisioner@example.com")
    Application.put_env(:plausible, Plausible.Provisioning, owner_email: owner.email)
    {:ok, :created, site} = Provisioning.create_site(owner, %{"domain" => "acme.example.com"})

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

    {:ok, owner: owner, site: site}
  end

  defp query(conn, key, site_id) do
    conn
    |> put_req_header("authorization", "Bearer " <> key)
    |> post("/api/v2/query", %{
      "site_id" => site_id,
      "metrics" => ["visitors", "pageviews"],
      "date_range" => ["2021-01-01", "2021-01-31"]
    })
  end

  test "the ensured key reads a provisioned site", %{conn: conn, owner: owner, site: site} do
    assert {:ok, :created} = ServiceKey.ensure(@key)

    assert json_response(query(conn, @key, site.domain), 200)["results"] == [
             %{"metrics" => [2, 3], "dimensions" => []}
           ]

    # A replaced key is refused.
    Application.put_env(:plausible, Plausible.Provisioning, owner_email: owner.email)
    assert {:ok, :replaced} = ServiceKey.ensure(String.duplicate("cd34", 16))
    assert json_response(query(build_conn(), @key, site.domain), 401)
  end

  test "a site the owner does not have is refused", %{conn: conn} do
    other = new_user(email: "someone@example.com")
    other_site = new_site(owner: other, domain: "other.example.com")
    assert {:ok, :created} = ServiceKey.ensure(@key)

    conn = query(conn, @key, other_site.domain)
    assert conn.status in [401, 403, 404]
    refute conn.resp_body =~ "results"
  end
end
