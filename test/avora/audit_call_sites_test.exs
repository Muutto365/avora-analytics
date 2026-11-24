defmodule Avora.AuditCallSitesTest do
  use PlausibleWeb.ConnCase, async: false
  use Plausible.Teams.Test
  use Oban.Testing, repo: Plausible.Repo

  alias Plausible.Repo

  @token "provisioning-test-token"

  setup do
    test_pid = self()
    handler = "avora-audit-test-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler,
      [:avora, :audit],
      fn _event, _measurements, record, _ -> send(test_pid, {:audit, record}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler) end)
    :ok
  end

  defp assert_audit(action) do
    assert_receive {:audit, %{"audit.action" => ^action} = record}, 1000
    record
  end

  describe "API keys" do
    setup [:create_user, :log_in]

    test "creating and deleting a key", %{conn: conn, user: user} do
      new_site(owner: user)

      post(conn, Routes.settings_path(conn, :api_keys), %{
        "api_key" => %{"name" => "k", "key" => "swordfish", "type" => "stats_api"}
      })

      key = Repo.get_by!(Plausible.Auth.ApiKey, user_id: user.id)
      record = assert_audit("api_key.create")
      assert record["target.type"] == "api_key"
      assert record["target.id"] == Integer.to_string(key.id)
      assert record["principal.kind"] == "human"
      assert record["principal.id"] == "unbound"
      refute Enum.any?(Map.values(record), &(&1 == user.email or &1 == "k"))

      delete(conn, Routes.settings_path(conn, :delete_api_key, key.id))
      assert assert_audit("api_key.delete")["target.id"] == Integer.to_string(key.id)
    end
  end

  describe "provisioning" do
    setup %{conn: conn} do
      original = Application.get_env(:plausible, Plausible.Provisioning)
      on_exit(fn -> Application.put_env(:plausible, Plausible.Provisioning, original) end)
      owner = new_user(email: "provisioner@example.com")

      Application.put_env(:plausible, Plausible.Provisioning,
        api_token: @token,
        owner_email: owner.email
      )

      conn =
        conn
        |> put_private(PlausibleWeb.FirstLaunchPlug, :skip)
        |> put_req_header("authorization", "Bearer " <> @token)

      {:ok, conn: conn}
    end

    test "site create and delete", %{conn: conn} do
      post(conn, "/api/provisioning/sites", %{domain: "audit.example.com"})
      site = Repo.get_by!(Plausible.Site, domain: "audit.example.com")

      record = assert_audit("site.create")
      assert record["principal.kind"] == "service"
      assert record["principal.id"] == "service:provisioning"
      assert record["target.id"] == Integer.to_string(site.id)
      assert record["avora.via"] == "provisioning"

      # an existing site is not a new create
      post(conn, "/api/provisioning/sites", %{domain: "audit.example.com"})
      refute_receive {:audit, %{"audit.action" => "site.create"}}, 100

      delete(conn, "/api/provisioning/sites/audit.example.com")
      assert assert_audit("site.delete")["target.id"] == Integer.to_string(site.id)
    end
  end

  describe "sites in the dashboard" do
    setup [:create_user, :log_in]

    test "a CSV export and a deletion", %{conn: conn, user: user} do
      site = new_site(owner: user)

      get(conn, "/#{site.domain}/export")
      record = assert_audit("export.csv")
      assert record["target.type"] == "site"
      assert record["target.id"] == Integer.to_string(site.id)
      refute Enum.any?(Map.values(record), &(&1 == site.domain))

      delete(conn, "/#{site.domain}")
      assert assert_audit("site.delete")["avora.via"] == "ui"
    end
  end

  describe "team roles" do
    test "a role change and a removal" do
      owner = new_user()
      new_site(owner: owner)
      team = team_of(owner)
      member = new_user()
      add_member(team, user: member, role: :viewer)

      {:ok, _} = Plausible.Teams.Memberships.UpdateRole.update(team, member.id, "editor", owner)
      record = assert_audit("team.role_change")
      assert record["avora.role"] == "editor"
      assert record["avora.previous_role"] == "viewer"
      assert record["target.type"] == "user"

      {:ok, _} = Plausible.Teams.Memberships.Remove.remove(team, member.id, owner)
      assert assert_audit("team.member_remove")["avora.previous_role"] == "editor"
    end
  end

  describe "binding task" do
    test "clearing a binding" do
      user =
        new_user()
        |> Ecto.Changeset.change(oidc_issuer: "https://id.example.com", oidc_subject: "s")
        |> Repo.update!()

      {:ok, _} = Plausible.Release.OIDCBinding.apply_action("clear", user.email, "", "")
      record = assert_audit("oidc.binding_change")
      assert record["principal.id"] == "system:task"
      assert record["avora.via"] == "task"
    end
  end

  test "every action in the closed list is recorded somewhere in lib/" do
    sources =
      Path.wildcard("lib/**/*.{ex,heex}")
      |> Enum.map_join("\n", &File.read!/1)

    for action <- Avora.Audit.actions() do
      assert sources =~ ~s(action: "#{action}"), "#{action} is never recorded"
    end
  end
end
