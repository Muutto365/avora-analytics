defmodule Avora.RolesTest do
  use Plausible.DataCase, async: false
  use Plausible.Teams.Test

  alias Avora.Roles
  alias Plausible.Auth.OIDC.Users
  alias Plausible.Teams

  @issuer "https://id.example.com"
  @client "analytics"
  @map %{
    "analytics-viewer" => :viewer,
    "analytics-editor" => :editor,
    "analytics-admin" => :admin
  }

  setup do
    oidc = Application.get_env(:plausible, Plausible.Auth.OIDC)
    provisioning = Application.get_env(:plausible, Plausible.Provisioning)

    Application.put_env(:plausible, Plausible.Auth.OIDC,
      enabled: true,
      issuer: @issuer,
      client_id: @client,
      role_map: @map,
      session_hours: 12,
      disable_password_login: false
    )

    owner = new_user(email: "provisioner@example.com")
    site = new_site(owner: owner)
    team = team_of(owner)
    Application.put_env(:plausible, Plausible.Provisioning, owner_email: owner.email)

    test_pid = self()
    handler = "roles-test-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler,
      [:avora, :audit],
      fn _, _, record, _ -> send(test_pid, {:audit, record}) end,
      nil
    )

    on_exit(fn ->
      :telemetry.detach(handler)
      Application.put_env(:plausible, Plausible.Auth.OIDC, oidc)
      Application.put_env(:plausible, Plausible.Provisioning, provisioning)
    end)

    {:ok, owner: owner, team: team, site: site}
  end

  defp claims(sub, roles, client \\ @client) do
    %{
      "iss" => @issuer,
      "sub" => sub,
      "email" => "#{sub}@example.com",
      "email_verified" => true,
      "resource_access" => %{client => %{"roles" => roles}}
    }
  end

  defp role_in(team, user) do
    case Repo.get_by(Teams.Membership, team_id: team.id, user_id: user.id) do
      nil -> nil
      membership -> membership.role
    end
  end

  describe "role_from_claims/3" do
    test "the highest mapped role of this client only" do
      assert Roles.role_from_claims(
               claims("a", ["analytics-viewer", "analytics-admin"]),
               @client,
               @map
             ) ==
               :admin

      assert Roles.role_from_claims(claims("a", ["analytics-editor", "x"]), @client, @map) ==
               :editor

      assert Roles.role_from_claims(claims("a", ["analytics-admin"], "other"), @client, @map) ==
               nil

      assert Roles.role_from_claims(claims("a", ["Analytics-Admin", "admin"]), @client, @map) ==
               nil

      assert Roles.role_from_claims(%{"resource_access" => "x"}, @client, @map) == nil
      assert Roles.role_from_claims(%{}, @client, @map) == nil
    end
  end

  describe "sign-in" do
    test "applies the mapped role to the managed team at every sign-in", %{team: team} do
      {:ok, user} = Users.resolve(claims("p1", ["analytics-viewer"]))
      assert role_in(team, user) == :viewer
      assert_receive {:audit, %{"audit.action" => "role.sync", "avora.role" => "viewer"} = record}
      assert record["avora.previous_role"] == "none"
      assert record["avora.via"] == "sign_in"

      {:ok, %{id: id}} = Users.resolve(claims("p1", ["analytics-admin"]))
      assert id == user.id
      assert role_in(team, user) == :admin

      assert_receive {:audit,
                      %{
                        "audit.action" => "role.sync",
                        "avora.role" => "admin",
                        "avora.previous_role" => "viewer"
                      }}

      # unchanged: no record
      {:ok, _} = Users.resolve(claims("p1", ["analytics-admin"]))
      refute_receive {:audit, %{"audit.action" => "role.sync"}}, 50
    end

    test "no mapped role: refused, membership and sessions removed", %{team: team} do
      {:ok, user} = Users.resolve(claims("p2", ["analytics-editor"]))
      assert role_in(team, user) == :editor
      session = Plausible.Auth.UserSessions.create!(user, "Unknown")

      assert {:error, :role_not_granted} = Users.resolve(claims("p2", ["something-else"]))
      assert role_in(team, user) == nil
      refute Repo.get(Plausible.Auth.UserSession, session.id)

      assert_receive {:audit,
                      %{
                        "audit.action" => "role.sync",
                        "avora.role" => "none",
                        "avora.previous_role" => "editor"
                      }}
    end

    test "nobody is created without a mapped role" do
      assert {:error, :role_not_granted} = Users.resolve(claims("p3", []))
      refute Repo.get_by(Plausible.Auth.User, email: "p3@example.com")
    end

    test "the team's owner is never changed", %{owner: owner, team: team} do
      owner =
        owner
        |> Ecto.Changeset.change(oidc_issuer: @issuer, oidc_subject: "owner-sub")
        |> Repo.update!()

      {:ok, %{id: owner_id}} =
        Users.resolve(Map.put(claims("owner-sub", ["analytics-viewer"]), "email", owner.email))

      assert owner_id == owner.id
      assert role_in(team, owner) == :owner

      assert {:error, :role_not_granted} =
               Users.resolve(Map.put(claims("owner-sub", []), "email", owner.email))

      assert role_in(team, owner) == :owner
    end

    test "without a managed team, sign-in still needs a role and changes no team" do
      Application.put_env(:plausible, Plausible.Provisioning, owner_email: nil)
      {:ok, user} = Users.resolve(claims("p4", ["analytics-viewer"]))

      assert Repo.all(
               from(m in Teams.Membership, where: m.user_id == ^user.id and m.role != :owner)
             ) == []
    end
  end

  describe "the managed team is read-only in the application" do
    test "role changes, removals and invitations are refused", %{
      owner: owner,
      team: team,
      site: site
    } do
      {:ok, member} = Users.resolve(claims("p5", ["analytics-viewer"]))

      assert {:error, :permission_denied} =
               Teams.Memberships.UpdateRole.update(team, member.id, "admin", owner)

      assert {:error, :permission_denied} =
               Teams.Memberships.Remove.remove(team, member.id, owner)

      assert {:error, :permission_denied} =
               Teams.Invitations.InviteToTeam.invite(team, owner, "new@example.com", :viewer)

      assert {:error, :permission_denied} =
               Teams.Invitations.InviteToSite.invite(site, owner, "guest@example.com", :viewer)

      assert role_in(team, member) == :viewer
    end

    test "other teams are unaffected" do
      other_owner = new_user()
      new_site(owner: other_owner)
      other_team = team_of(other_owner)
      member = new_user()
      add_member(other_team, user: member, role: :viewer)

      assert {:ok, _} =
               Teams.Memberships.UpdateRole.update(other_team, member.id, "editor", other_owner)
    end
  end
end
