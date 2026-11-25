defmodule Plausible.ProvisioningTest do
  # Fork addition: the service owner account (Plausible.Provisioning).
  use Plausible.DataCase, async: false
  use Plausible.Teams.Test

  alias Plausible.Auth
  alias Plausible.Provisioning

  @service "provisioning@avora-analytics.invalid"

  setup do
    original = Application.get_env(:plausible, Plausible.Provisioning)
    on_exit(fn -> Application.put_env(:plausible, Plausible.Provisioning, original) end)
    :ok
  end

  defp configure(opts), do: Application.put_env(:plausible, Plausible.Provisioning, opts)

  test "creates the service owner once, unverified and without a password" do
    configure(owner_email: @service)

    assert Provisioning.ensure_owner() == {:ok, :created}
    assert Provisioning.ensure_owner() == {:ok, :exists}

    owner = Provisioning.owner()
    assert owner.email == @service
    refute owner.email_verified
    assert owner.password_hash in [nil, ""]
    assert owner.oidc_subject == nil
  end

  test "an account anyone could sign in to is never the owner" do
    for {email, changes} <- [
          # a real address
          {"someone@example.com", []},
          # .invalid, but verified, with a password, or linked to single sign-on
          {@service, [email_verified: true]},
          {@service, [password_hash: Bcrypt.hash_pwd_salt("a-long-password-1")]},
          {@service, [oidc_issuer: "https://idp.example.com", oidc_subject: "s-1"]}
        ] do
      Repo.delete_all(Auth.User)

      %Auth.User{}
      |> Auth.User.changeset(%{email: email, name: "x", email_verified: false})
      |> Repo.insert!()
      |> Ecto.Changeset.change(changes)
      |> Repo.update!()

      configure(owner_email: email)
      assert Provisioning.owner() == nil, inspect(changes)

      if email == @service do
        # and ensure_owner neither adopts nor repairs it
        assert {:error, _} = Provisioning.ensure_owner()
        assert Provisioning.owner() == nil
      end
    end
  end

  test "never creates an account for a real address, and does nothing unconfigured" do
    configure(owner_email: "someone@example.com")
    assert Provisioning.ensure_owner() == {:ok, :disabled}
    refute Repo.get_by(Auth.User, email: "someone@example.com")

    configure(owner_email: nil)
    assert Provisioning.ensure_owner() == {:ok, :disabled}
  end

  test "single sign-on cannot link to the service owner" do
    configure(owner_email: @service)
    {:ok, :created} = Provisioning.ensure_owner()

    claims = %{
      "iss" => "https://idp.example.com/realms/staff",
      "sub" => "9b0f7c1e-4a8e-4f55-9a43-3b1f2c7d8e90",
      "email" => @service,
      "email_verified" => true
    }

    assert {:error, :account_not_linkable} =
             Auth.OIDC.Users.resolve(claims,
               enabled: true,
               issuer: "https://idp.example.com/realms/staff",
               allowed_groups: :any
             )

    assert Provisioning.owner().oidc_subject == nil
  end

  test "a tenant team is created once, set up, and owned by the owner" do
    owner = new_user(email: "owner@example.com")
    tenant = Ecto.UUID.generate()

    assert {:ok, team} = Provisioning.ensure_tenant_team(owner, tenant)
    assert team.tenant_id == tenant and team.setup_complete
    assert {:ok, again} = Provisioning.ensure_tenant_team(owner, tenant)
    assert again.id == team.id

    # another account's lookup never finds it
    assert Provisioning.tenant_team(new_user(), tenant) == nil
  end
end
