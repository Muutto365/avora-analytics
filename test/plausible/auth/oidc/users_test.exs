defmodule Plausible.Auth.OIDC.UsersTest do
  # Fork addition
  use Plausible.DataCase, async: false

  alias Plausible.Auth
  alias Plausible.Auth.OIDC.Users

  @issuer "https://id.example.com"

  setup do
    previous = Application.get_env(:plausible, Plausible.Auth.OIDC)
    on_exit(fn -> Application.put_env(:plausible, Plausible.Auth.OIDC, previous) end)
    put_config(disable_password_login: false)
    :ok
  end

  defp put_config(opts) do
    Application.put_env(
      :plausible,
      Plausible.Auth.OIDC,
      Keyword.merge(
        [
          enabled: true,
          issuer: @issuer,
          client_id: "analytics",
          role_map: %{"staff" => :viewer},
          session_hours: 12
        ],
        opts
      )
    )
  end

  defp claims(email, sub) do
    %{
      "iss" => @issuer,
      "sub" => sub,
      "email" => email,
      "email_verified" => true,
      "resource_access" => %{"analytics" => %{"roles" => ["staff"]}}
    }
  end

  describe "first link of an existing account" do
    test "binds only if the account is still unbound when the update runs" do
      user = new_user(email: "jane@example.com")
      # another identity binds the same account after it was read
      user |> Ecto.Changeset.change(oidc_issuer: @issuer, oidc_subject: "sub-a") |> Repo.update!()

      assert {:error, :account_not_linkable} = Users.link(user, @issuer, "sub-b")
      assert Repo.reload!(user).oidc_subject == "sub-a"
    end

    test "of two identities racing for one account, exactly one wins" do
      user = new_user(email: "jane@example.com")

      results =
        ["sub-a", "sub-b"]
        |> Enum.map(fn sub -> Task.async(fn -> Users.link(user, @issuer, sub) end) end)
        |> Enum.map(&Task.await/1)

      assert [{:error, :account_not_linkable}, {:ok, %Auth.User{oidc_subject: winner}}] =
               Enum.sort_by(results, &elem(&1, 0))

      assert Repo.reload!(user).oidc_subject == winner
    end

    test "refuses an identity already bound to another account" do
      new_user(email: "first@example.com")
      |> Ecto.Changeset.change(oidc_issuer: @issuer, oidc_subject: "sub-a")
      |> Repo.update!()

      user = new_user(email: "second@example.com")

      assert {:error, :account_not_linkable} = Users.link(user, @issuer, "sub-a")
      refute Repo.reload!(user).oidc_subject
    end

    test "revokes the account's existing sessions and keeps the password" do
      user = new_user(email: "jane@example.com", password: "very-secret-and-very-long-123")
      Auth.UserSessions.create!(user, "Earlier device")
      Auth.UserSessions.create!(user, "Another device")

      assert {:ok, linked} = Users.resolve(claims("jane@example.com", "sub-a"))

      assert linked.id == user.id
      assert linked.oidc_subject == "sub-a"
      assert Auth.UserSessions.list_for_user(user) == []
      assert Repo.reload!(user).password_hash == user.password_hash
    end

    test "deletes the account's API keys" do
      user = new_user(email: "jane@example.com")
      insert(:api_key, user: user)
      other = insert(:api_key, user: new_user())

      assert {:ok, _} = Users.resolve(claims("jane@example.com", "sub-a"))

      assert Repo.all(Auth.ApiKey) |> Enum.map(& &1.id) == [other.id]
    end

    test "closes the live connections of the revoked sessions" do
      user = new_user(email: "jane@example.com")
      session = Auth.UserSessions.create!(user, "Earlier device")
      PlausibleWeb.Endpoint.subscribe(Auth.UserSessions.socket_id(session.token))

      assert {:ok, _} = Users.resolve(claims("jane@example.com", "sub-a"))

      assert_receive %Phoenix.Socket.Broadcast{event: "disconnect"}
    end

    test "a refused link closes nothing" do
      user = new_user(email: "jane@example.com", email_verified: false)
      session = Auth.UserSessions.create!(user, "Earlier device")
      insert(:api_key, user: user)
      PlausibleWeb.Endpoint.subscribe(Auth.UserSessions.socket_id(session.token))

      assert {:error, :account_not_linkable} =
               Users.resolve(claims("jane@example.com", "sub-a"))

      refute_receive %Phoenix.Socket.Broadcast{event: "disconnect"}
      assert [_] = Auth.UserSessions.list_for_user(user)
      assert [_] = Repo.all(Auth.ApiKey)
    end

    test "removes the password when password login is disabled" do
      put_config(disable_password_login: true)
      user = new_user(email: "jane@example.com", password: "very-secret-and-very-long-123")
      assert user.password_hash

      assert {:ok, _} = Users.resolve(claims("jane@example.com", "sub-a"))

      refute Repo.reload!(user).password_hash
    end

    test "later logins of the bound identity leave sessions alone" do
      user = new_user(email: "jane@example.com")
      assert {:ok, _} = Users.resolve(claims("jane@example.com", "sub-a"))
      Auth.UserSessions.create!(user, "Device")

      assert {:ok, _} = Users.resolve(claims("jane@example.com", "sub-a"))
      assert [_] = Auth.UserSessions.list_for_user(user)
    end
  end

  describe "a completed email change" do
    defp patch_verification(enabled?) do
      selfhost = Application.get_env(:plausible, :selfhost)
      patch_env(:selfhost, Keyword.put(selfhost, :enable_email_verification, enabled?))
    end

    test "no longer blocks the first link once the new address is verified" do
      patch_verification(true)
      user = new_user(email: "old@example.com", password: "very-secret-and-very-long-123")

      {:ok, user} =
        user
        |> Auth.User.email_changeset(%{
          "email" => "new@example.com",
          "password" => "very-secret-and-very-long-123"
        })
        |> Repo.update()

      assert user.previous_email == "old@example.com"
      refute user.email_verified
      assert {:error, :account_not_linkable} = Users.resolve(claims("new@example.com", "sub-a"))

      {:ok, verification} = Auth.EmailVerification.issue_code(user)
      assert :ok = Auth.EmailVerification.verify_code(user, verification.code)

      user = Repo.reload!(user)
      assert user.email_verified
      refute user.previous_email
      assert {:ok, %{id: id}} = Users.resolve(claims("new@example.com", "sub-a"))
      assert id == user.id
    end

    test "that needs no verification keeps no previous address" do
      patch_verification(false)
      user = new_user(email: "old@example.com", password: "very-secret-and-very-long-123")

      {:ok, user} =
        user
        |> Auth.User.email_changeset(%{
          "email" => "new@example.com",
          "password" => "very-secret-and-very-long-123"
        })
        |> Repo.update()

      assert user.email == "new@example.com"
      assert user.email_verified
      refute user.previous_email
    end
  end
end
