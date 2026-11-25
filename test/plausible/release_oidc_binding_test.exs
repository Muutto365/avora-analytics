defmodule Plausible.ReleaseOIDCBindingTest do
  # Fork addition
  use Plausible.DataCase, async: false

  alias Plausible.Auth
  alias Plausible.Release.OIDCBinding

  @issuer "https://id.example.com"

  setup do
    patch_env(Plausible.Auth.OIDC,
      enabled: true,
      issuer: @issuer,
      role_map: %{"staff" => :viewer}
    )
  end

  defp session_with_subscription(user) do
    session = Auth.UserSessions.create!(user, "Device")
    PlausibleWeb.Endpoint.subscribe(Auth.UserSessions.socket_id(session.token))
    session
  end

  defp bind(user, issuer, subject) do
    user |> Ecto.Changeset.change(oidc_issuer: issuer, oidc_subject: subject) |> Repo.update!()
  end

  test "clear removes a binding and is idempotent" do
    user = new_user(email: "jane@example.com", password: "very-secret-and-very-long-123")
    bind(user, @issuer, "sub-a")
    session_with_subscription(user)

    assert {:ok, "Binding cleared."} =
             OIDCBinding.apply_action("clear", " Jane@Example.com ", "", "")

    assert_receive %Phoenix.Socket.Broadcast{event: "disconnect"}
    assert Auth.UserSessions.list_for_user(user) == []

    user = Repo.reload!(user)
    refute user.oidc_issuer
    refute user.oidc_subject
    assert user.password_hash

    session_with_subscription(user)

    assert {:ok, "The account is not bound; nothing was changed."} =
             OIDCBinding.apply_action("clear", "jane@example.com", "", "")

    refute_receive %Phoenix.Socket.Broadcast{event: "disconnect"}
    assert [_] = Auth.UserSessions.list_for_user(user)
  end

  test "rebind sets the identity and is idempotent" do
    user = new_user(email: "jane@example.com")
    bind(user, "https://old.example.com", "sub-old")
    insert(:api_key, user: user)
    session_with_subscription(user)

    assert {:ok, "Account bound to the identity."} =
             OIDCBinding.apply_action("rebind", "jane@example.com", @issuer, "sub-a")

    assert %{oidc_issuer: @issuer, oidc_subject: "sub-a"} = Repo.reload!(user)
    assert_receive %Phoenix.Socket.Broadcast{event: "disconnect"}
    assert Auth.UserSessions.list_for_user(user) == []
    assert [_] = Repo.all(Auth.ApiKey)

    assert {:ok, "The account is already bound to this identity; nothing was changed."} =
             OIDCBinding.apply_action("rebind", "jane@example.com", @issuer, "sub-a")
  end

  test "rebind refuses an issuer other than the configured one" do
    user = new_user(email: "jane@example.com")
    session_with_subscription(user)

    assert {:error, "OIDC_BINDING_ISSUER must be the configured OIDC_ISSUER" <> _} =
             OIDCBinding.apply_action(
               "rebind",
               "jane@example.com",
               "https://other.example.com",
               "s"
             )

    refute Repo.reload!(user).oidc_subject
    assert [_] = Auth.UserSessions.list_for_user(user)

    patch_env(Plausible.Auth.OIDC, enabled: false, disable_password_login: false)

    assert {:error, "OIDC_BINDING_ISSUER must be the configured OIDC_ISSUER (not set)" <> _} =
             OIDCBinding.apply_action("rebind", "jane@example.com", @issuer, "s")
  end

  test "rebind refuses an identity bound to another account" do
    other = new_user(email: "other@example.com")
    bind(other, @issuer, "sub-a")
    user = new_user(email: "jane@example.com")

    assert {:error, "Another account is bound to this identity; nothing was changed."} =
             OIDCBinding.apply_action("rebind", "jane@example.com", @issuer, "sub-a")

    refute Repo.reload!(user).oidc_subject
    assert Repo.reload!(other).oidc_subject == "sub-a"
  end

  test "invalid input changes nothing" do
    user = new_user(email: "jane@example.com")

    assert {:error, "OIDC_BINDING_EMAIL is not set"} =
             OIDCBinding.apply_action("clear", "", "", "")

    assert {:error, "No account with this email."} =
             OIDCBinding.apply_action("clear", "nobody@example.com", "", "")

    assert {:error, "OIDC_BINDING_ACTION must be clear or rebind"} =
             OIDCBinding.apply_action("delete", "jane@example.com", "", "")

    assert {:error, "OIDC_BINDING_ISSUER and OIDC_BINDING_SUBJECT are required for rebind"} =
             OIDCBinding.apply_action("rebind", "jane@example.com", @issuer, " ")

    refute Repo.reload!(user).oidc_subject
  end
end
