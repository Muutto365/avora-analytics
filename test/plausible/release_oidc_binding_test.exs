defmodule Plausible.ReleaseOIDCBindingTest do
  # Fork addition
  use Plausible.DataCase, async: true

  alias Plausible.Release.OIDCBinding

  @issuer "https://id.example.com"

  defp bind(user, issuer, subject) do
    user |> Ecto.Changeset.change(oidc_issuer: issuer, oidc_subject: subject) |> Repo.update!()
  end

  test "clear removes a binding and is idempotent" do
    user = new_user(email: "jane@example.com", password: "very-secret-and-very-long-123")
    bind(user, @issuer, "sub-a")

    assert {:ok, "Binding cleared."} =
             OIDCBinding.apply_action("clear", " Jane@Example.com ", "", "")

    user = Repo.reload!(user)
    refute user.oidc_issuer
    refute user.oidc_subject
    assert user.password_hash

    assert {:ok, "The account is not bound; nothing was changed."} =
             OIDCBinding.apply_action("clear", "jane@example.com", "", "")
  end

  test "rebind sets the identity and is idempotent" do
    user = new_user(email: "jane@example.com")
    bind(user, "https://old.example.com", "sub-old")

    assert {:ok, "Account bound to the identity."} =
             OIDCBinding.apply_action("rebind", "jane@example.com", @issuer, "sub-a")

    assert %{oidc_issuer: @issuer, oidc_subject: "sub-a"} = Repo.reload!(user)

    assert {:ok, "The account is already bound to this identity; nothing was changed."} =
             OIDCBinding.apply_action("rebind", "jane@example.com", @issuer, "sub-a")
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
