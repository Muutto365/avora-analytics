defmodule PlausibleWeb.Live.RegisterFormClosedTest do
  use PlausibleWeb.ConnCase, async: false

  import Ecto.Query, only: [from: 2]
  import Mox
  import Phoenix.LiveViewTest

  alias Plausible.Auth.User
  alias Plausible.Repo

  setup :verify_on_exit!

  @user_params %{
    "user" => %{
      "name" => "Mary Sue",
      "email" => "mary.sue@example.com",
      "password" => "very-long-and-very-secret-123",
      "password_confirmation" => "very-long-and-very-secret-123"
    }
  }

  setup do
    stub(Plausible.HTTPClient.Mock, :post, fn _, _, _ ->
      {:ok,
       %Finch.Response{
         status: 200,
         headers: [{"content-type", "application/json"}],
         body: %{"success" => true}
       }}
    end)

    inviter = new_user()
    site = new_site(owner: inviter)
    {:ok, site: site, inviter: inviter}
  end

  defp set_registration(mode) do
    config = Application.get_env(:plausible, :selfhost)
    patch_env(:selfhost, Keyword.put(config, :disable_registration, mode))
  end

  defp registered?, do: Repo.exists?(from(u in User, where: u.email == "mary.sue@example.com"))

  for mode <- [false, :invite_only] do
    test "register event on an unknown invitation id inserts nothing (#{mode})", %{conn: conn} do
      set_registration(unquote(mode))

      {:ok, lv, html} = live(conn, "/register/invitation/doesnotexist")
      assert html =~ "Your invitation has expired or been revoked"

      render_hook(lv, "register", @user_params)

      refute registered?()
    end
  end

  test "a valid invitation still registers with invite_only", %{
    conn: conn,
    site: site,
    inviter: inviter
  } do
    set_registration(:invite_only)
    invitation = invite_guest(site, "mary.sue@example.com", role: :editor, inviter: inviter)

    {:ok, lv, _html} = live(conn, "/register/invitation/#{invitation.invitation_id}")
    render_hook(lv, "register", @user_params)

    assert registered?()
  end

  for mode <- [true, :invite_only] do
    test "register event inserts nothing once registration is disabled (#{mode})", %{
      conn: conn
    } do
      set_registration(false)
      {:ok, lv, _html} = live(conn, "/register")

      set_registration(unquote(mode))
      render_hook(lv, "register", @user_params)

      refute registered?()
    end
  end

  test "register event still registers while registration is enabled", %{conn: conn} do
    set_registration(false)
    {:ok, lv, _html} = live(conn, "/register")

    render_hook(lv, "register", @user_params)

    assert registered?()
  end
end
