defmodule PlausibleWeb.AdminAuthControllerTest do
  use PlausibleWeb.ConnCase
  import Phoenix.LiveViewTest
  alias Plausible.Release

  describe "GET /" do
    @describetag :ce_build_only
    test "disable registration", %{conn: conn} do
      insert(:user)
      patch_config(disable_registration: true)
      conn = get(conn, "/register")
      assert redirected_to(conn) == "/login"
    end

    for mode <- [true, :invite_only] do
      test "disable registration (#{mode}) + first launch: registration stays closed",
           %{conn: conn} do
        patch_config(disable_registration: unquote(mode))
        refute Plausible.Repo.exists?(Plausible.Auth.User)
        refute Release.should_be_first_launch?()

        register_conn = get(conn, "/register")
        assert redirected_to(register_conn) == "/login"

        assert {:error, {:redirect, %{to: "/login"}}} = live(conn, "/register")

        # no redirect loop between /login and /register
        assert html_response(get(conn, "/login"), 200) =~ "Enter your account credentials"

        refute get_resp_header(get(conn, "/"), "location") == ["/register"]
        refute get_resp_header(get(conn, "/sites"), "location") == ["/register"]
      end
    end

    test "registration enabled + first launch: upstream first-launch flow", %{conn: conn} do
      patch_config(disable_registration: false)
      assert Release.should_be_first_launch?()

      assert redirected_to(get(conn, "/sites")) == "/register"
      assert html_response(get(conn, "/register"), 200) =~ "Enter your details"
    end
  end

  def patch_config(config) do
    updated_config = Keyword.merge([disable_registration: false], config)
    patch_env(:selfhost, updated_config)
  end
end
