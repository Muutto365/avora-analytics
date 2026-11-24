defmodule PlausibleWeb.LocaleTest do
  use PlausibleWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  doctest PlausibleWeb.Locale

  # A user exists, so the first-launch redirect to registration does not apply.
  setup do
    insert(:user)
    :ok
  end

  describe "language choice" do
    test "defaults to English", %{conn: conn} do
      html = conn |> get("/login") |> html_response(200)

      assert html =~ ~s(<html lang="en")
      assert html =~ "Log in"
    end

    test "follows Accept-Language", %{conn: conn} do
      html =
        conn
        |> put_req_header("accept-language", "fi-FI,fi;q=0.9,en;q=0.8")
        |> get("/login")
        |> html_response(200)

      assert html =~ ~s(<html lang="fi")
      assert html =~ "Kirjaudu sisään"
      assert html =~ "Salasana"
    end

    test "the cookie wins over Accept-Language", %{conn: conn} do
      html =
        conn
        |> put_req_header("accept-language", "fi")
        |> put_req_cookie("locale", "en")
        |> get("/login")
        |> html_response(200)

      assert html =~ ~s(<html lang="en")
      assert html =~ "Password"
    end

    test "ignores unsupported cookie values", %{conn: conn} do
      html = conn |> put_req_cookie("locale", "xx") |> get("/login") |> html_response(200)
      assert html =~ ~s(<html lang="en")
    end
  end

  describe "POST /locale" do
    test "stores only the language in a cookie and returns to the page", %{conn: conn} do
      conn = post(conn, "/locale", %{"locale" => "fi", "return_to" => "/sites?page=2"})

      assert redirected_to(conn) == "/sites?page=2"
      assert %{value: "fi", http_only: true, same_site: "Lax"} = conn.resp_cookies["locale"]
    end

    test "never redirects off the site", %{conn: conn} do
      for target <- ["https://example.com", "//example.com", "/\\example.com", nil] do
        conn = post(recycle(conn), "/locale", %{"locale" => "en", "return_to" => target})
        assert redirected_to(conn) == "/", inspect(target)
      end
    end

    test "ignores unsupported languages", %{conn: conn} do
      conn = post(conn, "/locale", %{"locale" => "xx", "return_to" => "/login"})

      assert redirected_to(conn) == "/login"
      refute Map.has_key?(conn.resp_cookies, "locale")
    end
  end

  describe "LiveViews" do
    setup [:create_user, :log_in, :create_site]

    test "the sites list renders in Finnish", %{conn: conn} do
      conn = put_req_header(conn, "accept-language", "fi")
      {:ok, lv, _html} = live(conn, "/sites")

      html = render(lv)
      assert html =~ "Hae sivustoja"
      assert html =~ "Kirjautuneena" or html =~ "Lisää sivusto"
    end

    test "the installation screen renders in Finnish", %{conn: conn, site: site} do
      conn = put_req_header(conn, "accept-language", "fi")
      {:ok, lv, _html} = live(conn, "/#{site.domain}/installation")

      html = render(lv)
      assert html =~ "Avoran ylläpitämillä verkkotunnuksilla"
      assert html =~ "Tarkista asennus"
    end
  end
end
