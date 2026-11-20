defmodule PlausibleWeb.OIDCControllerTest do
  # Fork addition: OIDC single sign-on against a local fake provider.
  use PlausibleWeb.ConnCase, async: false
  use Plausible.Repo

  alias Plausible.Auth
  alias Plausible.Test.OIDCFakeProvider, as: Provider

  @moduletag :tmp_dir

  setup {PlausibleWeb.FirstLaunchPlug.Test, :skip}

  describe "with OIDC configured" do
    setup %{tmp_dir: tmp_dir} do
      {:ok, provider: Provider.start!(tmp_dir)}
    end

    test "login redirects to the provider with state, nonce and S256 PKCE", %{conn: conn} do
      {_conn, params} = start_login(conn)

      assert params["response_type"] == "code"
      assert params["client_id"] == Provider.client_id()
      assert params["redirect_uri"] == PlausibleWeb.Endpoint.url() <> "/auth/oidc/callback"
      assert params["code_challenge_method"] == "S256"
      assert byte_size(params["state"]) >= 32
      assert byte_size(params["nonce"]) >= 32
      assert params["scope"] |> String.split() |> Enum.sort() == ["email", "openid", "profile"]
    end

    test "logs in an existing user, matching email case-insensitively", %{
      conn: conn,
      provider: provider
    } do
      user = new_user(email: "Jane.Doe@Example.com")

      conn = complete_login(conn, provider, %{"email" => "jane.doe@example.COM"})

      assert redirected_to(conn, 302) == "/sites"
      assert logged_in_user_id(conn) == user.id
      assert Repo.aggregate(Auth.User, :count) == 1
    end

    test "marks an unverified local email as verified", %{conn: conn, provider: provider} do
      user = new_user(email_verified: false)

      conn = complete_login(conn, provider, %{"email" => user.email})

      assert logged_in_user_id(conn) == user.id
      assert Repo.reload!(user).email_verified
    end

    test "creates a user just in time, without a usable password", %{
      conn: conn,
      provider: provider
    } do
      conn =
        complete_login(conn, provider, %{
          "email" => "new.person@example.com",
          "name" => nil,
          "given_name" => "New",
          "family_name" => "Person"
        })

      user = Repo.get_by!(Auth.User, email: "new.person@example.com")
      assert user.name == "New Person"
      assert user.email_verified
      assert is_nil(user.password_hash)
      assert logged_in_user_id(conn) == user.id

      # the password login for such a user fails normally
      conn =
        post(fresh(build_conn()), "/login", email: user.email, password: "anything-at-all-123")

      assert html_response(conn, 200) =~ "Wrong email or password"
    end

    test "follows a same-origin return_to", %{conn: conn, provider: provider} do
      conn = complete_login(conn, provider, %{}, return_to: "/example.com/settings")
      assert redirected_to(conn, 302) == "/example.com/settings"
    end

    for bad <- [
          "//evil.example/x",
          "https://evil.example/",
          "/\\evil.example",
          "javascript:alert(1)"
        ] do
      test "ignores an unsafe return_to #{inspect(bad)}", %{conn: conn, provider: provider} do
        conn = complete_login(conn, provider, %{}, return_to: unquote(bad))
        assert redirected_to(conn, 302) == "/sites"
      end
    end

    test "does not ask for TOTP when the user has it enabled", %{conn: conn, provider: provider} do
      user = new_user()
      {:ok, user, _} = Auth.TOTP.initiate(user)
      {:ok, user, _} = Auth.TOTP.enable(user, :skip_verify)

      conn = complete_login(conn, provider, %{"email" => user.email})

      assert redirected_to(conn, 302) == "/sites"
      assert logged_in_user_id(conn) == user.id
    end

    test "an OIDC session is not forced into team 2FA setup; a password session is", %{
      conn: conn,
      provider: provider
    } do
      user = new_user(password: "very-secret-and-very-long-123")
      team = new_site(owner: user).team |> Plausible.Teams.complete_setup()
      {:ok, _team} = Plausible.Teams.enable_force_2fa(team, user)

      oidc_conn = complete_login(conn, provider, %{"email" => user.email})
      assert get_session(oidc_conn, "login_method") == "oidc"
      oidc_conn = oidc_conn |> fresh() |> get("/sites", %{"__team" => team.identifier})
      assert html_response(oidc_conn, 200)

      password_conn =
        fresh(build_conn())
        |> post("/login", email: user.email, password: "very-secret-and-very-long-123")

      refute get_session(password_conn, "login_method")
      password_conn = password_conn |> fresh() |> get("/sites", %{"__team" => team.identifier})
      assert redirected_to(password_conn, 302) == "/2fa/setup/force-initiate"
    end

    test "refuses email_verified false", %{conn: conn, provider: provider} do
      conn = complete_login(conn, provider, %{"email_verified" => false})
      assert_refused(conn, "has not verified your email")
    end

    test "refuses a missing email_verified claim", %{conn: conn, provider: provider} do
      conn = complete_login(conn, provider, %{"email_verified" => nil})
      assert_refused(conn, "has not verified your email")
    end

    test "refuses a missing email", %{conn: conn, provider: provider} do
      conn = complete_login(conn, provider, %{"email" => nil})
      assert_refused(conn, "did not share an email")
    end

    test "refuses a token for another audience", %{conn: conn, provider: provider} do
      conn = complete_login(conn, provider, %{"aud" => "some-other-client"})
      assert_refused(conn)
    end

    test "refuses a token from another issuer", %{conn: conn, provider: provider} do
      conn = complete_login(conn, provider, %{"iss" => "http://localhost:1/other"})
      assert_refused(conn)
    end

    test "refuses an expired token", %{conn: conn, provider: provider} do
      conn = complete_login(conn, provider, %{"exp" => System.system_time(:second) - 60})
      assert_refused(conn)
    end

    test "refuses a wrong nonce", %{conn: conn, provider: provider} do
      conn = complete_login(conn, provider, %{"nonce" => "not-the-nonce"})
      assert_refused(conn)
    end

    test "refuses a token without a nonce", %{conn: conn, provider: provider} do
      conn = complete_login(conn, provider, %{"nonce" => nil})
      assert_refused(conn)
    end

    test "refuses a token signed by another key", %{conn: conn, provider: provider} do
      conn =
        complete_login(conn, provider, %{}, jwk: JOSE.JWK.generate_key({:rsa, 2048}))

      assert_refused(conn)
    end

    test "refuses a wrong state", %{conn: conn, provider: provider} do
      {conn, params} = start_login(conn)
      code = Provider.grant(provider, params)

      conn = conn |> fresh() |> get("/auth/oidc/callback", %{"code" => code, "state" => "x"})

      assert_refused(conn)
    end

    test "refuses a callback without a login started in this browser", %{
      conn: conn,
      provider: provider
    } do
      {_conn, params} = start_login(conn)
      code = Provider.grant(provider, params)

      conn =
        get(fresh(build_conn()), "/auth/oidc/callback", %{
          "code" => code,
          "state" => params["state"]
        })

      assert_refused(conn)
    end

    test "the login flow is single use", %{conn: conn, provider: provider} do
      {conn, params} = start_login(conn)
      code = Provider.grant(provider, params)
      conn = fresh(conn)
      callback = %{"code" => code, "state" => params["state"]}

      first = get(conn, "/auth/oidc/callback", callback)
      assert logged_in_user_id(first)
      refute get_session(first, "oidc_flow")

      # the same session continues without the flow data
      again = first |> fresh() |> get("/auth/oidc/callback", callback)
      assert redirected_to(again, 302) == "/login"
      assert Phoenix.Flash.get(again.assigns.flash, :login_error) =~ "Single sign-on failed"

      # replaying the earlier cookie fails too: the code was used up
      replay = get(conn, "/auth/oidc/callback", callback)
      assert redirected_to(replay, 302) == "/login"
      refute get_session(replay, "user_token")
    end

    test "refuses an expired login flow", %{conn: conn, provider: provider} do
      {_conn, params} = start_login(conn)
      code = Provider.grant(provider, params)

      sealed =
        Plug.Crypto.encrypt(
          PlausibleWeb.Endpoint.config(:secret_key_base),
          "oidc login flow",
          %{state: params["state"], nonce: params["nonce"], verifier: "v", return_to: nil},
          signed_at: System.system_time(:second) - 601
        )

      conn =
        conn
        |> init_test_session(%{"oidc_flow" => sealed})
        |> get("/auth/oidc/callback", %{"code" => code, "state" => params["state"]})

      assert_refused(conn)
    end

    test "refuses when the PKCE verifier does not match", %{conn: conn, provider: provider} do
      {conn, params} = start_login(conn)
      code = Provider.grant(provider, Map.put(params, "code_challenge", "not-the-challenge"))

      conn =
        conn
        |> fresh()
        |> get("/auth/oidc/callback", %{"code" => code, "state" => params["state"]})

      assert_refused(conn)
    end

    test "reports a provider error", %{conn: conn} do
      {conn, params} = start_login(conn)

      conn =
        conn
        |> fresh()
        |> get("/auth/oidc/callback", %{"error" => "access_denied", "state" => params["state"]})

      assert_refused(conn, "Sign-in was cancelled")
    end

    test "shows the SSO button next to the password form", %{conn: conn} do
      html = conn |> get("/login") |> html_response(200)

      assert html =~ "Sign in with SSO"
      assert html =~ "/auth/oidc/login"
      assert html =~ ~s(type="password")
      assert html =~ "Forgot password?"
    end
  end

  describe "with allowed groups" do
    setup %{tmp_dir: tmp_dir} do
      provider =
        Provider.start!(tmp_dir,
          OIDC_ALLOWED_GROUPS: "/staff/analytics, admins",
          OIDC_GROUPS_CLAIM: "roles"
        )

      {:ok, provider: provider}
    end

    test "accepts a member of an allowed group (full path, verbatim)", %{
      conn: conn,
      provider: provider
    } do
      conn = complete_login(conn, provider, %{"roles" => ["/other", "/staff/analytics"]})
      assert logged_in_user_id(conn)
    end

    test "accepts a single group given as a string", %{conn: conn, provider: provider} do
      conn = complete_login(conn, provider, %{"roles" => "admins"})
      assert logged_in_user_id(conn)
    end

    test "refuses a user outside the allowed groups and creates nobody", %{
      conn: conn,
      provider: provider
    } do
      conn =
        complete_login(conn, provider, %{
          "email" => "outsider@example.com",
          "roles" => ["/staff", "/staff/analytics/sub", "Admins"]
        })

      assert_refused(conn, "not allowed to sign in")
      refute Repo.get_by(Auth.User, email: "outsider@example.com")
    end

    test "refuses a user without the groups claim", %{conn: conn, provider: provider} do
      conn = complete_login(conn, provider, %{"groups" => ["admins"]})
      assert_refused(conn, "not allowed to sign in")
    end
  end

  describe "with a provider that does not support S256" do
    setup %{tmp_dir: tmp_dir} do
      Provider.start!(tmp_dir, [], %{"code_challenge_methods_supported" => ["plain"]})
      :ok
    end

    test "refuses to start a login", %{conn: conn} do
      conn = get(conn, "/auth/oidc/login")

      assert redirected_to(conn, 302) == "/login"
      assert Phoenix.Flash.get(conn.assigns.flash, :login_error) =~ "Single sign-on failed"
    end
  end

  describe "with password login disabled" do
    setup %{tmp_dir: tmp_dir} do
      provider =
        Provider.start!(tmp_dir,
          OIDC_DISABLE_PASSWORD_LOGIN: "true",
          OIDC_BUTTON_LABEL: "Continue with company account"
        )

      {:ok, provider: provider}
    end

    test "the login page shows only the SSO button", %{conn: conn} do
      html = conn |> get("/login") |> html_response(200)

      assert html =~ "Continue with company account"
      refute html =~ ~s(type="password")
      refute html =~ "Forgot password?"
    end

    test "refuses the password login", %{conn: conn} do
      user = new_user(password: "very-secret-and-very-long-123")

      conn = post(conn, "/login", email: user.email, password: "very-secret-and-very-long-123")

      assert redirected_to(conn, 302) == "/login"
      refute get_session(conn, "user_token")
      assert Phoenix.Flash.get(conn.assigns.flash, :login_error) =~ "Password login is disabled"
    end

    test "refuses the password reset and password 2FA steps", %{conn: conn} do
      for {method, path} <- [
            {:get, "/password/request-reset"},
            {:post, "/password/request-reset"},
            {:get, "/password/reset"},
            {:post, "/password/reset"},
            {:get, "/2fa/verify"},
            {:post, "/2fa/verify"},
            {:get, "/2fa/use_recovery_code"},
            {:post, "/2fa/use_recovery_code"}
          ] do
        conn = dispatch(conn, @endpoint, method, path, %{})
        assert redirected_to(conn, 302) == "/login", "#{method} #{path}"
      end
    end

    test "SSO login still works", %{conn: conn, provider: provider} do
      conn = complete_login(conn, provider)
      assert logged_in_user_id(conn)
    end
  end

  describe "without OIDC configured" do
    test "the endpoints do not exist", %{conn: conn} do
      refute Plausible.Auth.OIDC.enabled?()

      assert conn |> get("/auth/oidc/login") |> html_response(404)

      assert fresh(build_conn())
             |> get("/auth/oidc/callback", %{"code" => "x"})
             |> html_response(404)
    end

    test "the login page is unchanged", %{conn: conn} do
      html = conn |> get("/login") |> html_response(200)

      refute html =~ "/auth/oidc/login"
      assert html =~ ~s(type="password")
      assert html =~ "Forgot password?"
    end

    test "password login works", %{conn: conn} do
      user = new_user(password: "very-secret-and-very-long-123")
      conn = post(conn, "/login", email: user.email, password: "very-secret-and-very-long-123")
      assert redirected_to(conn, 302) == "/sites"
    end
  end

  # recycle/1 drops conn.private, so the first-launch skip is re-applied
  defp fresh(conn) do
    conn
    |> recycle()
    |> Plug.Conn.put_private(PlausibleWeb.FirstLaunchPlug, :skip)
  end

  defp start_login(conn, opts \\ []) do
    query = if rt = opts[:return_to], do: %{"return_to" => rt}, else: %{}
    conn = get(conn, "/auth/oidc/login", query)
    location = redirected_to(conn, 302)
    assert String.starts_with?(location, Plausible.Auth.OIDC.config()[:issuer] <> "/authorize?")
    {conn, location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()}
  end

  defp complete_login(conn, provider, claims \\ %{}, opts \\ []) do
    {conn, params} = start_login(conn, opts)
    code = Provider.grant(provider, params, claims, opts)

    conn
    |> fresh()
    |> get("/auth/oidc/callback", %{"code" => code, "state" => params["state"]})
  end

  defp logged_in_user_id(conn) do
    with token when is_binary(token) <- get_session(conn, "user_token"),
         {:ok, session} <- Auth.UserSessions.get_by_token(token) do
      session.user_id
    else
      _ -> nil
    end
  end

  defp assert_refused(conn, message \\ nil) do
    assert redirected_to(conn, 302) == "/login"
    refute logged_in_user_id(conn)

    if message do
      assert Phoenix.Flash.get(conn.assigns.flash, :login_error) =~ message
    end
  end
end
