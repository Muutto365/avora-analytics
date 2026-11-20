defmodule PlausibleWeb.OIDCControllerTest do
  # Fork addition: OIDC single sign-on against a local fake provider.
  use PlausibleWeb.ConnCase, async: false
  use Plausible.Repo

  import ExUnit.CaptureLog

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

      # the account is now bound to the provider's identity
      user = Repo.reload!(user)
      assert user.oidc_issuer == provider.issuer
      assert user.oidc_subject == "subject-1"
    end

    test "refuses to link an account whose email is not verified", %{
      conn: conn,
      provider: provider
    } do
      user = new_user(email_verified: false)

      conn = complete_login(conn, provider, %{"email" => user.email})

      assert_refused(conn, "cannot be linked")
      user = Repo.reload!(user)
      refute user.email_verified
      refute user.oidc_subject
    end

    test "refuses to link an account with a pending email change", %{
      conn: conn,
      provider: provider
    } do
      user = new_user(email: "new@example.com", previous_email: "old@example.com")

      conn = complete_login(conn, provider, %{"email" => "new@example.com"})

      assert_refused(conn, "cannot be linked")
      user = Repo.reload!(user)
      assert user.email == "new@example.com"
      refute user.oidc_subject
    end

    test "the first link ends sessions started before it", %{conn: conn, provider: provider} do
      user = new_user(email: "jane@example.com", password: "very-secret-and-very-long-123")

      earlier =
        fresh(build_conn())
        |> post("/login", email: user.email, password: "very-secret-and-very-long-123")

      assert earlier |> fresh() |> get("/sites") |> html_response(200)

      conn = complete_login(conn, provider, %{"email" => user.email})
      assert logged_in_user_id(conn) == user.id

      assert earlier |> fresh() |> get("/sites") |> redirected_to(302) =~ "/login"
      assert conn |> fresh() |> get("/sites") |> html_response(200)
    end

    test "refuses an account already bound to another identity", %{
      conn: conn,
      provider: provider
    } do
      user = new_user(email: "jane@example.com")
      complete_login(conn, provider, %{"email" => user.email}, sub: "subject-a")

      conn =
        complete_login(fresh(build_conn()), provider, %{"email" => user.email}, sub: "subject-b")

      assert_refused(conn, "cannot be linked")
      assert Repo.reload!(user).oidc_subject == "subject-a"
    end

    test "a bound identity is found by subject and follows the provider's email", %{
      conn: conn,
      provider: provider
    } do
      complete_login(conn, provider, %{"email" => "jane@example.com"}, sub: "subject-a")
      user = Repo.get_by!(Auth.User, email: "jane@example.com")

      conn =
        complete_login(fresh(build_conn()), provider, %{"email" => "jane.doe@example.com"},
          sub: "subject-a"
        )

      assert logged_in_user_id(conn) == user.id
      user = Repo.reload!(user)
      assert user.email == "jane.doe@example.com"
      assert user.email_verified
      assert Repo.aggregate(Auth.User, :count) == 1
    end

    test "a provider email change to an address another user has is refused", %{
      conn: conn,
      provider: provider
    } do
      complete_login(conn, provider, %{"email" => "jane@example.com"}, sub: "subject-a")
      user = Repo.get_by!(Auth.User, email: "jane@example.com")
      other = new_user(email: "taken@example.com")

      conn =
        complete_login(fresh(build_conn()), provider, %{"email" => "taken@example.com"},
          sub: "subject-a"
        )

      assert_refused(conn, "already used by another account")
      assert Repo.reload!(user).email == "jane@example.com"
      assert Repo.reload!(other).oidc_subject == nil
    end

    test "local email changes are refused while OIDC is enabled", %{
      conn: conn,
      provider: provider
    } do
      conn = complete_login(conn, provider, %{"email" => "jane@example.com"})
      user = Repo.get_by!(Auth.User, email: "jane@example.com")

      for path <- ["/settings/security/email", "/settings/security/email/cancel"] do
        refused =
          conn
          |> fresh()
          |> post(path, %{"user" => %{"email" => "other@example.com", "password" => "x"}})

        assert redirected_to(refused, 302) == "/settings/security#update-email"

        assert Phoenix.Flash.get(refused.assigns.flash, :error) =~
                 "managed by your identity provider"
      end

      user = Repo.reload!(user)
      assert user.email == "jane@example.com"
      refute user.previous_email

      # the next single sign-on still lands on the same, unchanged account
      conn = complete_login(fresh(build_conn()), provider, %{"email" => "jane@example.com"})
      assert logged_in_user_id(conn) == user.id
    end

    test "a passwordless account gets a form error on the password change form", %{
      conn: conn,
      provider: provider
    } do
      conn = complete_login(conn, provider, %{"email" => "jane@example.com"})

      conn =
        conn
        |> fresh()
        |> post("/settings/security/password", %{
          "user" => %{
            "old_password" => "anything-at-all-123",
            "password" => "super-long-super-secret-999",
            "password_confirmation" => "super-long-super-secret-999"
          }
        })

      assert html_response(conn, 200) =~ "is invalid"
    end

    test "the session has a fixed lifetime that use does not extend", %{
      conn: conn,
      provider: provider
    } do
      conn = complete_login(conn, provider)
      {:ok, session} = Auth.UserSessions.get_by_token(get_session(conn, "user_token"))

      assert session.fixed_timeout
      expected = NaiveDateTime.add(NaiveDateTime.utc_now(:second), 12 * 3600, :second)
      assert abs(NaiveDateTime.diff(session.timeout_at, expected)) <= 5

      later = NaiveDateTime.add(NaiveDateTime.utc_now(:second), 6 * 3600, :second)
      touched = Auth.UserSessions.touch(session, later)
      assert touched.timeout_at == session.timeout_at
      assert touched.last_used_at == later

      # once it has passed, the session no longer logs anyone in
      session
      |> Ecto.Changeset.change(timeout_at: NaiveDateTime.add(NaiveDateTime.utc_now(:second), -1))
      |> Repo.update!()

      assert conn |> fresh() |> get("/sites") |> redirected_to(302) =~ "/login"
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

    test "an account with its own 2FA still goes through its TOTP step", %{
      conn: conn,
      provider: provider
    } do
      user = new_user()
      {:ok, user, _} = Auth.TOTP.initiate(user)
      {:ok, user, _} = Auth.TOTP.enable(user, :skip_verify)

      conn = complete_login(conn, provider, %{"email" => user.email}, return_to: "/settings")

      assert redirected_to(conn, 302) == "/2fa/verify?return_to=%2Fsettings"
      refute logged_in_user_id(conn)

      conn =
        conn
        |> fresh()
        |> post("/2fa/verify", %{
          "code" => NimbleTOTP.verification_code(user.totp_secret),
          "return_to" => "/settings"
        })

      assert redirected_to(conn, 302) == "/settings"
      assert logged_in_user_id(conn) == user.id
      assert get_session(conn, "login_method") == "oidc"
      {:ok, session} = Auth.UserSessions.get_by_token(get_session(conn, "user_token"))
      assert session.fixed_timeout
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
      log =
        capture_log(fn ->
          send(self(), {:conn, complete_login(conn, provider, %{"aud" => "some-other-client"})})
        end)

      assert_received {:conn, conn}
      assert_refused(conn)
      assert log =~ "validation failed: missing_claim(aud)"
    end

    test "refuses a token from another issuer", %{conn: conn, provider: provider} do
      log =
        capture_log(fn ->
          send(
            self(),
            {:conn, complete_login(conn, provider, %{"iss" => "http://localhost:1/other"})}
          )
        end)

      assert_received {:conn, conn}
      assert_refused(conn)
      assert log =~ "validation failed: missing_claim(iss)"
    end

    test "refuses an expired token", %{conn: conn, provider: provider} do
      log =
        capture_log(fn ->
          send(
            self(),
            {:conn, complete_login(conn, provider, %{"exp" => System.system_time(:second) - 60})}
          )
        end)

      assert_received {:conn, conn}
      assert_refused(conn)
      assert log =~ "validation failed: token_expired"
    end

    test "refuses a wrong nonce", %{conn: conn, provider: provider} do
      log =
        capture_log(fn ->
          send(self(), {:conn, complete_login(conn, provider, %{"nonce" => "not-the-nonce"})})
        end)

      assert_received {:conn, conn}
      assert_refused(conn)
      assert log =~ "validation failed: missing_claim(nonce)"
    end

    test "refuses a token without a nonce", %{conn: conn, provider: provider} do
      log =
        capture_log(fn ->
          send(self(), {:conn, complete_login(conn, provider, %{"nonce" => nil})})
        end)

      assert_received {:conn, conn}
      assert_refused(conn)
      assert log =~ "validation failed: missing_claim(nonce)"
    end

    test "refuses a token signed by another key", %{conn: conn, provider: provider} do
      log =
        capture_log(fn ->
          send(
            self(),
            {:conn, complete_login(conn, provider, %{}, jwk: JOSE.JWK.generate_key({:rsa, 2048}))}
          )
        end)

      assert_received {:conn, conn}
      assert_refused(conn)
      assert log =~ "validation failed: no_matching_key"
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
      {login_conn, params} = start_login(conn)
      secret_key_base = PlausibleWeb.Endpoint.config(:secret_key_base)

      # the real flow data of this login, sealed again with an older time
      {:ok, flow} =
        Plug.Crypto.decrypt(
          secret_key_base,
          "oidc login flow",
          get_session(login_conn, "oidc_flow")
        )

      reseal = fn signed_at ->
        Plug.Crypto.encrypt(secret_key_base, "oidc login flow", flow, signed_at: signed_at)
      end

      callback = fn sealed ->
        code = Provider.grant(provider, params)

        fresh(build_conn())
        |> init_test_session(%{"oidc_flow" => sealed})
        |> get("/auth/oidc/callback", %{"code" => code, "state" => params["state"]})
      end

      expired = callback.(reseal.(System.system_time(:second) - 601))
      assert_refused(expired, "took too long")

      # the same data within its lifetime works, so only the age was refused
      assert logged_in_user_id(callback.(reseal.(System.system_time(:second) - 60)))
    end

    test "refuses a token without a signature (alg none)", %{conn: conn, provider: provider} do
      log =
        capture_log(fn ->
          send(self(), {:conn, complete_login(conn, provider, %{}, unsigned: true)})
        end)

      assert_received {:conn, conn}
      assert_refused(conn)
      assert log =~ "validation failed: no_matching_key"
    end

    test "refuses a token for several audiences issued to another party (azp)", %{
      conn: conn,
      provider: provider
    } do
      log =
        capture_log(fn ->
          conn =
            complete_login(conn, provider, %{
              "aud" => [Provider.client_id(), "another-client"],
              "azp" => "another-client"
            })

          send(self(), {:conn, conn})
        end)

      assert_received {:conn, conn}
      assert_refused(conn)
      assert log =~ "validation failed: missing_claim(azp)"
    end

    test "accepts several audiences when azp names this client", %{
      conn: conn,
      provider: provider
    } do
      conn =
        complete_login(conn, provider, %{
          "aud" => [Provider.client_id(), "another-client"],
          "azp" => Provider.client_id()
        })

      assert logged_in_user_id(conn)
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

  describe "with pushed authorization requests" do
    setup %{tmp_dir: tmp_dir} do
      provider =
        Provider.start!(tmp_dir, [], fn issuer ->
          %{"pushed_authorization_request_endpoint" => issuer <> "/par"}
        end)

      {:ok, provider: provider}
    end

    test "pushes the request, with S256 PKCE, and logs in", %{conn: conn, provider: provider} do
      conn = get(conn, "/auth/oidc/login")

      url_params =
        conn |> redirected_to(302) |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

      assert Map.keys(url_params) |> Enum.sort() == ["client_id", "request_uri"]

      params = Provider.authorization_params(provider, url_params)
      assert params["code_challenge_method"] == "S256"

      code = Provider.grant(provider, params)

      conn =
        conn
        |> fresh()
        |> get("/auth/oidc/callback", %{"code" => code, "state" => params["state"]})

      assert redirected_to(conn, 302) == "/sites"
      assert logged_in_user_id(conn)
    end
  end

  describe "with an internal provider address" do
    setup %{tmp_dir: tmp_dir} do
      provider =
        Provider.start!(tmp_dir, [internal_address: true], fn issuer ->
          %{"pushed_authorization_request_endpoint" => issuer <> "/par"}
        end)

      {:ok, provider: provider}
    end

    test "the browser uses the public issuer, the server the internal address", %{
      conn: conn,
      provider: provider
    } do
      conn = get(conn, "/auth/oidc/login")
      location = redirected_to(conn, 302)
      assert String.starts_with?(location, "https://id.invalid/tenant/authorize?")

      url_params = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
      params = Provider.authorization_params(provider, url_params)
      code = Provider.grant(provider, params)

      conn =
        conn
        |> fresh()
        |> get("/auth/oidc/callback", %{"code" => code, "state" => params["state"]})

      assert redirected_to(conn, 302) == "/sites"
      assert logged_in_user_id(conn)
    end
  end

  describe "with the provider unreachable" do
    setup %{tmp_dir: tmp_dir} do
      Provider.start!(tmp_dir, down: true)
      :ok
    end

    test "the login page works and SSO reports the outage", %{conn: conn} do
      assert conn |> get("/login") |> html_response(200) =~ "Sign in with SSO"

      conn = conn |> fresh() |> get("/auth/oidc/login")

      assert redirected_to(conn, 302) == "/login"
      assert Phoenix.Flash.get(conn.assigns.flash, :login_error) =~ "temporarily unavailable"
    end

    test "a callback reports the outage", %{conn: conn} do
      sealed =
        Plug.Crypto.encrypt(
          PlausibleWeb.Endpoint.config(:secret_key_base),
          "oidc login flow",
          %{state: "s", nonce: "n", verifier: "v", return_to: nil}
        )

      conn =
        conn
        |> init_test_session(%{"oidc_flow" => sealed})
        |> get("/auth/oidc/callback", %{"code" => "c", "state" => "s"})

      assert redirected_to(conn, 302) == "/login"
      assert Phoenix.Flash.get(conn.assigns.flash, :login_error) =~ "temporarily unavailable"
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

    test "registration is disabled, whatever DISABLE_REGISTRATION says", %{conn: conn} do
      assert Keyword.fetch!(Application.get_env(:plausible, :selfhost), :disable_registration) ==
               false

      conn = get(conn, "/register")
      assert redirected_to(conn, 302) == "/login"

      inviter = new_user()
      site = new_site(owner: inviter)
      invitation = invite_guest(site, "invitee@example.com", role: :viewer, inviter: inviter)

      conn = get(fresh(build_conn()), "/register/invitation/#{invitation.invitation_id}")
      assert redirected_to(conn, 302) == "/login"
    end

    test "an account with its own 2FA can complete its TOTP step after SSO", %{
      conn: conn,
      provider: provider
    } do
      user = new_user()
      {:ok, user, _} = Auth.TOTP.initiate(user)
      {:ok, user, _} = Auth.TOTP.enable(user, :skip_verify)

      conn = complete_login(conn, provider, %{"email" => user.email})
      assert redirected_to(conn, 302) == "/2fa/verify"

      assert conn |> fresh() |> get("/2fa/verify") |> html_response(200)

      conn =
        conn
        |> fresh()
        |> post("/2fa/verify", %{"code" => NimbleTOTP.verification_code(user.totp_secret)})

      assert redirected_to(conn, 302) == "/sites"
      assert logged_in_user_id(conn) == user.id
    end

    test "a password user's 2FA step stays refused", %{conn: conn} do
      user = new_user()
      {:ok, user, _} = Auth.TOTP.initiate(user)
      {:ok, user, _} = Auth.TOTP.enable(user, :skip_verify)

      conn =
        conn
        |> PlausibleWeb.TwoFactor.Session.set_2fa_user(user)
        |> fresh()
        |> post("/2fa/verify", %{"code" => NimbleTOTP.verification_code(user.totp_secret)})

      assert redirected_to(conn, 302) == "/login"
      refute logged_in_user_id(conn)
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
