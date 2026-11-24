defmodule Plausible.Auth.OIDC.ConfigTest do
  # Fork addition
  use ExUnit.Case, async: true

  alias Plausible.Auth.OIDC.Config

  @moduletag :tmp_dir

  defp parse!(env), do: Config.parse!(&env[&1])

  defp secret_file(tmp_dir, contents \\ "s3cret\n") do
    path = Path.join(tmp_dir, "secret")
    File.write!(path, contents)
    path
  end

  test "off when nothing is set" do
    assert parse!(%{}) == [enabled: false, disable_password_login: false]
    assert parse!(%{"OIDC_ISSUER" => "  "})[:enabled] == false
  end

  test "full configuration", %{tmp_dir: tmp_dir} do
    config =
      parse!(%{
        "OIDC_ISSUER" => "https://id.example.com/tenant",
        "OIDC_CLIENT_ID" => "analytics",
        "OIDC_CLIENT_SECRET_FILE" => secret_file(tmp_dir),
        "OIDC_ROLE_MAP" => "analytics-admin=admin, analytics-viewer = Viewer ,,",
        "OIDC_DISABLE_PASSWORD_LOGIN" => "true",
        "OIDC_INTERNAL_ISSUER_URL" => "http://id.internal:8080/tenant",
        "OIDC_INTERNAL_ISSUER_ALLOW_HTTP" => "true",
        "OIDC_SESSION_HOURS" => "8"
      })

    assert config[:enabled]
    assert config[:issuer] == "https://id.example.com/tenant"
    assert config[:client_secret] == "s3cret"
    assert config[:role_map] == %{"analytics-admin" => :admin, "analytics-viewer" => :viewer}
    assert config[:button_label] == "Sign in with SSO"
    assert config[:disable_password_login]
    assert config[:internal_issuer_url] == "http://id.internal:8080/tenant"
    assert config[:session_hours] == 8
  end

  defp base(tmp_dir) do
    %{
      "OIDC_ISSUER" => "https://id.example.com",
      "OIDC_CLIENT_ID" => "analytics",
      "OIDC_CLIENT_SECRET_FILE" => secret_file(tmp_dir),
      "OIDC_ROLE_MAP" => "staff=viewer"
    }
  end

  test "the role map must be set and well formed; there is no \"anyone\"", %{tmp_dir: tmp_dir} do
    assert_raise ArgumentError, ~r/OIDC_ROLE_MAP is required/, fn ->
      parse!(Map.delete(base(tmp_dir), "OIDC_ROLE_MAP"))
    end

    assert_raise ArgumentError, ~r/OIDC_ROLE_MAP is required/, fn ->
      parse!(Map.put(base(tmp_dir), "OIDC_ROLE_MAP", "  "))
    end

    assert_raise ArgumentError, ~r/maps no roles/, fn ->
      parse!(Map.put(base(tmp_dir), "OIDC_ROLE_MAP", " , ,"))
    end

    for bad <- ["*", "staff", "staff=owner", "staff=billing", "staff=", "=viewer", "a b=viewer"] do
      assert_raise ArgumentError, ~r/must be <client role>=<role>/, fn ->
        parse!(Map.put(base(tmp_dir), "OIDC_ROLE_MAP", bad))
      end
    end

    assert_raise ArgumentError, ~r/more than once/, fn ->
      parse!(Map.put(base(tmp_dir), "OIDC_ROLE_MAP", "staff=viewer,staff=admin"))
    end
  end

  test "the group settings it replaced stop the start", %{tmp_dir: tmp_dir} do
    for name <- ["OIDC_ALLOWED_GROUPS", "OIDC_GROUPS_CLAIM"] do
      assert_raise ArgumentError, ~r/#{name} is no longer supported/, fn ->
        parse!(Map.put(base(tmp_dir), name, "/staff"))
      end
    end
  end

  test "session hours default to 12 and are bounded", %{tmp_dir: tmp_dir} do
    assert parse!(base(tmp_dir))[:session_hours] == 12
    assert parse!(Map.put(base(tmp_dir), "OIDC_SESSION_HOURS", "1"))[:session_hours] == 1
    assert parse!(Map.put(base(tmp_dir), "OIDC_SESSION_HOURS", "72"))[:session_hours] == 72

    for bad <- ["0", "73", "-1", "1.5", "twelve"] do
      assert_raise ArgumentError, ~r/OIDC_SESSION_HOURS/, fn ->
        parse!(Map.put(base(tmp_dir), "OIDC_SESSION_HOURS", bad))
      end
    end
  end

  test "an internal address must use https unless loopback or explicitly allowed", %{
    tmp_dir: tmp_dir
  } do
    with_internal = &Map.put(base(tmp_dir), "OIDC_INTERNAL_ISSUER_URL", &1)

    assert_raise ArgumentError, ~r/OIDC_INTERNAL_ISSUER_ALLOW_HTTP=true/, fn ->
      parse!(with_internal.("http://id.internal:8080"))
    end

    assert parse!(with_internal.("https://id.internal"))[:internal_issuer_url] ==
             "https://id.internal"

    assert parse!(with_internal.("http://127.0.0.1:8080"))[:internal_issuer_url]

    assert parse!(
             Map.put(
               with_internal.("http://id.internal:8080"),
               "OIDC_INTERNAL_ISSUER_ALLOW_HTTP",
               "true"
             )
           )[:internal_issuer_url] == "http://id.internal:8080"

    assert_raise ArgumentError, ~r/without OIDC_INTERNAL_ISSUER_URL/, fn ->
      parse!(Map.put(base(tmp_dir), "OIDC_INTERNAL_ISSUER_ALLOW_HTTP", "true"))
    end
  end

  test "requires the client id and a readable, non-empty secret file", %{tmp_dir: tmp_dir} do
    base = %{"OIDC_ISSUER" => "https://id.example.com", "OIDC_CLIENT_ID" => "analytics"}

    assert_raise ArgumentError, ~r/OIDC_CLIENT_ID/, fn ->
      parse!(Map.delete(base, "OIDC_CLIENT_ID"))
    end

    assert_raise ArgumentError, ~r/OIDC_CLIENT_SECRET_FILE is required/, fn -> parse!(base) end

    assert_raise ArgumentError, ~r/could not be read/, fn ->
      parse!(Map.put(base, "OIDC_CLIENT_SECRET_FILE", Path.join(tmp_dir, "missing")))
    end

    assert_raise ArgumentError, ~r/empty/, fn ->
      parse!(Map.put(base, "OIDC_CLIENT_SECRET_FILE", secret_file(tmp_dir, "\n")))
    end
  end

  test "the secret is never taken from the environment" do
    assert_raise ArgumentError, ~r/OIDC_CLIENT_SECRET_FILE is required/, fn ->
      parse!(%{
        "OIDC_ISSUER" => "https://id.example.com",
        "OIDC_CLIENT_ID" => "analytics",
        "OIDC_CLIENT_SECRET" => "s3cret"
      })
    end
  end

  test "plain http only for loopback issuers", %{tmp_dir: tmp_dir} do
    base = %{"OIDC_CLIENT_ID" => "a", "OIDC_CLIENT_SECRET_FILE" => secret_file(tmp_dir)}

    assert_raise ArgumentError, ~r/must use https/, fn ->
      parse!(Map.put(base, "OIDC_ISSUER", "http://id.example.com"))
    end

    assert parse!(
             base
             |> Map.put("OIDC_ISSUER", "http://localhost:8080/x")
             |> Map.put("OIDC_ROLE_MAP", "staff=viewer")
           )[:enabled]
  end

  test "refuses to disable password login without OIDC" do
    assert_raise ArgumentError, ~r/nobody would be able to log in/, fn ->
      parse!(%{"OIDC_DISABLE_PASSWORD_LOGIN" => "true"})
    end
  end

  test "refuses partial configuration without an issuer" do
    assert_raise ArgumentError, ~r/OIDC_CLIENT_ID set without OIDC_ISSUER/, fn ->
      parse!(%{"OIDC_CLIENT_ID" => "analytics"})
    end
  end
end
