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
        "OIDC_ALLOWED_GROUPS" => "/staff, /staff/analytics ,,",
        "OIDC_DISABLE_PASSWORD_LOGIN" => "true",
        "OIDC_INTERNAL_ISSUER_URL" => "http://id.internal:8080/tenant"
      })

    assert config[:enabled]
    assert config[:issuer] == "https://id.example.com/tenant"
    assert config[:client_secret] == "s3cret"
    assert config[:allowed_groups] == ["/staff", "/staff/analytics"]
    assert config[:groups_claim] == "groups"
    assert config[:button_label] == "Sign in with SSO"
    assert config[:disable_password_login]
    assert config[:internal_issuer_url] == "http://id.internal:8080/tenant"
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

    assert parse!(Map.put(base, "OIDC_ISSUER", "http://localhost:8080/x"))[:enabled]
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
