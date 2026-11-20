defmodule Plausible.Test.OIDCFakeProvider do
  @moduledoc """
  A local OpenID provider for tests (fork addition): discovery document,
  JWKS and a token endpoint served by Bypass on localhost, with ID tokens
  signed by a key generated per test. No external network is used.
  """

  import ExUnit.Assertions

  @client_id "avora-test-client"
  @client_secret "test-client-secret"
  @kid "test-key-1"

  defstruct [:bypass, :issuer, :jwk, :agent]

  def client_id, do: @client_id
  def client_secret, do: @client_secret

  @doc """
  Starts the provider, points the application config at it and starts the
  provider configuration worker. Call from a `setup` block of an
  `async: false` test module.

  With `internal_address: true` the provider presents itself as
  `https://id.invalid/tenant` (which does not resolve) and is reachable
  only via `OIDC_INTERNAL_ISSUER_URL`. With `down: true` it is stopped
  before the provider configuration worker starts.
  """
  def start!(context_dir, overrides \\ [], discovery_overrides \\ %{}) do
    {internal_address?, overrides} = Keyword.pop(overrides, :internal_address, false)
    {down?, overrides} = Keyword.pop(overrides, :down, false)
    bypass = Bypass.open()
    address = "http://localhost:#{bypass.port}"
    # with an internal address, the public issuer is an https name that
    # does not resolve, so only rewritten requests can reach the provider
    prefix = if internal_address?, do: "/tenant", else: ""
    issuer = if internal_address?, do: "https://id.invalid" <> prefix, else: address
    jwk = JOSE.JWK.generate_key({:rsa, 2048})
    {:ok, agent} = Agent.start_link(fn -> %{grants: %{}, par: %{}} end)
    provider = %__MODULE__{bypass: bypass, issuer: issuer, jwk: jwk, agent: agent}

    Bypass.stub(bypass, "GET", prefix <> "/.well-known/openid-configuration", fn conn ->
      overrides =
        if is_function(discovery_overrides, 1),
          do: discovery_overrides.(issuer),
          else: discovery_overrides

      json(conn, 200, Map.merge(discovery(issuer), overrides))
    end)

    Bypass.stub(bypass, "GET", prefix <> "/jwks", fn conn ->
      {_, public} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()

      json(conn, 200, %{
        "keys" => [Map.merge(public, %{"kid" => @kid, "use" => "sig", "alg" => "RS256"})]
      })
    end)

    Bypass.stub(bypass, "POST", prefix <> "/token", fn conn -> token_endpoint(conn, provider) end)

    # pushed authorization requests, used when the discovery document
    # lists this endpoint
    Bypass.stub(bypass, "POST", prefix <> "/par", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      params = URI.decode_query(body)
      assert client_authenticated?(conn, params), "client did not authenticate"

      request_uri =
        "urn:ietf:params:oauth:request_uri:" <>
          Integer.to_string(System.unique_integer([:positive]))

      Agent.update(agent, &put_in(&1, [:par, request_uri], params))
      json(conn, 201, %{"request_uri" => request_uri, "expires_in" => 60})
    end)

    secret_file = Path.join(context_dir, "oidc_client_secret")
    File.write!(secret_file, @client_secret <> "\n")

    env =
      %{
        "OIDC_ISSUER" => issuer,
        "OIDC_INTERNAL_ISSUER_URL" => if(internal_address?, do: address <> prefix),
        "OIDC_CLIENT_ID" => @client_id,
        "OIDC_CLIENT_SECRET_FILE" => secret_file
      }
      |> Map.merge(Map.new(overrides, fn {k, v} -> {to_string(k), v} end))

    previous = Application.get_env(:plausible, Plausible.Auth.OIDC)

    Application.put_env(
      :plausible,
      Plausible.Auth.OIDC,
      Plausible.Auth.OIDC.Config.parse!(&env[&1])
    )

    ExUnit.Callbacks.on_exit(fn ->
      Application.put_env(:plausible, Plausible.Auth.OIDC, previous)
    end)

    if down?, do: Bypass.down(bypass)

    ExUnit.Callbacks.start_supervised!(Plausible.Auth.OIDC.provider_child_spec())
    # Waits until the discovery document and keys are loaded.
    unless down? do
      %Oidcc.ProviderConfiguration{} =
        Oidcc.ProviderConfiguration.Worker.get_provider_configuration(
          Plausible.Auth.OIDC.Provider
        )

      %JOSE.JWK{} = Oidcc.ProviderConfiguration.Worker.get_jwks(Plausible.Auth.OIDC.Provider)
    end

    provider
  end

  @doc """
  The parameters of the authorization request: from the redirect URL, or
  from the pushed request it refers to.
  """
  def authorization_params(provider, url_params) do
    case url_params do
      %{"request_uri" => request_uri} ->
        Map.fetch!(Agent.get(provider.agent, & &1.par), request_uri)

      params ->
        params
    end
  end

  def discovery(issuer) do
    %{
      "issuer" => issuer,
      "authorization_endpoint" => issuer <> "/authorize",
      "token_endpoint" => issuer <> "/token",
      "jwks_uri" => issuer <> "/jwks",
      "response_types_supported" => ["code"],
      "subject_types_supported" => ["public"],
      "id_token_signing_alg_values_supported" => ["RS256"],
      "code_challenge_methods_supported" => ["S256"],
      # client_secret_jwt is listed but not accepted, like a provider
      # whose client is set up for the client secret
      "token_endpoint_auth_methods_supported" => [
        "client_secret_jwt",
        "client_secret_basic",
        "client_secret_post"
      ],
      "token_endpoint_auth_signing_alg_values_supported" => ["HS256", "RS256"],
      "grant_types_supported" => ["authorization_code"],
      "scopes_supported" => ["openid", "email", "profile"]
    }
  end

  @doc """
  Registers an authorization code the token endpoint will accept once,
  bound to the PKCE challenge from the authorization request. `claims` are
  merged over valid defaults; `nil` values remove a claim. `opts[:jwk]`
  signs with a different key.
  """
  def grant(provider, auth_params, claims \\ %{}, opts \\ []) do
    code = "code-" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
    now = System.system_time(:second)

    claims =
      %{
        "iss" => provider.issuer,
        "sub" => "subject-" <> code,
        "aud" => @client_id,
        "exp" => now + 300,
        "iat" => now,
        "nonce" => auth_params["nonce"],
        "email" => "jane@example.com",
        "email_verified" => true,
        "name" => "Jane Doe"
      }
      |> Map.merge(claims)
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)
      |> Map.new()

    id_token = sign(Keyword.get(opts, :jwk, provider.jwk), claims)

    Agent.update(provider.agent, fn state ->
      put_in(state, [:grants, code], %{
        challenge: auth_params["code_challenge"],
        redirect_uri: auth_params["redirect_uri"],
        id_token: id_token
      })
    end)

    code
  end

  def sign(jwk, claims) do
    {_, token} =
      jwk
      |> JOSE.JWT.sign(%{"alg" => "RS256", "kid" => @kid}, claims)
      |> JOSE.JWS.compact()

    token
  end

  defp token_endpoint(conn, provider) do
    {:ok, body, conn} = Plug.Conn.read_body(conn)
    params = URI.decode_query(body)

    assert client_authenticated?(conn, params), "client did not authenticate"

    grant =
      Agent.get_and_update(provider.agent, fn state ->
        {get_in(state, [:grants, params["code"]]),
         update_in(state, [:grants], &Map.delete(&1, params["code"]))}
      end)

    cond do
      is_nil(grant) ->
        json(conn, 400, %{"error" => "invalid_grant"})

      params["redirect_uri"] != grant.redirect_uri ->
        json(conn, 400, %{"error" => "invalid_grant"})

      not pkce_ok?(params["code_verifier"], grant.challenge) ->
        json(conn, 400, %{"error" => "invalid_grant", "error_description" => "pkce"})

      true ->
        json(conn, 200, %{
          "access_token" => "access-token",
          "token_type" => "Bearer",
          "expires_in" => 300,
          "id_token" => grant.id_token
        })
    end
  end

  defp pkce_ok?(verifier, challenge) when is_binary(verifier) and is_binary(challenge) do
    :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false) == challenge
  end

  defp pkce_ok?(_, _), do: false

  defp client_authenticated?(conn, params) do
    basic =
      "Basic " <>
        Base.encode64(
          URI.encode_www_form(@client_id) <> ":" <> URI.encode_www_form(@client_secret)
        )

    Plug.Conn.get_req_header(conn, "authorization") == [basic] or
      (params["client_id"] == @client_id and params["client_secret"] == @client_secret)
  end

  defp json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.resp(status, Jason.encode!(body))
  end
end
