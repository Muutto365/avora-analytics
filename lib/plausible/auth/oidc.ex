defmodule Plausible.Auth.OIDC do
  @moduledoc """
  OpenID Connect single sign-on (fork addition).

  Authorization code flow with PKCE (S256), `state` and `nonce`, on top of
  the `oidcc` library, which loads the provider's discovery document and
  keys and validates the ID token (signature, `iss`, `aud`, `exp`, `nonce`).

  Settings come from `Plausible.Auth.OIDC.Config`; with `OIDC_ISSUER` unset
  every function here reports the feature as off and nothing is started.
  """

  require Logger

  alias Plausible.Auth.OIDC.HTTPAdapter

  @provider __MODULE__.Provider
  @flow_salt "oidc login flow"
  @flow_ttl_seconds 600
  @scopes ["openid", "email", "profile"]
  # Client authentication with the client secret, as most providers set up
  # confidential clients by default.
  @auth_methods [:client_secret_basic, :client_secret_post]

  @type flow() :: %{
          state: String.t(),
          nonce: String.t(),
          verifier: String.t(),
          return_to: String.t() | nil
        }

  @spec enabled?() :: boolean()
  def enabled?, do: Keyword.get(config(), :enabled, false) == true

  @spec password_login_disabled?() :: boolean()
  def password_login_disabled?,
    do: enabled?() and Keyword.get(config(), :disable_password_login, false) == true

  @spec button_label() :: String.t()
  def button_label, do: Keyword.get(config(), :button_label, "Sign in with SSO")

  @doc "Supervisor children: the provider configuration worker, when enabled."
  @spec child_specs() :: [Supervisor.child_spec()]
  def child_specs do
    if enabled?(), do: [provider_child_spec()], else: []
  end

  @doc false
  def provider_child_spec do
    config = config()
    issuer = Keyword.fetch!(config, :issuer)

    Supervisor.child_spec(
      {Oidcc.ProviderConfiguration.Worker,
       %{
         issuer: issuer,
         name: @provider,
         # Retry instead of stopping, so an unreachable provider does not
         # take the application down with it.
         backoff_type: :random_exponential,
         backoff_min: 1_000,
         backoff_max: 60_000,
         provider_configuration_opts: %{
           quirks: %{allow_unsafe_http: Plausible.Auth.OIDC.Config.loopback?(issuer)},
           request_opts: request_opts()
         }
       }},
      id: @provider
    )
  end

  @doc """
  Starts a login: returns the provider URL to redirect to and the flow data
  to keep (encrypted) in the browser session until the callback.
  """
  @spec start(String.t(), String.t() | nil) ::
          {:ok, String.t(), String.t()} | {:error, atom()}
  def start(redirect_uri, return_to) do
    flow = %{
      state: random_token(),
      nonce: random_token(),
      verifier: random_token(),
      return_to: safe_return_to(return_to)
    }

    opts = %{
      redirect_uri: redirect_uri,
      scopes: @scopes,
      state: flow.state,
      nonce: flow.nonce,
      pkce_verifier: flow.verifier,
      require_pkce: true,
      # used for a pushed authorization request, when the provider offers it
      preferred_auth_methods: @auth_methods,
      request_opts: request_opts()
    }

    with :ok <- ensure_s256(),
         {:ok, url} <-
           call_provider(fn ->
             Oidcc.create_redirect_url(@provider, client_id(), client_secret(), opts)
           end) do
      {:ok, IO.iodata_to_binary(url), seal(flow)}
    else
      {:error, reason} when is_atom(reason) ->
        {:error, reason}

      {:error, reason} ->
        Logger.warning("OIDC authorization request failed: #{reason_kind(reason)}")
        {:error, :provider_error}
    end
  end

  @doc """
  Completes a login from the callback parameters and the sealed flow data.
  Returns the validated ID token claims.
  """
  @spec finish(String.t() | nil, map(), String.t()) :: {:ok, map(), flow()} | {:error, atom()}
  def finish(sealed_flow, params, redirect_uri) do
    with {:ok, flow} <- unseal(sealed_flow),
         :ok <- check_state(flow, params["state"]),
         :ok <- check_provider_error(params),
         {:ok, code} <- fetch_code(params),
         {:ok, claims} <- exchange(code, flow, redirect_uri) do
      {:ok, claims, flow}
    end
  end

  @doc """
  Accepts only same-origin absolute paths (`/sites`, not `//host` or
  `https://host`); anything else becomes `nil`.
  """
  @spec safe_return_to(term()) :: String.t() | nil
  def safe_return_to(path) when is_binary(path) do
    uri = URI.parse(path)

    if String.starts_with?(path, "/") and not String.starts_with?(path, "//") and
         not String.contains?(path, ["\\", "\r", "\n", "\t"]) and is_nil(uri.scheme) and
         is_nil(uri.host) do
      path
    end
  rescue
    URI.Error -> nil
  end

  def safe_return_to(_), do: nil

  defp exchange(code, flow, redirect_uri) do
    opts = %{
      redirect_uri: redirect_uri,
      nonce: flow.nonce,
      pkce_verifier: flow.verifier,
      require_pkce: true,
      preferred_auth_methods: @auth_methods,
      request_opts: request_opts()
    }

    case call_provider(fn ->
           Oidcc.retrieve_token(code, @provider, client_id(), client_secret(), opts)
         end) do
      {:ok, %Oidcc.Token{id: %Oidcc.Token.Id{claims: claims}}} when is_map(claims) ->
        {:ok, claims}

      {:ok, _token_without_id_token} ->
        {:error, :no_id_token}

      {:error, :provider_unavailable} = error ->
        error

      {:error, reason} ->
        # The reason can carry claims or response bodies; log only its kind.
        Logger.warning("OIDC token exchange or validation failed: #{reason_kind(reason)}")
        {:error, :invalid_token}
    end
  end

  # The worker may be down or still retrying the discovery document; that
  # is reported as an unavailable provider rather than a crash.
  defp call_provider(fun) do
    case fun.() do
      :undefined -> provider_unavailable()
      {:error, :provider_not_ready} -> provider_unavailable()
      result -> result
    end
  catch
    kind, _ when kind in [:exit, :error] -> provider_unavailable()
  end

  defp provider_unavailable do
    Logger.warning("OIDC provider configuration is not available")
    {:error, :provider_unavailable}
  end

  # oidcc uses S256 whenever the provider lists it, and would otherwise
  # fall back to "plain" or no PKCE at all; refuse that instead.
  defp ensure_s256 do
    case call_provider(fn ->
           Oidcc.ProviderConfiguration.Worker.get_provider_configuration(@provider)
         end) do
      %Oidcc.ProviderConfiguration{code_challenge_methods_supported: methods}
      when is_list(methods) ->
        if "S256" in methods, do: :ok, else: pkce_unsupported()

      %Oidcc.ProviderConfiguration{} ->
        pkce_unsupported()

      {:error, _} = error ->
        error
    end
  end

  defp pkce_unsupported do
    Logger.warning("OIDC provider does not support PKCE with S256")
    {:error, :pkce_unsupported}
  end

  defp check_state(flow, state) when is_binary(state) do
    if Plug.Crypto.secure_compare(flow.state, state), do: :ok, else: {:error, :invalid_state}
  end

  defp check_state(_flow, _state), do: {:error, :invalid_state}

  defp check_provider_error(%{"error" => error}) when is_binary(error) do
    if error == "access_denied", do: {:error, :access_denied}, else: {:error, :provider_error}
  end

  defp check_provider_error(_params), do: :ok

  defp fetch_code(%{"code" => code}) when is_binary(code) and code != "", do: {:ok, code}
  defp fetch_code(_params), do: {:error, :missing_code}

  defp seal(flow) do
    Plug.Crypto.encrypt(secret_key_base(), @flow_salt, flow, max_age: @flow_ttl_seconds)
  end

  defp unseal(sealed) when is_binary(sealed) do
    case Plug.Crypto.decrypt(secret_key_base(), @flow_salt, sealed, max_age: @flow_ttl_seconds) do
      {:ok, %{state: _, nonce: _, verifier: _} = flow} -> {:ok, flow}
      {:error, :expired} -> {:error, :flow_expired}
      _ -> {:error, :invalid_state}
    end
  end

  defp unseal(_), do: {:error, :invalid_state}

  defp request_opts do
    config = config()

    %{
      http_adapter:
        {HTTPAdapter,
         %{
           public_base: Keyword.get(config, :issuer),
           internal_base: Keyword.get(config, :internal_issuer_url)
         }}
    }
  end

  # Names the claim, never its value.
  defp reason_kind({:missing_claim, {claim, _expected}, _claims}) when is_binary(claim),
    do: "missing_claim(#{claim})"

  defp reason_kind({:missing_claim, claim, _claims}) when is_binary(claim),
    do: "missing_claim(#{claim})"

  defp reason_kind({kind, _}) when is_atom(kind), do: kind
  defp reason_kind({kind, _, _}) when is_atom(kind), do: kind
  defp reason_kind(kind) when is_atom(kind), do: kind
  defp reason_kind(_), do: :other

  defp random_token, do: 32 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

  defp client_id, do: Keyword.fetch!(config(), :client_id)
  defp client_secret, do: Keyword.fetch!(config(), :client_secret)
  defp secret_key_base, do: PlausibleWeb.Endpoint.config(:secret_key_base)

  @doc false
  def config, do: Application.get_env(:plausible, __MODULE__, [])
end
