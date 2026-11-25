defmodule Avora.TenantToken do
  @moduledoc """
  The tenant of a person, read from their verified access token (fork
  addition; infra ADR-0066 §2 and §3).

  A service that shows a person their own sites' numbers (the hub) calls
  the Stats API with its service key and forwards the person's access
  token. This module verifies that token and returns the person's tenant;
  `Avora.TenantScope` then allows only that tenant's sites.

  Issuers are bound to tenants by configuration, never by the token alone:

    * the staff issuer (`OIDC_ISSUER`, the realm staff sign in with) maps
      every token to one fixed tenant, `TENANT_STAFF_TENANT_ID`;
    * the tenant issuer (`TENANT_ORG_ISSUER`) maps a token to the single
      Organization it names (claim `organization`, `{alias => %{"id" =>
      uuid}}`); none, several or a malformed one is refused.

  A token is accepted only when its signature, `iss`, `exp` and `nbf` are
  valid, its `aud` contains `TENANT_TOKEN_AUDIENCE`, it is an access token
  (`typ` "Bearer") and its `azp` is one of `TENANT_TOKEN_CLIENTS`.
  Anything else is refused; nothing here guesses a tenant.
  """

  require Logger

  alias Avora.TenantToken.Config
  alias Plausible.Auth.OIDC.HTTPAdapter

  @org_provider __MODULE__.OrgProvider
  @staff_provider Plausible.Auth.OIDC.Provider
  @signing_algs ["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"]
  @uuid ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/

  @type error() :: :not_configured | :invalid_token | :provider_unavailable

  @spec enabled?() :: boolean()
  def enabled?, do: Keyword.get(config(), :enabled, false) == true

  @doc "Supervisor children: the tenant issuer's configuration worker, when configured."
  @spec child_specs() :: [Supervisor.child_spec()]
  def child_specs do
    case Enum.find(bindings(), &(&1.provider == @org_provider)) do
      nil -> []
      binding -> [org_provider_child_spec(binding)]
    end
  end

  defp org_provider_child_spec(binding) do
    Supervisor.child_spec(
      {Oidcc.ProviderConfiguration.Worker,
       %{
         issuer: binding.issuer,
         name: @org_provider,
         backoff_type: :random_exponential,
         backoff_min: 1_000,
         backoff_max: 60_000,
         provider_configuration_opts: %{
           quirks: %{allow_unsafe_http: Plausible.Auth.OIDC.Config.loopback?(binding.issuer)},
           request_opts: %{
             http_adapter:
               {HTTPAdapter,
                %{public_base: binding.issuer, internal_base: binding.internal_issuer_url}}
           }
         }
       }},
      id: @org_provider
    )
  end

  @doc """
  Verifies `token` and returns the tenant id (a lowercase UUID) it maps
  to, or `{:error, reason}`. The reason never carries claim values.
  """
  @spec tenant(String.t() | nil) :: {:ok, String.t()} | {:error, error()}
  def tenant(token) do
    cond do
      not enabled?() -> {:error, :not_configured}
      not is_binary(token) or token == "" -> {:error, :invalid_token}
      true -> verify(token)
    end
  end

  defp verify(token) do
    with {:ok, issuer} <- peek_issuer(token),
         {:ok, binding} <- binding_for(issuer),
         {:ok, context} <- client_context(binding),
         {:ok, claims} <- validate(token, context),
         :ok <- check_access_token(claims) do
      tenant_from_claims(binding, claims)
    end
  end

  # Only picks which configured issuer verifies the token; the issuer is
  # checked again, with the signature, by `validate/2`.
  defp peek_issuer(token) do
    case JOSE.JWT.peek_payload(token) do
      %JOSE.JWT{fields: %{"iss" => issuer}} when is_binary(issuer) -> {:ok, issuer}
      _ -> {:error, :invalid_token}
    end
  rescue
    _ -> {:error, :invalid_token}
  end

  defp binding_for(issuer) do
    case Enum.find(bindings(), &(&1.issuer == issuer)) do
      nil -> {:error, :invalid_token}
      binding -> {:ok, binding}
    end
  end

  defp client_context(%{context: context}) when is_function(context, 0), do: context.()

  defp client_context(binding) do
    case Oidcc.ClientContext.from_configuration_worker(
           binding.provider,
           audience(),
           :unauthenticated
         ) do
      {:ok, context} -> {:ok, context}
      {:error, _} -> provider_unavailable()
    end
  catch
    kind, _ when kind in [:exit, :error] -> provider_unavailable()
  end

  defp provider_unavailable do
    Logger.warning("Tenant token: issuer configuration is not available")
    {:error, :provider_unavailable}
  end

  defp validate(token, context) do
    case Oidcc.Token.validate_jwt(token, context, %{signing_algs: @signing_algs}) do
      {:ok, claims} when is_map(claims) ->
        {:ok, claims}

      {:error, reason} ->
        Logger.info("Tenant token refused: #{reason_kind(reason)}")
        {:error, :invalid_token}
    end
  rescue
    _ -> {:error, :invalid_token}
  end

  @doc false
  @spec check_access_token(map()) :: :ok | {:error, :invalid_token}
  def check_access_token(claims) do
    cond do
      claims["typ"] != "Bearer" ->
        refused("not an access token")

      claims["azp"] not in Keyword.get(config(), :clients, []) ->
        refused("client not allowed")

      true ->
        :ok
    end
  end

  @doc """
  The tenant a verified token's claims map to under `binding`
  (`%{mode: {:fixed, uuid}}` or `%{mode: :organization}`).
  """
  @spec tenant_from_claims(map(), map()) :: {:ok, String.t()} | {:error, :invalid_token}
  def tenant_from_claims(%{mode: {:fixed, tenant_id}}, _claims), do: {:ok, tenant_id}

  def tenant_from_claims(%{mode: :organization}, claims) do
    case claims["organization"] do
      %{} = orgs when map_size(orgs) == 1 ->
        case Map.values(orgs) do
          [%{"id" => id}] when is_binary(id) ->
            if Regex.match?(@uuid, id), do: {:ok, id}, else: refused("organization id")

          _ ->
            refused("organization without id")
        end

      %{} = orgs when map_size(orgs) > 1 ->
        refused("more than one organization")

      _ ->
        refused("no organization")
    end
  end

  defp refused(why) do
    Logger.info("Tenant token refused: #{why}")
    {:error, :invalid_token}
  end

  # Names the kind of failure, never a claim value.
  defp reason_kind({:missing_claim, {claim, _}, _}) when is_binary(claim),
    do: "missing_claim(#{claim})"

  defp reason_kind({:missing_claim, claim, _}) when is_binary(claim),
    do: "missing_claim(#{claim})"

  defp reason_kind({kind, _}) when is_atom(kind), do: Atom.to_string(kind)
  defp reason_kind({kind, _, _}) when is_atom(kind), do: Atom.to_string(kind)
  defp reason_kind(kind) when is_atom(kind), do: Atom.to_string(kind)
  defp reason_kind(_), do: "other"

  defp bindings do
    config()
    |> Keyword.get(:bindings, [])
    |> Enum.map(fn
      %{provider: _} = binding -> binding
      %{kind: :staff} = binding -> Map.put(binding, :provider, @staff_provider)
      %{kind: :organization} = binding -> Map.put(binding, :provider, @org_provider)
    end)
  end

  defp audience, do: Keyword.fetch!(config(), :audience)

  defp config, do: Application.get_env(:plausible, __MODULE__, Config.disabled())
end
