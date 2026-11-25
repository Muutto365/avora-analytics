defmodule Avora.TenantScope do
  @moduledoc """
  Limits the service Stats API key to one tenant's sites per request (fork
  addition; infra ADR-0066 §3).

  The service key (`Plausible.Provisioning.ServiceKey`) sits on the
  provisioning owner's account, which holds every provisioned site. On its
  own it would read any tenant's numbers, so with it every request must
  also carry the person's access token in `x-avora-user-token`. The
  request is allowed only when:

    * it is a stats read (`stats:read:*`), never a sites or provisioning call;
    * the token verifies and maps to a tenant (`Avora.TenantToken`);
    * the requested site belongs to that tenant (`sites.tenant_id`).

  `authenticate/3` runs before the site is looked up, so a request without
  a valid token gets the same answer whatever site it names; `check_site/1`
  runs after, and a site of another tenant, or of none, gets the same
  answer as an unknown site. Neither tells which domains exist. Every other
  API key is unaffected.
  """

  import Plug.Conn

  alias Plausible.Provisioning.ServiceKey

  @header "x-avora-user-token"

  def header, do: @header

  @doc """
  For the service key: refuses anything but a stats read, verifies the user
  token and assigns its tenant (`:avora_tenant_id`). Other keys pass.
  """
  @spec authenticate(Plug.Conn.t(), Plausible.Auth.ApiKey.t(), String.t()) ::
          {:ok, Plug.Conn.t()} | {:error, atom()}
  def authenticate(conn, api_key, scope) do
    if ServiceKey.service_key?(api_key) do
      conn = assign(conn, :avora_service_key, true)
      authenticate_service(conn, scope)
    else
      {:ok, conn}
    end
  end

  defp authenticate_service(conn, "stats:read:" <> _) do
    with {:ok, token} <- user_token(conn),
         {:ok, tenant_id} <- Avora.TenantToken.tenant(token) do
      {:ok, assign(conn, :avora_tenant_id, tenant_id)}
    else
      {:error, :not_configured} -> {:error, :user_tokens_not_accepted}
      {:error, :provider_unavailable} -> {:error, :user_token_unverifiable}
      {:error, _} -> {:error, :invalid_user_token}
    end
  end

  defp authenticate_service(_conn, _scope), do: {:error, :invalid_api_key}

  @doc """
  For the service key: the site found for the request must be the
  authenticated tenant's. Other keys pass.
  """
  @spec check_site(Plug.Conn.t()) :: {:ok, Plug.Conn.t()} | {:error, :invalid_api_key}
  def check_site(%Plug.Conn{assigns: %{avora_service_key: true}} = conn) do
    tenant_id = conn.assigns[:avora_tenant_id]

    case conn.assigns[:site] do
      %Plausible.Site{tenant_id: ^tenant_id} when is_binary(tenant_id) -> {:ok, conn}
      _ -> {:error, :invalid_api_key}
    end
  end

  def check_site(conn), do: {:ok, conn}

  defp user_token(conn) do
    case get_req_header(conn, @header) do
      [token] when token != "" -> {:ok, String.trim(token)}
      _ -> {:error, :missing_user_token}
    end
  end
end
