defmodule Avora.TenantScope do
  @moduledoc """
  Limits the service Stats API key to one tenant's sites per request (fork
  addition; infra ADR-0066 §3).

  The service key (`Plausible.Provisioning.ServiceKey`) sits on the
  provisioning owner's account, which holds every provisioned site. On its
  own it would read any tenant's numbers, so with it every request must
  also carry the person's access token in `#{"x-avora-user-token"}`. The
  request is allowed only when:

    * it is a stats read (`stats:read:*`), never a sites or provisioning call;
    * the token verifies and maps to a tenant (`Avora.TenantToken`);
    * the requested site belongs to that tenant (`sites.tenant_id`).

  A site of another tenant, or of none, gets the same answer as an unknown
  site, so the check cannot be used to learn which domains exist. Every
  other API key is unaffected.
  """

  import Plug.Conn

  alias Plausible.Provisioning.ServiceKey

  @header "x-avora-user-token"

  def header, do: @header

  @spec check(Plug.Conn.t(), Plausible.Auth.ApiKey.t(), String.t()) ::
          {:ok, Plug.Conn.t()} | {:error, atom()}
  def check(conn, api_key, scope) do
    if ServiceKey.service_key?(api_key), do: check_service(conn, scope), else: {:ok, conn}
  end

  defp check_service(conn, "stats:read:" <> _) do
    with {:ok, token} <- user_token(conn),
         {:ok, tenant_id} <- Avora.TenantToken.tenant(token) do
      case conn.assigns[:site] do
        %Plausible.Site{tenant_id: ^tenant_id} -> {:ok, assign(conn, :avora_tenant_id, tenant_id)}
        _ -> {:error, :invalid_api_key}
      end
    else
      {:error, :not_configured} -> {:error, :user_tokens_not_accepted}
      {:error, :provider_unavailable} -> {:error, :user_token_unverifiable}
      {:error, _} -> {:error, :invalid_user_token}
    end
  end

  defp check_service(_conn, _scope), do: {:error, :invalid_api_key}

  defp user_token(conn) do
    case get_req_header(conn, @header) do
      [token] when token != "" -> {:ok, String.trim(token)}
      _ -> {:error, :missing_user_token}
    end
  end
end
