defmodule PlausibleWeb.Plugs.AuthorizeProvisioningAPI do
  @moduledoc """
  Authorizes requests to the provisioning API with a bearer token
  (`PROVISIONING_API_TOKEN`). The API answers 404 when no token is
  configured.
  """

  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    case configured_token() do
      nil ->
        conn
        |> send_json(404, %{error: "Not found"})
        |> halt()

      token ->
        if authorized?(conn, token) do
          conn
        else
          conn
          |> put_resp_header("www-authenticate", "Bearer")
          |> send_json(401, %{error: "Unauthorized"})
          |> halt()
        end
    end
  end

  defp configured_token do
    case Keyword.get(Application.get_env(:plausible, Plausible.Provisioning, []), :api_token) do
      token when is_binary(token) and token != "" -> token
      _ -> nil
    end
  end

  defp authorized?(conn, token) do
    with [value | _] <- get_req_header(conn, "authorization"),
         [scheme, given] <- String.split(String.trim(value), ~r/\s+/, parts: 2),
         "bearer" <- String.downcase(scheme) do
      Plug.Crypto.secure_compare(String.trim(given), token)
    else
      _ -> false
    end
  end

  defp send_json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
