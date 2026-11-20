defmodule PlausibleWeb.OIDCController do
  @moduledoc """
  OIDC single sign-on endpoints (fork addition). See `Plausible.Auth.OIDC`.
  """

  use PlausibleWeb, :controller

  require Logger

  alias Plausible.Auth.OIDC
  alias PlausibleWeb.UserAuth

  @flow_session_key "oidc_flow"
  @login_method_key "login_method"

  plug :require_enabled
  plug PlausibleWeb.RequireLoggedOutPlug when action in [:login]

  def login(conn, params) do
    case OIDC.start(redirect_uri(), params["return_to"]) do
      {:ok, url, sealed_flow} ->
        conn
        |> put_session(@flow_session_key, sealed_flow)
        |> redirect(external: url)

      {:error, reason} ->
        refuse(conn, reason)
    end
  end

  def callback(conn, params) do
    # The flow data is single use: drop it before validating anything.
    sealed_flow = get_session(conn, @flow_session_key)
    conn = delete_session(conn, @flow_session_key)

    with {:ok, claims, flow} <- OIDC.finish(sealed_flow, params, redirect_uri()),
         {:ok, user} <- OIDC.Users.resolve(claims) do
      conn
      |> mark_oidc_session()
      |> UserAuth.log_in_user(user, flow.return_to)
    else
      {:error, reason} -> refuse(conn, reason)
    end
  end

  @doc """
  Path that starts a login, keeping a same-origin `return_to` if given.
  """
  @spec login_path(Plug.Conn.t()) :: String.t()
  def login_path(conn) do
    case OIDC.safe_return_to(conn.params["return_to"]) do
      nil -> "/auth/oidc/login"
      return_to -> "/auth/oidc/login?" <> URI.encode_query(return_to: return_to)
    end
  end

  @doc """
  Whether the current browser session was established through OIDC.
  """
  @spec oidc_session?(Plug.Conn.t()) :: boolean()
  def oidc_session?(conn) do
    # Reads the fetched session directly so it also works where the
    # session has not been fetched (then the answer is simply false).
    OIDC.enabled?() and
      match?(%{@login_method_key => "oidc"}, conn.private[:plug_session] || %{})
  end

  # `UserAuth.log_in_user/3` renews the session and sends the redirect.
  # Before-send callbacks run in reverse registration order, so this one
  # runs before the session cookie is written and after the renewal.
  defp mark_oidc_session(conn) do
    register_before_send(conn, &put_session(&1, @login_method_key, "oidc"))
  end

  defp refuse(conn, reason) do
    Logger.warning("OIDC login refused: #{if is_atom(reason), do: reason, else: :other}")

    conn
    |> put_flash(:login_error, message(reason))
    |> redirect(to: Routes.auth_path(conn, :login_form))
  end

  defp message(:email_unverified),
    do: "Your identity provider has not verified your email address."

  defp message(:email_missing),
    do: "Your identity provider did not share an email address."

  defp message(:group_not_allowed),
    do: "Your account is not allowed to sign in here."

  defp message(:access_denied), do: "Sign-in was cancelled."

  defp message(:provider_unavailable),
    do: "Single sign-on is temporarily unavailable. Please try again later."

  defp message(_), do: "Single sign-on failed. Please try again."

  defp redirect_uri, do: PlausibleWeb.Endpoint.url() <> "/auth/oidc/callback"

  defp require_enabled(conn, _opts) do
    if OIDC.enabled?() do
      conn
    else
      conn
      |> render_error(404)
      |> halt()
    end
  end
end
