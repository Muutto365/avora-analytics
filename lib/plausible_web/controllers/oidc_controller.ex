defmodule PlausibleWeb.OIDCController do
  @moduledoc """
  OIDC single sign-on endpoints (fork addition). See `Plausible.Auth.OIDC`.
  """

  use PlausibleWeb, :controller

  require Logger

  alias Plausible.Auth
  alias Plausible.Auth.OIDC
  alias PlausibleWeb.OIDC.LoginSession
  alias PlausibleWeb.TwoFactor
  alias PlausibleWeb.UserAuth

  @flow_session_key "oidc_flow"

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
      conn = LoginSession.put_pending(conn, user)

      # The provider handles MFA, but an account that has its own two-factor
      # authentication enabled still goes through it, as after a password.
      if Auth.TOTP.enabled?(user) and not TwoFactor.Session.remember_2fa?(conn, user) do
        query = if flow.return_to, do: [return_to: flow.return_to], else: []

        conn
        |> TwoFactor.Session.set_2fa_user(user)
        |> redirect(to: Routes.auth_path(conn, :verify_2fa, query))
      else
        UserAuth.log_in_user(conn, user, flow.return_to)
      end
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

  defp message(:role_not_granted),
    do: "Your account is not allowed to sign in here."

  defp message(:email_taken),
    do: "Your email address at the identity provider is already used by another account here."

  defp message(:account_not_linkable),
    do:
      "An account with your email address already exists here and cannot be " <>
        "linked to single sign-on. Please contact an administrator."

  defp message(:access_denied), do: "Sign-in was cancelled."

  defp message(:flow_expired), do: "Sign-in took too long. Please try again."

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
