defmodule PlausibleWeb.Plugs.OIDCPasswordLogin do
  @moduledoc """
  Refuses the password login, password reset and the two-factor step after
  a password when `OIDC_DISABLE_PASSWORD_LOGIN` is set (fork addition).
  Without that setting it does nothing.
  """

  @behaviour Plug

  import Plug.Conn

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    if Plausible.Auth.OIDC.password_login_disabled?() and not oidc_two_factor_step?(conn) do
      conn
      |> PlausibleWeb.TwoFactor.Session.clear_2fa_user()
      |> Phoenix.Controller.put_flash(
        :login_error,
        "Password login is disabled. Please use single sign-on."
      )
      |> Phoenix.Controller.redirect(to: "/login")
      |> halt()
    else
      conn
    end
  end

  # The account's own two-factor step after a single sign-on login stays
  # available (see PlausibleWeb.OIDCController.callback/2).
  defp oidc_two_factor_step?(conn) do
    conn.path_info in [["2fa", "verify"], ["2fa", "use_recovery_code"]] and
      case PlausibleWeb.TwoFactor.Session.get_2fa_user(conn) do
        {:ok, user} -> PlausibleWeb.OIDC.LoginSession.pending?(conn, user)
        _ -> false
      end
  end
end
