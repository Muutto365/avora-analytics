defmodule PlausibleWeb.Plugs.OIDCPasswordLogin do
  @moduledoc """
  Refuses the password login, password reset and password-based 2FA steps
  when `OIDC_DISABLE_PASSWORD_LOGIN` is set (fork addition). Without that
  setting it does nothing.
  """

  @behaviour Plug

  import Plug.Conn

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    if Plausible.Auth.OIDC.password_login_disabled?() do
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
end
