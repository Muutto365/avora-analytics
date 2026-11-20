defmodule PlausibleWeb.OIDC.LoginSession do
  @moduledoc """
  Session handling for OIDC single sign-on (fork addition).

  After the provider has authenticated a user, `put_pending/2` stores a
  short-lived, encrypted marker for that user in the browser session. When
  `PlausibleWeb.UserAuth.log_in_user/3` then logs that user in, directly or
  after the account's own two-factor step, `session_opts/2` gives the new
  session a fixed lifetime (`OIDC_SESSION_HOURS`, not extended by use) and
  `mark/2` records in the browser session that it came from the provider.
  """

  alias Plausible.Auth.OIDC

  @pending_key "oidc_login"
  @method_key "login_method"
  @salt "oidc login pending"
  @pending_ttl_seconds 600

  @spec put_pending(Plug.Conn.t(), Plausible.Auth.User.t()) :: Plug.Conn.t()
  def put_pending(conn, user) do
    sealed = Plug.Crypto.encrypt(secret_key_base(), @salt, user.id, max_age: @pending_ttl_seconds)
    Plug.Conn.put_session(conn, @pending_key, sealed)
  end

  @doc "Whether the provider has just authenticated this user in this browser."
  @spec pending?(Plug.Conn.t(), Plausible.Auth.User.t()) :: boolean()
  def pending?(conn, user) do
    with true <- OIDC.enabled?(),
         sealed when is_binary(sealed) <- session(conn)[@pending_key],
         {:ok, user_id} <-
           Plug.Crypto.decrypt(secret_key_base(), @salt, sealed, max_age: @pending_ttl_seconds) do
      user_id == user.id
    else
      _ -> false
    end
  end

  @doc """
  Options for `Plausible.Auth.UserSessions.create!/3` and whether the
  session is an OIDC session.
  """
  @spec session_opts(Plug.Conn.t(), Plausible.Auth.User.t()) :: {Keyword.t(), boolean()}
  def session_opts(conn, user) do
    if pending?(conn, user) do
      hours = Keyword.fetch!(OIDC.config(), :session_hours)
      timeout_at = NaiveDateTime.utc_now(:second) |> NaiveDateTime.add(hours * 3600, :second)
      {[timeout_at: timeout_at, fixed_timeout: true], true}
    else
      {[], false}
    end
  end

  @doc "Call after the session has been renewed for the logged-in user."
  @spec mark(Plug.Conn.t(), boolean()) :: Plug.Conn.t()
  def mark(conn, true), do: Plug.Conn.put_session(conn, @method_key, "oidc")
  def mark(conn, false), do: conn

  @doc "Whether the current browser session was established through OIDC."
  @spec oidc_session?(Plug.Conn.t()) :: boolean()
  def oidc_session?(conn) do
    OIDC.enabled?() and session(conn)[@method_key] == "oidc"
  end

  # Reads the fetched session directly, so this also works (and answers
  # false) where the session has not been fetched.
  defp session(conn), do: conn.private[:plug_session] || %{}

  defp secret_key_base, do: PlausibleWeb.Endpoint.config(:secret_key_base)
end
