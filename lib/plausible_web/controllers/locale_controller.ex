defmodule PlausibleWeb.LocaleController do
  use PlausibleWeb, :controller

  alias PlausibleWeb.Locale

  @one_year 60 * 60 * 24 * 365

  def update(conn, %{"locale" => locale} = params) when is_binary(locale) do
    conn =
      if locale in Locale.supported() do
        put_resp_cookie(conn, Locale.cookie_name(), locale,
          max_age: @one_year,
          same_site: "Lax",
          http_only: true,
          secure: PlausibleWeb.Endpoint.secure_cookie?()
        )
      else
        conn
      end

    redirect(conn, to: return_path(params["return_to"]))
  end

  def update(conn, params), do: redirect(conn, to: return_path(params["return_to"]))

  # Only paths on this site, never another host.
  defp return_path("/" <> rest = path) do
    if String.starts_with?(rest, ["/", "\\"]) or String.contains?(path, ["\r", "\n"]),
      do: "/",
      else: path
  end

  defp return_path(_), do: "/"
end
