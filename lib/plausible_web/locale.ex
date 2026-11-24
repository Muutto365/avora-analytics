defmodule PlausibleWeb.Locale do
  @moduledoc """
  The interface language: English or Finnish.

  The language comes from the `locale` cookie when the user picked one with
  the language switch (the cookie holds only the language code), otherwise
  from the browser's Accept-Language header, otherwise English. The plug
  copies the chosen language into the session so that LiveViews, which run
  in their own processes, can set it too (see `on_mount/4`).
  """

  @behaviour Plug

  import Plug.Conn

  @supported ~w(en fi)
  @default "en"
  @cookie "locale"
  @session_key "locale"

  def supported, do: @supported
  def default, do: @default
  def cookie_name, do: @cookie

  @doc """
  Sets the language for the current process.
  """
  def put(locale) when locale in @supported do
    Gettext.put_locale(PlausibleWeb.Gettext, locale)
    locale
  end

  def put(_), do: put(@default)

  def current, do: Gettext.get_locale(PlausibleWeb.Gettext)

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    conn = fetch_cookies(conn)

    locale =
      case conn.cookies[@cookie] do
        locale when locale in @supported -> locale
        _ -> from_accept_language(get_req_header(conn, "accept-language"))
      end

    put(locale)

    conn =
      if get_session(conn, @session_key) == locale do
        conn
      else
        put_session(conn, @session_key, locale)
      end

    assign(conn, :locale, locale)
  end

  @doc """
  Picks the best supported language from Accept-Language header values.

      iex> PlausibleWeb.Locale.from_accept_language(["fi-FI,fi;q=0.9,en;q=0.8"])
      "fi"

      iex> PlausibleWeb.Locale.from_accept_language(["de-DE,en;q=0.5,fi;q=0.4"])
      "en"

      iex> PlausibleWeb.Locale.from_accept_language([])
      "en"
  """
  def from_accept_language(header_values) do
    header_values
    |> Enum.flat_map(&String.split(&1, ","))
    |> Enum.map(&parse_language_range/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.filter(fn {lang, _q} -> lang in @supported end)
    |> Enum.sort_by(fn {_lang, q} -> q end, :desc)
    |> case do
      [{lang, _q} | _] -> lang
      [] -> @default
    end
  end

  defp parse_language_range(range) do
    [tag | params] = range |> String.trim() |> String.split(";")

    lang = tag |> String.trim() |> String.downcase() |> String.split("-") |> hd()

    q =
      Enum.find_value(params, 1.0, fn param ->
        case String.split(String.trim(param), "=") do
          ["q", value] ->
            case Float.parse(value) do
              {q, _} -> q
              :error -> 0.0
            end

          _ ->
            nil
        end
      end)

    if lang != "" and q > 0, do: {lang, q}
  end

  @doc """
  LiveView hook: sets the language chosen by the plug for the LiveView process.
  """
  def on_mount(:default, _params, session, socket) do
    locale = put(session[@session_key])
    {:cont, Phoenix.Component.assign(socket, :locale, locale)}
  end
end
