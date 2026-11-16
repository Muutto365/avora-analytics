defmodule PlausibleWeb.RemoteIP do
  @moduledoc """
  Implements the strategy of retrieving client's remote IP

  Forwarded-IP headers (`X-Plausible-IP`, `CF-Connecting-IP`,
  `B-Forwarded-For`, `X-Forwarded-For`, `Forwarded`) are only honoured
  from a trusted forwarding proxy:

    * when `INGEST_KEY` is set, only for requests whose `x-ingest-key`
      header matches it;
    * when `INGEST_KEY` is not set, only if `TRUST_FORWARDED_IP_HEADERS`
      is explicitly enabled (accepts them from any sender).

  Otherwise the IP of the connection's peer is used.
  """

  require Logger

  @key_header "x-ingest-key"

  @doc "Logs, once at boot, when forwarded headers are ignored or trusted from anyone."
  def log_configuration do
    config = Application.get_env(:plausible, __MODULE__, [])

    cond do
      configured_key(config) ->
        :ok

      Keyword.get(config, :trust_forwarded_headers, false) == true ->
        Logger.warning(
          "TRUST_FORWARDED_IP_HEADERS is enabled: client IP headers are accepted from any sender"
        )

      true ->
        Logger.warning(
          "INGEST_KEY is not set: client IP headers are ignored and the connection's peer IP is used"
        )
    end
  end

  def get(conn) do
    if trust_forwarded_headers?(conn) do
      from_forwarded_headers(conn)
    else
      peer_ip(conn)
    end
  end

  @doc false
  def trust_forwarded_headers?(conn) do
    config = Application.get_env(:plausible, __MODULE__, [])

    case configured_key(config) do
      nil ->
        Keyword.get(config, :trust_forwarded_headers, false) == true

      key ->
        case Plug.Conn.get_req_header(conn, @key_header) do
          [given | _] -> Plug.Crypto.secure_compare(given, key)
          [] -> false
        end
    end
  end

  defp configured_key(config) do
    case Keyword.get(config, :ingest_key) do
      key when is_binary(key) and key != "" -> key
      _ -> nil
    end
  end

  defp peer_ip(conn), do: to_string(:inet_parse.ntoa(conn.remote_ip))

  defp from_forwarded_headers(conn) do
    x_plausible_ip = List.first(Plug.Conn.get_req_header(conn, "x-plausible-ip")) || ""
    cf_connecting_ip = List.first(Plug.Conn.get_req_header(conn, "cf-connecting-ip")) || ""
    x_forwarded_for = List.first(Plug.Conn.get_req_header(conn, "x-forwarded-for")) || ""
    b_forwarded_for = List.first(Plug.Conn.get_req_header(conn, "b-forwarded-for")) || ""
    forwarded = List.first(Plug.Conn.get_req_header(conn, "forwarded")) || ""

    cond do
      byte_size(x_plausible_ip) > 0 ->
        clean_ip(x_plausible_ip)

      byte_size(cf_connecting_ip) > 0 ->
        clean_ip(cf_connecting_ip)

      byte_size(b_forwarded_for) > 0 ->
        parse_forwarded_for(b_forwarded_for)

      byte_size(x_forwarded_for) > 0 ->
        parse_forwarded_for(x_forwarded_for)

      byte_size(forwarded) > 0 ->
        Regex.named_captures(~r/for=(?<for>[^;,]+).*$/, forwarded)
        |> Map.get("for")
        # IPv6 addresses are enclosed in quote marks and square brackets: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded
        |> String.trim("\"")
        |> clean_ip()

      true ->
        peer_ip(conn)
    end
  end

  # Removes port from both IPv4 and IPv6 addresses. From https://regexr.com/3hpvt
  # Removes surrounding [] of an IPv6 address
  @port_regex ~r/((\.\d+)|(\]))(?<port>:[0-9]+)$/
  defp clean_ip(ip_and_port) do
    ip =
      case Regex.named_captures(@port_regex, ip_and_port) do
        %{"port" => port} -> String.trim_trailing(ip_and_port, port)
        _ -> ip_and_port
      end

    ip
    |> String.trim_leading("[")
    |> String.trim_trailing("]")
  end

  defp parse_forwarded_for(header) do
    String.split(header, ",")
    |> Enum.map(&String.trim/1)
    |> List.first()
    |> clean_ip()
  end
end
