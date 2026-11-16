defmodule PlausibleWeb.RemoteIP do
  @moduledoc """
  Implements the strategy of retrieving client's remote IP

  Client IP headers are only honoured from senders that are known to
  overwrite them:

    1. When the request's `x-ingest-key` header matches `INGEST_KEY`, the
       `X-Plausible-IP` header is used.
    2. Otherwise, when the connection's peer is in `TRUSTED_PROXY_CIDRS`,
       the header named by `TRUSTED_PROXY_IP_HEADER` is used.
    3. Otherwise, the connection's peer IP is used.

  No other forwarded header is ever read. The chosen header must hold a
  single IP address (optionally with a port); anything else falls back to
  the peer IP.
  """

  import Bitwise
  require Logger

  @key_header "x-ingest-key"
  @ingest_ip_header "x-plausible-ip"

  @doc "Logs, once at boot, when no trusted source of client IPs is configured."
  def log_configuration do
    config = config()

    if is_nil(configured_key(config)) and Keyword.get(config, :trusted_proxies, []) == [] do
      Logger.warning(
        "Neither INGEST_KEY nor TRUSTED_PROXY_CIDRS is set: client IP headers are ignored and the connection's peer IP is used"
      )
    end

    :ok
  end

  def get(conn) do
    config = config()

    cond do
      ingest_key_matches?(conn, config) ->
        header_ip(conn, @ingest_ip_header) || peer_ip(conn)

      trusted_proxy?(conn, config) ->
        header_ip(conn, Keyword.fetch!(config, :trusted_proxy_ip_header)) || peer_ip(conn)

      true ->
        peer_ip(conn)
    end
  end

  @doc """
  Parses `TRUSTED_PROXY_CIDRS`: a comma-separated list of IPv4 or IPv6
  addresses or CIDR ranges.
  """
  @spec parse_cidrs!(String.t() | nil) :: [{:inet.ip_address(), non_neg_integer()}]
  def parse_cidrs!(nil), do: []

  def parse_cidrs!(value) when is_binary(value) do
    value
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.map(&parse_cidr!/1)
  end

  defp parse_cidr!(cidr) do
    {address, prefix} =
      case String.split(cidr, "/") do
        [address] -> {address, nil}
        [address, prefix] -> {address, prefix}
        _ -> invalid_cidr!(cidr)
      end

    ip =
      case :inet.parse_strict_address(String.to_charlist(address)) do
        {:ok, ip} -> ip
        {:error, _} -> invalid_cidr!(cidr)
      end

    max = ip_bits(ip)

    prefix =
      case prefix && Integer.parse(prefix) do
        nil -> max
        {n, ""} when n >= 0 and n <= max -> n
        _ -> invalid_cidr!(cidr)
      end

    {ip, prefix}
  end

  defp invalid_cidr!(cidr) do
    raise ArgumentError, "Invalid TRUSTED_PROXY_CIDRS entry: #{inspect(cidr)}"
  end

  defp config, do: Application.get_env(:plausible, __MODULE__, [])

  defp ingest_key_matches?(conn, config) do
    case configured_key(config) do
      nil ->
        false

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

  defp trusted_proxy?(conn, config) do
    header = Keyword.get(config, :trusted_proxy_ip_header)
    proxies = Keyword.get(config, :trusted_proxies, [])

    is_binary(header) and header != "" and
      Enum.any?(proxies, &in_cidr?(conn.remote_ip, &1))
  end

  defp in_cidr?(ip, {network, prefix}) do
    ip = unmap_ipv4(ip)

    ip_bits(ip) == ip_bits(network) and
      prefix_bits(ip, prefix) == prefix_bits(network, prefix)
  end

  defp unmap_ipv4({0, 0, 0, 0, 0, 0xFFFF, ab, cd}),
    do: {ab >>> 8, ab &&& 0xFF, cd >>> 8, cd &&& 0xFF}

  defp unmap_ipv4(ip), do: ip

  defp ip_bits(ip) when tuple_size(ip) == 4, do: 32
  defp ip_bits(ip) when tuple_size(ip) == 8, do: 128

  defp prefix_bits(ip, prefix) do
    {size, bits_per_part} = if tuple_size(ip) == 4, do: {32, 8}, else: {128, 16}

    value =
      ip
      |> Tuple.to_list()
      |> Enum.reduce(0, fn part, acc -> (acc <<< bits_per_part) + part end)

    value >>> (size - prefix)
  end

  defp peer_ip(conn), do: to_string(:inet_parse.ntoa(conn.remote_ip))

  defp header_ip(conn, header) do
    with [value | _] <- Plug.Conn.get_req_header(conn, header),
         ip = value |> String.trim() |> clean_ip(),
         {:ok, _} <- :inet.parse_strict_address(String.to_charlist(ip)) do
      ip
    else
      _ -> nil
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
end
