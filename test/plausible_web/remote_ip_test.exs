defmodule PlausibleWeb.RemoteIPTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Plug.Test
  import Plug.Conn

  alias PlausibleWeb.RemoteIP

  @tunnel {10, 1, 2, 3}
  @outsider {203, 0, 113, 9}

  setup do
    original = Application.get_env(:plausible, RemoteIP)
    on_exit(fn -> Application.put_env(:plausible, RemoteIP, original) end)
    :ok
  end

  defp configure(opts) do
    opts =
      Keyword.update(opts, :trusted_proxies, [], fn cidrs -> RemoteIP.parse_cidrs!(cidrs) end)

    Application.put_env(:plausible, RemoteIP, opts)
  end

  defp conn_from(peer, headers) do
    Enum.reduce(headers, %{conn(:post, "/api/event") | remote_ip: peer}, fn {k, v}, conn ->
      put_req_header(conn, k, v)
    end)
  end

  @spoofed_headers [
    {"x-forwarded-for", "6.6.6.6"},
    {"cf-connecting-ip", "6.6.6.6"},
    {"b-forwarded-for", "6.6.6.6"},
    {"forwarded", "for=6.6.6.6"},
    {"true-client-ip", "6.6.6.6"}
  ]

  describe "rule (a): matching ingest key" do
    setup do
      configure(ingest_key: "s3cret-key")
    end

    test "uses X-Plausible-IP" do
      conn = conn_from(@outsider, [{"x-ingest-key", "s3cret-key"}, {"x-plausible-ip", "1.1.1.1"}])
      assert RemoteIP.get(conn) == "1.1.1.1"
    end

    test "strips a port and IPv6 brackets" do
      assert RemoteIP.get(
               conn_from(@outsider, [
                 {"x-ingest-key", "s3cret-key"},
                 {"x-plausible-ip", "1.1.1.1:443"}
               ])
             ) == "1.1.1.1"

      assert RemoteIP.get(
               conn_from(@outsider, [
                 {"x-ingest-key", "s3cret-key"},
                 {"x-plausible-ip", "[2001:db8::1]:443"}
               ])
             ) == "2001:db8::1"
    end

    test "ignores every other forwarded header" do
      for header <- @spoofed_headers do
        conn = conn_from(@outsider, [{"x-ingest-key", "s3cret-key"}, header])
        assert RemoteIP.get(conn) == "203.0.113.9", "header #{elem(header, 0)}"
      end
    end

    test "falls back to the peer IP when X-Plausible-IP is not a single IP" do
      for value <- ["", "1.1.1.1, 2.2.2.2", "not-an-ip"] do
        conn =
          conn_from(@outsider, [{"x-ingest-key", "s3cret-key"}, {"x-plausible-ip", value}])

        assert RemoteIP.get(conn) == "203.0.113.9", "value #{inspect(value)}"
      end
    end

    test "a wrong or missing key does not unlock X-Plausible-IP" do
      for key <- ["wrong", "", "s3cret-ke", "s3cret-key2", "S3CRET-KEY", nil] do
        headers = [{"x-plausible-ip", "1.1.1.1"}]
        headers = if key, do: [{"x-ingest-key", key} | headers], else: headers
        assert RemoteIP.get(conn_from(@outsider, headers)) == "203.0.113.9", inspect(key)
      end
    end

    test "an empty configured key matches nothing" do
      configure(ingest_key: "")
      conn = conn_from(@outsider, [{"x-ingest-key", ""}, {"x-plausible-ip", "1.1.1.1"}])
      assert RemoteIP.get(conn) == "203.0.113.9"
    end
  end

  describe "rule (b): trusted proxy peer" do
    setup do
      configure(
        ingest_key: "s3cret-key",
        trusted_proxies: "10.0.0.0/8, 2001:db8::/32",
        trusted_proxy_ip_header: "cf-connecting-ip"
      )
    end

    test "uses the configured header from a trusted peer" do
      conn = conn_from(@tunnel, [{"cf-connecting-ip", "1.1.1.1"}])
      assert RemoteIP.get(conn) == "1.1.1.1"
    end

    test "trusts IPv6 and IPv4-mapped peers in range" do
      assert RemoteIP.get(
               conn_from({0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, [{"cf-connecting-ip", "1.1.1.1"}])
             ) == "1.1.1.1"

      assert RemoteIP.get(
               conn_from({0, 0, 0, 0, 0, 0xFFFF, 0x0A01, 0x0203}, [
                 {"cf-connecting-ip", "1.1.1.1"}
               ])
             ) == "1.1.1.1"
    end

    test "ignores a spoofed X-Forwarded-For through a trusted peer" do
      conn = conn_from(@tunnel, [{"x-forwarded-for", "6.6.6.6"}])
      assert RemoteIP.get(conn) == "10.1.2.3"

      conn = conn_from(@tunnel, [{"x-forwarded-for", "6.6.6.6"}, {"cf-connecting-ip", "1.1.1.1"}])
      assert RemoteIP.get(conn) == "1.1.1.1"
    end

    test "ignores a client X-Plausible-IP without the key" do
      conn = conn_from(@tunnel, [{"x-plausible-ip", "6.6.6.6"}, {"cf-connecting-ip", "1.1.1.1"}])
      assert RemoteIP.get(conn) == "1.1.1.1"

      conn = conn_from(@tunnel, [{"x-plausible-ip", "6.6.6.6"}])
      assert RemoteIP.get(conn) == "10.1.2.3"
    end

    test "a matching key takes rule (a) first" do
      conn =
        conn_from(@tunnel, [
          {"x-ingest-key", "s3cret-key"},
          {"x-plausible-ip", "1.1.1.1"},
          {"cf-connecting-ip", "2.2.2.2"}
        ])

      assert RemoteIP.get(conn) == "1.1.1.1"
    end

    test "uses the peer IP when the peer is outside the trusted ranges" do
      conn = conn_from(@outsider, [{"cf-connecting-ip", "1.1.1.1"}])
      assert RemoteIP.get(conn) == "203.0.113.9"

      conn = conn_from({11, 0, 0, 1}, [{"cf-connecting-ip", "1.1.1.1"}])
      assert RemoteIP.get(conn) == "11.0.0.1"
    end
  end

  describe "rule (c): nothing configured" do
    test "uses the peer IP for every header" do
      configure([])

      for header <- [{"x-plausible-ip", "6.6.6.6"} | @spoofed_headers] do
        assert RemoteIP.get(conn_from(@tunnel, [header])) == "10.1.2.3"
      end
    end
  end

  describe "parse_cidrs!/1" do
    test "parses addresses and ranges" do
      assert RemoteIP.parse_cidrs!(nil) == []
      assert RemoteIP.parse_cidrs!("") == []

      assert RemoteIP.parse_cidrs!("10.0.0.0/8, 192.0.2.1,::1/128") == [
               {{10, 0, 0, 0}, 8},
               {{192, 0, 2, 1}, 32},
               {{0, 0, 0, 0, 0, 0, 0, 1}, 128}
             ]
    end

    test "rejects invalid entries" do
      for value <- ["10.0.0.0/33", "nope", "10.0.0.0/x", "::1/129", "1.2.3.4/8/8"] do
        assert_raise ArgumentError, ~r/Invalid TRUSTED_PROXY_CIDRS/, fn ->
          RemoteIP.parse_cidrs!(value)
        end
      end
    end
  end

  describe "log_configuration/0" do
    test "warns when nothing trusted is configured" do
      configure([])
      assert capture_log(fn -> RemoteIP.log_configuration() end) =~ "INGEST_KEY nor"
    end

    test "is quiet when a key or trusted proxies are set" do
      configure(ingest_key: "k")
      assert capture_log(fn -> RemoteIP.log_configuration() end) == ""

      configure(trusted_proxies: "10.0.0.0/8", trusted_proxy_ip_header: "cf-connecting-ip")
      assert capture_log(fn -> RemoteIP.log_configuration() end) == ""
    end
  end

  describe "Sentry header scrubbing" do
    test "drops the ingest key and the default sensitive headers" do
      conn =
        conn_from(@tunnel, [
          {"x-ingest-key", "s3cret-key"},
          {"authorization", "Bearer x"},
          {"user-agent", "test"}
        ])

      headers = PlausibleWeb.Endpoint.scrub_sentry_headers(conn)
      refute Map.has_key?(headers, "x-ingest-key")
      refute Map.has_key?(headers, "authorization")
      assert headers["user-agent"] == "test"
    end
  end
end
