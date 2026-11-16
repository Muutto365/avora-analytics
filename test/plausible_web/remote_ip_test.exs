defmodule PlausibleWeb.RemoteIPTest do
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias PlausibleWeb.RemoteIP

  @peer {10, 1, 2, 3}

  setup do
    original = Application.get_env(:plausible, RemoteIP)
    on_exit(fn -> Application.put_env(:plausible, RemoteIP, original) end)
    :ok
  end

  defp configure(opts), do: Application.put_env(:plausible, RemoteIP, opts)

  defp conn_with(headers) do
    Enum.reduce(headers, %{conn(:post, "/api/event") | remote_ip: @peer}, fn {k, v}, conn ->
      put_req_header(conn, k, v)
    end)
  end

  @forwarded_headers [
    {"x-plausible-ip", "1.1.1.1"},
    {"cf-connecting-ip", "1.1.1.1"},
    {"b-forwarded-for", "1.1.1.1, 2.2.2.2"},
    {"x-forwarded-for", "1.1.1.1, 2.2.2.2"},
    {"forwarded", "for=1.1.1.1;proto=https"}
  ]

  describe "with an ingest key configured" do
    setup do
      configure(ingest_key: "s3cret-key", trust_forwarded_headers: false)
    end

    test "honours each forwarded header when the key matches" do
      for header <- @forwarded_headers do
        conn = conn_with([{"x-ingest-key", "s3cret-key"}, header])
        assert RemoteIP.get(conn) == "1.1.1.1", "header #{elem(header, 0)}"
      end
    end

    test "uses the peer IP when the key is missing" do
      for header <- @forwarded_headers do
        assert RemoteIP.get(conn_with([header])) == "10.1.2.3"
      end
    end

    test "uses the peer IP when the key is wrong" do
      for key <- ["wrong", "", "s3cret-ke", "s3cret-key2", "S3CRET-KEY"] do
        conn = conn_with([{"x-ingest-key", key}, {"x-plausible-ip", "1.1.1.1"}])
        assert RemoteIP.get(conn) == "10.1.2.3", "key #{inspect(key)}"
      end
    end

    test "uses the peer IP when the key matches but no forwarded header is sent" do
      assert RemoteIP.get(conn_with([{"x-ingest-key", "s3cret-key"}])) == "10.1.2.3"
    end

    test "the key wins over the any-sender setting" do
      configure(ingest_key: "s3cret-key", trust_forwarded_headers: true)
      assert RemoteIP.get(conn_with([{"x-plausible-ip", "1.1.1.1"}])) == "10.1.2.3"
    end
  end

  describe "without an ingest key" do
    test "uses the peer IP by default" do
      configure([])

      for header <- @forwarded_headers do
        assert RemoteIP.get(conn_with([header])) == "10.1.2.3"
      end
    end

    test "an empty key counts as unset and matches nothing" do
      configure(ingest_key: "", trust_forwarded_headers: false)
      conn = conn_with([{"x-ingest-key", ""}, {"x-plausible-ip", "1.1.1.1"}])
      assert RemoteIP.get(conn) == "10.1.2.3"
    end

    test "honours forwarded headers from anyone only when explicitly enabled" do
      configure(ingest_key: nil, trust_forwarded_headers: true)

      for header <- @forwarded_headers do
        assert RemoteIP.get(conn_with([header])) == "1.1.1.1"
      end
    end
  end
end
