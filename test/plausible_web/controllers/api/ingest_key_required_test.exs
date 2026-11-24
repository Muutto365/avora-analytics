defmodule PlausibleWeb.Api.IngestKeyRequiredTest do
  # With REQUIRE_INGEST_KEY on, only a request carrying the ingest key may
  # submit events: nobody else can add visits to a site's numbers.
  use PlausibleWeb.ConnCase, async: false
  use Plausible.ClickhouseRepo

  alias PlausibleWeb.RemoteIP

  @key "test-ingest-key-0123456789abcdef"
  @user_agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

  setup do
    original = Application.get_env(:plausible, RemoteIP)
    on_exit(fn -> Application.put_env(:plausible, RemoteIP, original) end)
    {:ok, site: new_site()}
  end

  defp configure(opts), do: Application.put_env(:plausible, RemoteIP, opts)

  defp send_event(conn, site, key) do
    conn = put_req_header(conn, "user-agent", @user_agent)
    conn = if key, do: put_req_header(conn, "x-ingest-key", key), else: conn

    post(conn, "/api/event", %{
      domain: site.domain,
      name: "pageview",
      url: "http://#{site.domain}/"
    })
  end

  defp events(site) do
    Plausible.Event.WriteBuffer.flush()

    ClickhouseRepo.all(from(e in Plausible.ClickhouseEventV2, where: e.site_id == ^site.id))
  end

  describe "with the key required" do
    setup do
      configure(ingest_key: @key, require_ingest_key: true, trusted_proxies: [])
      :ok
    end

    test "an event without the key is refused and not recorded", %{conn: conn, site: site} do
      conn = send_event(conn, site, nil)

      assert conn.status == 403
      assert conn.resp_body == "forbidden"
      assert events(site) == []
    end

    test "an event with a wrong key is refused and not recorded", %{conn: conn, site: site} do
      conn = send_event(conn, site, "not-the-key")

      assert conn.status == 403
      assert events(site) == []
    end

    test "an event with the key is accepted and recorded", %{conn: conn, site: site} do
      conn = send_event(conn, site, @key)

      assert conn.status == 202
      assert [_] = events(site)
    end
  end

  describe "without the requirement (upstream behaviour)" do
    test "an event without the key is accepted", %{conn: conn, site: site} do
      configure(ingest_key: @key, require_ingest_key: false, trusted_proxies: [])

      conn = send_event(conn, site, nil)

      assert conn.status == 202
      assert [_] = events(site)
    end
  end

  describe "event_allowed?/1" do
    test "is false for a key of the wrong length or case" do
      configure(ingest_key: @key, require_ingest_key: true, trusted_proxies: [])

      for given <- [String.upcase(@key), @key <> "x", String.slice(@key, 0..-2//1), ""] do
        conn = Plug.Test.conn(:post, "/api/event") |> put_req_header("x-ingest-key", given)
        refute RemoteIP.event_allowed?(conn), "accepted #{inspect(given)}"
      end
    end

    test "is true without the requirement, key or not" do
      configure(ingest_key: @key, require_ingest_key: false, trusted_proxies: [])

      assert RemoteIP.event_allowed?(Plug.Test.conn(:post, "/api/event"))
    end
  end
end
