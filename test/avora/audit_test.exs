defmodule Avora.AuditTest do
  use Plausible.DataCase, async: false

  alias Avora.Audit

  @issuer "https://id.example.com/realms/staff"
  @sub "6f1c2b9e-3a4d-4e5f-8a7b-0c1d2e3f4a5b"

  setup do
    oidc = Application.get_env(:plausible, Plausible.Auth.OIDC)
    audit = Application.get_env(:plausible, Audit)
    Application.put_env(:plausible, Plausible.Auth.OIDC, enabled: true, issuer: @issuer)

    on_exit(fn ->
      Audit.remove_handler()
      Application.put_env(:plausible, Plausible.Auth.OIDC, oidc)
      Application.put_env(:plausible, Audit, audit || [])
    end)

    :ok
  end

  defp user(issuer, subject), do: %Plausible.Auth.User{oidc_issuer: issuer, oidc_subject: subject}

  describe "person_id/1" do
    test "a subject of the configured issuer, as a UUID" do
      assert Audit.person_id(user(@issuer, @sub)) == "oidc:" <> @sub
      assert Audit.person_id(user(@issuer, String.upcase(@sub))) == "oidc:" <> @sub
    end

    test "anything else is unbound" do
      assert Audit.person_id(user(@issuer, "alice")) == "unbound"
      assert Audit.person_id(user("https://other.example.com", @sub)) == "unbound"
      assert Audit.person_id(user(nil, nil)) == "unbound"
      assert Audit.person_id(nil) == "unbound"
    end
  end

  describe "build/1" do
    test "a full record in the loop.audit v1 shape" do
      tenant = Ecto.UUID.generate()

      assert {:ok, record} =
               Audit.build(%{
                 action: "team.role_change",
                 principal: {"human", "oidc:" <> @sub},
                 target_type: "user",
                 target_id: "unbound",
                 tenant_id: String.upcase(tenant),
                 role: :editor,
                 previous_role: :viewer,
                 via: "ui",
                 reason: "changed_by_admin"
               })

      assert %{
               "event.name" => "loop.audit",
               "audit.schema" => 1,
               "audit.source" => "avora-analytics",
               "audit.action" => "team.role_change",
               "audit.outcome" => "success",
               "audit.reason" => "changed_by_admin",
               "principal.kind" => "human",
               "principal.id" => "oidc:" <> @sub,
               "loop.org" => ^tenant,
               "target.type" => "user",
               "target.id" => "unbound",
               "avora.role" => "editor",
               "avora.previous_role" => "viewer",
               "avora.via" => "ui"
             } = record

      assert {:ok, _} = Ecto.UUID.cast(record["audit.event_id"])
      assert {:ok, _, 0} = DateTime.from_iso8601(record["time"])
    end

    test "refuses an unknown action, outcome or principal" do
      base = %{action: "site.create", principal: Audit.provisioning_principal()}
      assert {:ok, _} = Audit.build(base)
      assert {:error, _} = Audit.build(%{base | action: "site.rename"})
      assert {:error, _} = Audit.build(Map.put(base, :outcome, "maybe"))
      assert {:error, _} = Audit.build(%{base | principal: {"human", "alice@example.com"}})
      assert {:error, _} = Audit.build(%{base | principal: {"robot", "system:task"}})
      assert {:error, _} = Audit.build(Map.delete(base, :principal))
    end

    test "leaves out values of the wrong shape: no domains, emails or free text" do
      principal = Audit.provisioning_principal()

      {:ok, record} =
        Audit.build(%{
          action: "site.delete",
          principal: principal,
          target_type: "site",
          target_id: "example.com",
          tenant_id: "not-a-uuid",
          role: :overlord,
          via: "carrier pigeon",
          reason: "Deleted by Alice"
        })

      assert record["target.type"] == "site"
      for key <- ~w(target.id loop.org avora.role avora.via audit.reason), do: refute(record[key])

      {:ok, record} =
        Audit.build(%{
          action: "team.member_remove",
          principal: principal,
          target_type: "user",
          target_id: "alice@example.com"
        })

      refute record["target.id"]

      {:ok, record} =
        Audit.build(%{action: "site.delete", principal: principal, target_type: "planet"})

      refute record["target.type"]
    end

    test "numeric ids as strings" do
      {:ok, record} =
        Audit.build(%{
          action: "api_key.delete",
          principal: {"human", "unbound"},
          target_type: "api_key",
          target_id: 42
        })

      assert record["target.id"] == "42"
    end
  end

  describe "the file" do
    setup do
      dir = Path.join(System.tmp_dir!(), "avora-audit-#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      on_exit(fn -> File.rm_rf!(dir) end)
      {:ok, audit_file: Path.join(dir, "audit.jsonl")}
    end

    test "nothing is written without AUDIT_LOG_FILE", %{audit_file: file} do
      Application.put_env(:plausible, Audit, file: nil)
      assert Audit.ensure_handler() == :off
      assert :ok = Audit.record(action: "site.create", principal: Audit.task_principal())
      refute File.exists?(file)
    end

    test "one JSON object per line, whatever the log level", %{audit_file: file} do
      Application.put_env(:plausible, Audit, file: file)
      level = Logger.level()
      Logger.configure(level: :error)
      on_exit(fn -> Logger.configure(level: level) end)

      :ok = Audit.record(action: "site.create", principal: Audit.task_principal(), via: "task")

      :ok =
        Audit.record(
          action: "api_key.create",
          principal: {"human", "oidc:" <> @sub},
          target_type: "api_key",
          target_id: 7
        )

      lines = file |> File.read!() |> String.split("\n", trim: true)
      assert [first, second] = Enum.map(lines, &Jason.decode!/1)
      assert first["audit.action"] == "site.create"
      assert first["principal.id"] == "system:task"
      assert second["audit.action"] == "api_key.create"
      assert second["target.id"] == "7"
    end

    test "other log handlers do not take the records", %{audit_file: file} do
      Application.put_env(:plausible, Audit, file: file)
      assert Audit.ensure_handler() == :ok

      {:ok, %{filters: filters}} = :logger.get_handler_config(:default)
      assert Keyword.has_key?(filters, :avora_audit_stop)
    end

    test "an invalid record is not written and does not raise", %{audit_file: file} do
      Application.put_env(:plausible, Audit, file: file)
      assert :ok = Audit.record(action: "nope", principal: Audit.task_principal())
      refute File.exists?(file) and File.read!(file) != ""
    end
  end
end
