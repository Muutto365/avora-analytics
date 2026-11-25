defmodule Plausible.Provisioning.ServiceKeyTest do
  # Fork addition
  use Plausible.DataCase, async: false
  use Plausible.Teams.Test

  import ExUnit.CaptureLog
  import Ecto.Query

  alias Plausible.Auth
  alias Plausible.Provisioning.ServiceKey

  @key String.duplicate("ab12", 16)
  @other_key String.duplicate("cd34", 16)

  setup do
    original = Application.get_env(:plausible, Plausible.Provisioning)
    on_exit(fn -> Application.put_env(:plausible, Plausible.Provisioning, original) end)

    owner = new_user(email: "provisioner@example.com")
    team = owner_team_of(owner)
    configure(owner_email: owner.email, hub_stats_api_key: @key)

    {:ok, owner: owner, team: team}
  end

  defp configure(opts), do: Application.put_env(:plausible, Plausible.Provisioning, opts)

  defp hub_keys(user) do
    Repo.all(from(k in Auth.ApiKey, where: k.user_id == ^user.id and k.name == "hub"))
  end

  defp owner_team_of(user) do
    {:ok, team} = Plausible.Provisioning.owner_team(user)
    team
  end

  test "does nothing when no key is configured", %{owner: owner} do
    for key <- [nil, ""] do
      configure(owner_email: owner.email, hub_stats_api_key: key)
      assert ServiceKey.ensure() == {:ok, :disabled}
    end

    assert hub_keys(owner) == []
  end

  test "does nothing when the owner does not exist", %{owner: owner} do
    configure(owner_email: "nobody@example.com", hub_stats_api_key: @key)
    assert ServiceKey.ensure() == {:ok, :no_owner}

    configure(owner_email: nil, hub_stats_api_key: @key)
    assert ServiceKey.ensure() == {:ok, :no_owner}

    assert Repo.aggregate(Auth.ApiKey, :count) == 0
    assert hub_keys(owner) == []
  end

  test "the first start creates the key in the owner's team", %{owner: owner, team: team} do
    assert ServiceKey.ensure() == {:ok, :created}

    assert [key] = hub_keys(owner)
    assert key.key_hash == Auth.ApiKey.do_hash(@key)
    assert key.team_id == team.id
    assert key.scopes == ["stats:read:*"]

    assert {:ok, %{api_key: found}} = Auth.find_api_key(@key)
    assert found.id == key.id
  end

  test "a second start changes nothing", %{owner: owner} do
    assert ServiceKey.ensure() == {:ok, :created}
    [before] = hub_keys(owner)

    assert ServiceKey.ensure() == {:ok, :unchanged}
    assert [after_second] = hub_keys(owner)
    assert after_second.id == before.id
    assert after_second.updated_at == before.updated_at
  end

  test "a changed value replaces the key", %{owner: owner} do
    assert ServiceKey.ensure() == {:ok, :created}
    [old] = hub_keys(owner)

    configure(owner_email: owner.email, hub_stats_api_key: @other_key)
    assert ServiceKey.ensure() == {:ok, :replaced}

    assert [new] = hub_keys(owner)
    assert new.id != old.id
    assert new.key_hash == Auth.ApiKey.do_hash(@other_key)
    assert {:error, :invalid_api_key} = Auth.find_api_key(@key)
    assert {:ok, _} = Auth.find_api_key(@other_key)
  end

  test "a stale hash (a rotated SECRET_KEY_BASE) replaces the key", %{owner: owner} do
    assert ServiceKey.ensure() == {:ok, :created}
    [old] = hub_keys(owner)
    old |> Ecto.Changeset.change(key_hash: String.duplicate("0", 64)) |> Repo.update!()

    assert ServiceKey.ensure() == {:ok, :replaced}
    assert [new] = hub_keys(owner)
    assert new.key_hash == Auth.ApiKey.do_hash(@key)
  end

  test "duplicates collapse to exactly one key", %{owner: owner, team: team} do
    {:ok, _} = Auth.create_stats_api_key(owner, team, "hub", @other_key)
    {:ok, _} = Auth.create_stats_api_key(owner, team, "hub", String.duplicate("ef56", 16))

    assert ServiceKey.ensure() == {:ok, :replaced}
    assert [key] = hub_keys(owner)
    assert key.key_hash == Auth.ApiKey.do_hash(@key)
  end

  test "other keys are never touched", %{owner: owner, team: team} do
    {:ok, own_other} = Auth.create_stats_api_key(owner, team, "reporting", @other_key)
    someone = new_user(email: "someone@example.com")

    {:ok, someones_hub} =
      Auth.create_stats_api_key(someone, owner_team_of(someone), "hub", String.duplicate("ef56", 16))

    assert ServiceKey.ensure() == {:ok, :created}
    configure(owner_email: owner.email, hub_stats_api_key: String.duplicate("9a8b", 16))
    assert ServiceKey.ensure() == {:ok, :replaced}

    assert Repo.reload!(own_other).key_hash == own_other.key_hash
    assert Repo.reload!(someones_hub).key_hash == someones_hub.key_hash
    assert Repo.aggregate(Auth.ApiKey, :count) == 3
  end

  test "a failure is reported, rolls back and keeps the existing key", %{owner: owner, team: team} do
    assert ServiceKey.ensure() == {:ok, :created}
    [current] = hub_keys(owner)

    # Another key already holds the value: the insert hits the unique hash.
    {:ok, clash} = Auth.create_stats_api_key(owner, team, "reporting", @other_key)
    configure(owner_email: owner.email, hub_stats_api_key: @other_key)

    assert {:error, reason} = ServiceKey.ensure()
    assert reason =~ "invalid"
    refute reason =~ @other_key

    assert hub_keys(owner) |> Enum.map(& &1.id) == [current.id]
    assert Repo.reload!(clash)
  end

  test "the key is never logged, on success or failure", %{owner: owner, team: team} do
    level = Logger.level()
    Logger.configure(level: :debug)
    on_exit(fn -> Logger.configure(level: level) end)

    log =
      capture_log([level: :debug], fn ->
        ServiceKey.run()
        ServiceKey.run()
        configure(owner_email: owner.email, hub_stats_api_key: @other_key)
        ServiceKey.run()

        {:ok, _} = Auth.create_stats_api_key(owner, team, "reporting", @key)
        configure(owner_email: owner.email, hub_stats_api_key: @key)
        ServiceKey.run()
      end)

    assert log =~ "created"
    assert log =~ "unchanged"
    assert log =~ "replaced"
    assert log =~ "not ensured"

    for secret <- [@key, @other_key] do
      refute log =~ secret
      refute log =~ binary_part(secret, 0, 12)
    end
  end

  test "it runs once at start and never stops the application" do
    spec = ServiceKey.child_spec([])
    assert spec.restart == :temporary
  end
end
