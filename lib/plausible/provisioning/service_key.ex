defmodule Plausible.Provisioning.ServiceKey do
  @moduledoc """
  Keeps one Stats API key for an internal service on the provisioning
  owner's account.

  When `HUB_STATS_API_KEY` is configured and the provisioning owner
  (`PROVISIONING_OWNER_EMAIL`) exists, `ensure/0` makes sure the owner has
  exactly one Stats API key named `hub` whose stored hash
  matches the configured value: it creates the key, or replaces it when
  the stored hash differs (the hash depends on `SECRET_KEY_BASE`, so a
  rotation of either value is picked up at the next start). The owner's
  other keys are never touched. With no configured value it does nothing.

  It runs once at every start (`child_spec/1`). It never logs the key, and
  a failure is logged without stopping the application.
  """

  import Ecto.Query

  require Logger

  alias Plausible.Auth
  alias Plausible.Provisioning
  alias Plausible.Repo

  @name "hub"

  @doc "The name of the managed key."
  def name, do: @name

  @doc false
  def child_spec(_opts) do
    %{
      id: __MODULE__,
      start: {Task, :start_link, [&run/0]},
      restart: :temporary
    }
  end

  @doc false
  def run do
    case ensure() do
      {:ok, :disabled} ->
        :ok

      {:ok, :no_owner} ->
        Logger.info("Service Stats API key: provisioning owner not found, skipped")

      {:ok, result} ->
        Logger.info("Service Stats API key: #{result}")

      {:error, reason} ->
        Logger.error("Service Stats API key: not ensured (#{reason})")
    end
  end

  @doc """
  Ensures the managed key. Returns `{:ok, :disabled | :no_owner |
  :unchanged | :created | :replaced}` or `{:error, reason}`, where
  `reason` is a short string that never contains the key.
  """
  @spec ensure(String.t() | nil) ::
          {:ok, :disabled | :no_owner | :unchanged | :created | :replaced}
          | {:error, String.t()}
  def ensure(key \\ configured_key())

  def ensure(key) when not is_binary(key) or key == "", do: {:ok, :disabled}

  def ensure(key) do
    case Provisioning.owner() do
      nil -> {:ok, :no_owner}
      owner -> ensure_for(owner, key)
    end
  rescue
    e -> {:error, "exception #{inspect(e.__struct__)}"}
  catch
    kind, _ -> {:error, "#{kind}"}
  end

  defp ensure_for(owner, key) do
    with {:ok, team} <- owner_team(owner) do
      hash = Auth.ApiKey.do_hash(key)

      Repo.transaction(fn ->
        case managed_keys(owner) do
          [%Auth.ApiKey{key_hash: ^hash, team_id: team_id}] when team_id == team.id ->
            :unchanged

          existing ->
            ids = Enum.map(existing, & &1.id)
            Repo.delete_all(from(k in Auth.ApiKey, where: k.id in ^ids))

            case Auth.create_stats_api_key(owner, team, @name, key) do
              {:ok, _} -> if existing == [], do: :created, else: :replaced
              {:error, reason} -> Repo.rollback(describe(reason))
            end
        end
      end)
    end
  end

  defp owner_team(owner) do
    case Provisioning.owner_team(owner) do
      {:ok, team} -> {:ok, team}
      {:error, reason} -> {:error, "no team (#{describe(reason)})"}
    end
  end

  defp managed_keys(owner) do
    Repo.all(
      from(k in Auth.ApiKey,
        where: k.user_id == ^owner.id and k.name == ^@name,
        lock: "FOR UPDATE"
      )
    )
  end

  # Never inspect a changeset: its changes hold the raw key.
  defp describe(%Ecto.Changeset{errors: errors}) do
    fields = errors |> Keyword.keys() |> Enum.uniq() |> Enum.join(", ")
    "invalid: #{fields}"
  end

  defp describe(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp describe(_), do: "error"

  defp configured_key do
    :plausible
    |> Application.get_env(Plausible.Provisioning, [])
    |> Keyword.get(:hub_stats_api_key)
  end
end
