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

  @doc """
  Whether `api_key` must be limited to one tenant per request
  (`Avora.TenantScope`): the configured key itself (by its hash), or any
  key named `#{@name}` on any account. Decided from the key alone, never
  from a lookup of the owner account, so an owner whose email changed, or
  a key left behind by an earlier owner, stays limited (fails closed).
  """
  @spec service_key?(Auth.ApiKey.t()) :: boolean()
  def service_key?(%Auth.ApiKey{name: @name}), do: true

  def service_key?(%Auth.ApiKey{key_hash: hash}) when is_binary(hash) do
    case configured_key() do
      key when is_binary(key) and key != "" -> Plug.Crypto.secure_compare(Auth.ApiKey.do_hash(key), hash)
      _ -> false
    end
  end

  def service_key?(_), do: false

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
    # The service owner first (Plausible.Provisioning.ensure_owner/0): the
    # key lives on it.
    case Provisioning.ensure_owner() do
      {:ok, :created} -> Logger.info("Provisioning owner: created")
      {:ok, _} -> :ok
      {:error, reason} -> Logger.error("Provisioning owner: not ensured (#{reason})")
    end

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

  # The key belongs to no team: it reads the sites of every team its owner
  # owns, one per tenant (Plausible.Provisioning), and Avora.TenantScope
  # limits each request to the tenant of the person's token.
  defp ensure_for(owner, key) do
    hash = Auth.ApiKey.do_hash(key)

    Repo.transaction(fn ->
      case managed_keys(owner) do
        [%Auth.ApiKey{key_hash: ^hash, team_id: nil}] ->
          :unchanged

        existing ->
          ids = Enum.map(existing, & &1.id)
          Repo.delete_all(from(k in Auth.ApiKey, where: k.id in ^ids))

          # The configured value may already be a key on another account (an
          # earlier owner's hub key, before the service owner existed): only
          # this service holds the value, so that copy goes, or the new key
          # would collide with it on the unique hash.
          Repo.delete_all(
            from(k in Auth.ApiKey, where: k.key_hash == ^hash and k.user_id != ^owner.id)
          )

          %Auth.ApiKey{}
          |> Auth.ApiKey.changeset(nil, %{name: @name, user_id: owner.id, key: key})
          |> Repo.insert()
          |> case do
            {:ok, _} -> if existing == [], do: :created, else: :replaced
            {:error, reason} -> Repo.rollback(describe(reason))
          end
      end
    end)
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
