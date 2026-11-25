defmodule Plausible.Provisioning do
  @moduledoc """
  Site provisioning for an internal service (fork addition).

  Sites are provisioned per tenant: each provisioned site carries the
  tenant's id (`tenant_id`, a UUID) and a tenant reaches only its own
  sites. All provisioned sites belong to a single owner account,
  configured with `PROVISIONING_OWNER_EMAIL`, and are created in the one
  team that account owns. The service can only manage sites in that team.
  """

  import Ecto.Query

  alias Plausible.Auth
  alias Plausible.Repo
  alias Plausible.Site
  alias Plausible.Sites
  alias Plausible.Teams

  @doc "The configured owner account, if it exists."
  @spec owner() :: Auth.User.t() | nil
  def owner do
    case Keyword.get(config(), :owner_email) do
      email when is_binary(email) and email != "" -> Repo.get_by(Auth.User, email: email)
      _ -> nil
    end
  end

  @doc "A tenant id in canonical (lowercase) form, or `:error`."
  @spec cast_tenant_id(term()) :: {:ok, Ecto.UUID.t()} | :error
  def cast_tenant_id(value) when is_binary(value) do
    if Regex.match?(~r/\A[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\z/, value),
      do: Ecto.UUID.cast(String.downcase(value)),
      else: :error
  end

  def cast_tenant_id(_), do: :error

  @doc """
  Creates the tenant's site for `domain` in the owner's team, or returns it
  when the tenant already has it (`{:ok, :exists, site}`), so repeating the
  call changes nothing.

  A site of the owner's team that has no tenant yet is adopted by the first
  tenant that puts it (`{:ok, :adopted, site}`): such sites were provisioned
  before sites carried a tenant, by the same caller. A domain used by any
  other site (another tenant's, or one outside the team) is
  `{:error, :domain_taken}`.
  """
  @spec put_site(Auth.User.t(), Ecto.UUID.t(), String.t(), map()) ::
          {:ok, :created | :exists | :adopted, Site.t()}
          | {:error, :domain_taken}
          | {:error, Ecto.Changeset.t()}
          | {:error, term()}
  def put_site(owner, tenant_id, domain, params) do
    params = params |> Map.take(["timezone"]) |> Map.put("domain", domain)
    # the same normalisation as site creation applies
    domain = params |> Site.new() |> Ecto.Changeset.get_field(:domain)

    with {:ok, team} <- owner_team(owner) do
      case existing_site(domain) do
        %Site{team_id: team_id, tenant_id: ^tenant_id} = site when team_id == team.id ->
          {:ok, :exists, site}

        %Site{team_id: team_id, tenant_id: nil} = site when team_id == team.id ->
          adopt_site(site, tenant_id)

        %Site{} ->
          {:error, :domain_taken}

        nil ->
          create_site(owner, team, tenant_id, params)
      end
    end
  end

  # Sets the tenant only while the site still has none, so two tenants
  # racing for the same untenanted site cannot both adopt it.
  defp adopt_site(site, tenant_id) do
    {count, _} =
      Repo.update_all(
        from(s in Site, where: s.id == ^site.id and is_nil(s.tenant_id)),
        set: [tenant_id: tenant_id]
      )

    case {count, Repo.get(Site, site.id)} do
      {1, %Site{} = adopted} -> {:ok, :adopted, adopted}
      {0, %Site{tenant_id: ^tenant_id} = existing} -> {:ok, :exists, existing}
      _ -> {:error, :domain_taken}
    end
  end

  defp create_site(owner, team, tenant_id, params) do
    Repo.transaction(fn ->
      case Sites.create(owner, params, team) do
        {:ok, %{site: site}} ->
          site |> Ecto.Changeset.change(tenant_id: tenant_id) |> Repo.update!()

        {:error, :site, %Ecto.Changeset{} = changeset, _} ->
          Repo.rollback(changeset)

        {:error, _step, reason, _} ->
          Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, site} -> {:ok, :created, site}
      {:error, reason} -> {:error, reason}
    end
  end

  defp existing_site(domain) when is_binary(domain) and domain != "" do
    Repo.one(
      from(s in Site,
        where: s.domain == ^domain or s.domain_changed_from == ^domain,
        limit: 1
      )
    )
  end

  defp existing_site(_), do: nil

  @doc "The owner's single owned team (created if missing), whether or not its setup is complete."
  @spec owner_team(Auth.User.t()) :: {:ok, Teams.Team.t()} | {:error, term()}
  def owner_team(owner) do
    case Teams.get_owned_team(owner) do
      {:ok, team} -> {:ok, team}
      {:error, :no_team} -> Teams.get_or_create(owner)
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "The tenant's sites in the owner's team, by domain."
  @spec list_sites(Auth.User.t(), Ecto.UUID.t()) :: [Site.t()]
  def list_sites(owner, tenant_id) do
    case Teams.get_owned_team(owner) do
      {:ok, team} ->
        Repo.all(
          from(s in Site,
            where: s.team_id == ^team.id and s.tenant_id == ^tenant_id,
            order_by: s.domain
          )
        )

      _ ->
        []
    end
  end

  @doc "The tenant's site for `domain`, or `nil`."
  @spec get_site(Auth.User.t(), Ecto.UUID.t(), String.t()) :: Site.t() | nil
  def get_site(owner, tenant_id, domain) do
    owner
    |> list_sites(tenant_id)
    |> Enum.find(&(&1.domain == domain))
  end

  @doc """
  Deletes the site and queues the deletion of its events and imported
  data from ClickHouse.
  """
  @spec delete_site(Site.t()) :: :ok
  def delete_site(site) do
    {:ok, _} = Site.Removal.run(site)

    {:ok, _} =
      %{}
      |> Plausible.Workers.ClickhouseCleanSites.new(
        unique: [period: 60, states: [:available, :scheduled]]
      )
      |> Oban.insert()

    :ok
  end

  defp config, do: Application.get_env(:plausible, __MODULE__, [])
end
