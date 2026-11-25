defmodule Plausible.Provisioning do
  @moduledoc """
  Site provisioning for an internal service (fork addition; infra ADR-0066
  §3, Loimi 1a685f7b).

  **A tenant is a team.** Each tenant (a UUID, `teams.tenant_id`) has one
  team, created on its first site, and its sites live in that team, so
  Plausible's own team checks (memberships, team-scoped keys, the
  dashboard) keep tenants apart.

  **Every tenant team is owned by one service account**, configured with
  `PROVISIONING_OWNER_EMAIL`. Nobody can sign in to it: `ensure_owner/0`
  creates it with an unverified address under the reserved `.invalid`
  domain, which single sign-on never links, and no password. The service
  only manages teams this account owns that carry a tenant.

  **Sites provisioned before tenant teams** sit in a team without a tenant
  owned by `PROVISIONING_LEGACY_OWNER_EMAIL`. One tenant,
  `PROVISIONING_ADOPTING_TENANT_ID`, adopts such a site by its exact domain
  (the site moves into its team); no other tenant can.
  """

  import Ecto.Query

  require Logger

  alias Plausible.Auth
  alias Plausible.Repo
  alias Plausible.Site
  alias Plausible.Sites
  alias Plausible.Teams

  @owner_name "Avora provisioning"

  @doc "The configured owner account, if it exists."
  @spec owner() :: Auth.User.t() | nil
  def owner do
    case Keyword.get(config(), :owner_email) do
      email when is_binary(email) and email != "" -> Repo.get_by(Auth.User, email: email)
      _ -> nil
    end
  end

  @doc """
  Creates the service owner account when it is configured, missing, and its
  address is under `.invalid` (never a real person's address, so this never
  takes over someone's future sign-in). Returns `{:ok, :created |
  :exists | :disabled}` or `{:error, reason}`.
  """
  @spec ensure_owner() :: {:ok, :created | :exists | :disabled} | {:error, String.t()}
  def ensure_owner do
    case Keyword.get(config(), :owner_email) do
      email when is_binary(email) and email != "" ->
        cond do
          owner() -> {:ok, :exists}
          service_address?(email) -> create_owner(email)
          true -> {:ok, :disabled}
        end

      _ ->
        {:ok, :disabled}
    end
  end

  @doc "Whether `email` is a service address (under the reserved `.invalid` domain)."
  @spec service_address?(String.t()) :: boolean()
  def service_address?(email) when is_binary(email),
    do: email |> String.downcase() |> String.ends_with?(".invalid")

  defp create_owner(email) do
    %Auth.User{}
    |> Auth.User.changeset(%{email: email, name: @owner_name, email_verified: false})
    |> Ecto.Changeset.unique_constraint(:email)
    |> Repo.insert()
    |> case do
      {:ok, _} -> {:ok, :created}
      {:error, _} -> if owner(), do: {:ok, :exists}, else: {:error, "could not create"}
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

  @doc "The tenant's team, owned by `owner`, or `nil`."
  @spec tenant_team(Auth.User.t(), Ecto.UUID.t()) :: Teams.Team.t() | nil
  def tenant_team(owner, tenant_id) do
    Repo.one(
      from(t in Teams.Team,
        join: m in Teams.Membership,
        on: m.team_id == t.id and m.user_id == ^owner.id and m.role == :owner,
        where: t.tenant_id == ^tenant_id
      )
    )
  end

  @doc "The tenant's team, created (owned by `owner`) if missing."
  @spec ensure_tenant_team(Auth.User.t(), Ecto.UUID.t()) ::
          {:ok, Teams.Team.t()} | {:error, :tenant_team_taken | term()}
  def ensure_tenant_team(owner, tenant_id) do
    case tenant_team(owner, tenant_id) do
      %Teams.Team{} = team ->
        {:ok, team}

      nil ->
        Repo.transaction(fn ->
          team =
            %Teams.Team{}
            |> Teams.Team.changeset(%{name: "Tenant " <> String.slice(tenant_id, 0, 8)})
            |> Teams.Team.setup_changeset()
            |> Ecto.Changeset.put_change(:tenant_id, tenant_id)
            |> Ecto.Changeset.unique_constraint(:tenant_id)
            |> Repo.insert()

          case team do
            {:ok, team} ->
              team |> Teams.Membership.changeset(owner, :owner) |> Repo.insert!()
              team

            {:error, _} ->
              Repo.rollback(:raced)
          end
        end)
        |> case do
          {:ok, team} ->
            {:ok, team}

          {:error, :raced} ->
            # Another request created it at the same moment; it must be ours.
            case tenant_team(owner, tenant_id) do
              %Teams.Team{} = team -> {:ok, team}
              nil -> {:error, :tenant_team_taken}
            end
        end
    end
  end

  @doc """
  Creates the tenant's site for `domain` in the tenant's team, or returns it
  when the tenant already has it (`{:ok, :exists, site}`), so repeating the
  call changes nothing. A legacy site (see the module doc) is adopted by the
  adopting tenant (`{:ok, :adopted, site}`). A domain used by any other site
  is `{:error, :domain_taken}`.
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

    case existing_site(domain) do
      %Site{} = site ->
        site = Repo.preload(site, :team)

        cond do
          tenant_site?(site, owner, tenant_id) -> {:ok, :exists, site}
          adoptable?(site, domain, tenant_id) -> adopt_site(owner, site, tenant_id)
          true -> {:error, :domain_taken}
        end

      nil ->
        with {:ok, team} <- ensure_tenant_team(owner, tenant_id) do
          create_site(owner, team, params)
        end
    end
  end

  defp tenant_site?(%Site{team: %Teams.Team{tenant_id: tenant_id} = team}, owner, tenant_id)
       when is_binary(tenant_id),
       do: owned_by?(team, owner)

  defp tenant_site?(_, _, _), do: false

  defp owned_by?(team, user) do
    Repo.exists?(
      from(m in Teams.Membership,
        where: m.team_id == ^team.id and m.user_id == ^user.id and m.role == :owner
      )
    )
  end

  # Only the configured adopting tenant, only the site's current domain,
  # only from a team without a tenant that the legacy owner owns.
  defp adoptable?(%Site{domain: domain, team: %Teams.Team{tenant_id: nil} = team}, domain, tenant_id) do
    with adopting when is_binary(adopting) <- Keyword.get(config(), :adopting_tenant_id),
         true <- adopting == tenant_id,
         %Auth.User{} = legacy <- legacy_owner() do
      owned_by?(team, legacy)
    else
      _ -> false
    end
  end

  defp adoptable?(_, _, _), do: false

  defp legacy_owner do
    case Keyword.get(config(), :legacy_owner_email) do
      email when is_binary(email) and email != "" -> Repo.get_by(Auth.User, email: email)
      _ -> nil
    end
  end

  defp adopt_site(owner, site, tenant_id) do
    with {:ok, team} <- ensure_tenant_team(owner, tenant_id) do
      :ok = Teams.Invitations.transfer_site(site, team)
      {:ok, :adopted, site |> Repo.reload!() |> Repo.preload(:team, force: true)}
    end
  end

  defp create_site(owner, team, params) do
    case Sites.create(owner, params, team) do
      {:ok, %{site: site}} -> {:ok, :created, Repo.preload(site, :team)}
      {:error, :site, %Ecto.Changeset{} = changeset, _} -> {:error, changeset}
      {:error, _step, reason, _} -> {:error, reason}
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

  @doc "The tenant's sites, by domain."
  @spec list_sites(Auth.User.t(), Ecto.UUID.t()) :: [Site.t()]
  def list_sites(owner, tenant_id) do
    case tenant_team(owner, tenant_id) do
      %Teams.Team{} = team ->
        Repo.all(
          from(s in Site, where: s.team_id == ^team.id, order_by: s.domain, preload: :team)
        )

      nil ->
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

  @doc "Deletes the tenant's team once it has no sites left; no team is fine."
  @spec delete_tenant_team(Auth.User.t(), Ecto.UUID.t()) :: :ok
  def delete_tenant_team(owner, tenant_id) do
    case tenant_team(owner, tenant_id) do
      nil ->
        :ok

      team ->
        case Teams.delete(team) do
          {:ok, :deleted} ->
            :ok

          other ->
            Logger.warning("Provisioning: tenant team not deleted: #{inspect(other)}")
            :ok
        end
    end
  end

  defp config, do: Application.get_env(:plausible, __MODULE__, [])
end
