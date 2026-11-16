defmodule Plausible.Provisioning do
  @moduledoc """
  Site provisioning for an internal service.

  All provisioned sites belong to a single owner account, configured
  with `PROVISIONING_OWNER_EMAIL`, and are created in the one team that
  account owns. The service can only manage sites that this account owns.
  """

  import Ecto.Query

  alias Plausible.Auth
  alias Plausible.Repo
  alias Plausible.Site
  alias Plausible.Site.SharedLink
  alias Plausible.Sites
  alias Plausible.Teams

  @shared_link_name "Provisioned link"

  @doc "Name of the shared link managed by provisioning."
  def shared_link_name, do: @shared_link_name

  @doc "The configured owner account, if it exists."
  @spec owner() :: Auth.User.t() | nil
  def owner do
    case Keyword.get(config(), :owner_email) do
      email when is_binary(email) and email != "" -> Repo.get_by(Auth.User, email: email)
      _ -> nil
    end
  end

  @doc """
  Creates a site in the owner's team. Creating a site that already exists
  in that team returns it (`{:ok, :exists, site}`); a domain used anywhere
  else is `{:error, :domain_taken}`.
  """
  @spec create_site(Auth.User.t(), map()) ::
          {:ok, :created | :exists, Site.t()}
          | {:error, :domain_taken}
          | {:error, Ecto.Changeset.t()}
          | {:error, term()}
  def create_site(owner, params) do
    params = Map.take(params, ["domain", "timezone"])
    # the same normalisation as site creation applies
    domain = params |> Site.new() |> Ecto.Changeset.get_field(:domain)

    with {:ok, team} <- owner_team(owner) do
      case existing_site(domain) do
        %Site{team_id: team_id} = site when team_id == team.id ->
          {:ok, :exists, site}

        %Site{} ->
          {:error, :domain_taken}

        nil ->
          case Sites.create(owner, params, team) do
            {:ok, %{site: site}} -> {:ok, :created, site}
            {:error, :site, %Ecto.Changeset{} = changeset, _} -> {:error, changeset}
            {:error, _step, reason, _} -> {:error, reason}
          end
      end
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

  # The owner's single owned team, whether or not its setup is complete.
  defp owner_team(owner) do
    case Teams.get_owned_team(owner) do
      {:ok, team} -> {:ok, team}
      {:error, :no_team} -> Teams.get_or_create(owner)
      {:error, reason} -> {:error, reason}
    end
  end

  @spec get_site(Auth.User.t(), String.t()) :: Site.t() | nil
  def get_site(owner, domain) do
    Sites.get_for_user(owner, domain, roles: [:owner])
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

  @doc """
  Creates the site's provisioned shared link, replacing any previous
  one, and returns it with its URL.
  """
  @spec rotate_shared_link(Site.t()) :: {:ok, String.t()} | {:error, term()}
  def rotate_shared_link(site) do
    Repo.transaction(fn ->
      Repo.delete_all(
        from(l in SharedLink, where: l.site_id == ^site.id and l.name == ^@shared_link_name)
      )

      case Sites.create_shared_link(site, @shared_link_name) do
        {:ok, link} -> Sites.shared_link_url(site, link)
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  defp config, do: Application.get_env(:plausible, __MODULE__, [])
end
