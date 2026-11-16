defmodule Plausible.Provisioning do
  @moduledoc """
  Site provisioning for an internal service.

  All provisioned sites belong to a single owner account, configured
  with `PROVISIONING_OWNER_EMAIL`. The service can only manage sites that
  this account owns.
  """

  import Ecto.Query

  alias Plausible.Auth
  alias Plausible.Repo
  alias Plausible.Site
  alias Plausible.Site.SharedLink
  alias Plausible.Sites

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

  @spec create_site(Auth.User.t(), map()) ::
          {:ok, Site.t()} | {:error, Ecto.Changeset.t()} | {:error, term()}
  def create_site(owner, params) do
    params = Map.take(params, ["domain", "timezone"])

    case Sites.create(owner, params) do
      {:ok, %{site: site}} -> {:ok, site}
      {:error, :site, %Ecto.Changeset{} = changeset, _} -> {:error, changeset}
      {:error, _step, reason, _} -> {:error, reason}
    end
  end

  @spec get_site(Auth.User.t(), String.t()) :: Site.t() | nil
  def get_site(owner, domain) do
    Sites.get_for_user(owner, domain, roles: [:owner])
  end

  @spec delete_site(Site.t()) :: :ok
  def delete_site(site) do
    {:ok, _} = Site.Removal.run(site)
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
