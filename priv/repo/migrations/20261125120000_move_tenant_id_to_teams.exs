defmodule Plausible.Repo.Migrations.MoveTenantIdToTeams do
  # Fork addition: a tenant's unit is a team (one team per tenant, owned by
  # the provisioning service account; see Plausible.Provisioning), so
  # Plausible's own team checks keep tenants apart. The site-level column
  # from 20261124120000 never held data in production and is dropped.
  use Ecto.Migration

  def up do
    alter table(:teams) do
      add :tenant_id, :uuid
    end

    create unique_index(:teams, [:tenant_id], where: "tenant_id IS NOT NULL")

    drop_if_exists index(:sites, [:tenant_id])

    alter table(:sites) do
      remove :tenant_id
    end
  end

  def down do
    alter table(:sites) do
      add :tenant_id, :uuid
    end

    create index(:sites, [:tenant_id], where: "tenant_id IS NOT NULL")

    drop_if_exists index(:teams, [:tenant_id])

    alter table(:teams) do
      remove :tenant_id
    end
  end
end
