defmodule Plausible.Repo.Migrations.AddTenantIdToSites do
  # Fork addition: the tenant a provisioned site belongs to (see
  # Plausible.Provisioning).
  use Ecto.Migration

  def change do
    alter table(:sites) do
      add :tenant_id, :uuid
    end

    create index(:sites, [:tenant_id], where: "tenant_id IS NOT NULL")
  end
end
