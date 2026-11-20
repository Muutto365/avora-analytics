defmodule Plausible.Repo.Migrations.AddOidcIdentity do
  # Fork addition: OIDC single sign-on (see Plausible.Auth.OIDC).
  use Ecto.Migration

  def change do
    alter table(:users) do
      add :oidc_issuer, :text
      add :oidc_subject, :text
    end

    create unique_index(:users, [:oidc_issuer, :oidc_subject])

    alter table(:user_sessions) do
      add :fixed_timeout, :boolean, null: false, default: false
    end
  end
end
