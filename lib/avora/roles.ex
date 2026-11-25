defmodule Avora.Roles do
  @moduledoc """
  Staff roles from the identity provider's client roles (fork addition).

  The identity provider assigns roles on this application's own client
  (`resource_access.<OIDC_CLIENT_ID>.roles` in the ID token). One declared
  table, `OIDC_ROLE_MAP`, maps them to roles here, and the result is
  applied at every sign-in, so the provider is the source:

    * **Who may sign in:** only a person holding at least one mapped role.
      A role the table does not name grants nothing. A bound account that
      signs in without any mapped role is refused, and loses its
      membership of the managed team and its sessions.
    * **What they may do:** their role in the **managed team**, the team
      that holds the provisioned sites (the team owned by the
      `PROVISIONING_OWNER_EMAIL` account). The highest mapped role wins
      (`admin` > `editor` > `viewer`); the team's owner is never changed.
    * **No second source:** while the table is in use, members, roles,
      invitations and guest access of the managed team cannot be changed in
      the application's own settings.

  Every change is recorded as a `role.sync` audit record.
  """

  import Ecto.Query, only: [from: 2]

  alias Plausible.Auth
  alias Plausible.Repo
  alias Plausible.Teams

  @rank %{viewer: 1, editor: 2, admin: 3}

  @doc "The roles a mapping may grant, lowest first."
  def grantable_roles, do: [:viewer, :editor, :admin]

  @doc """
  The highest role the claims grant through `role_map`, or `nil`. Only the
  roles of `client_id` are read.
  """
  @spec role_from_claims(map(), String.t() | nil, %{String.t() => atom()}) :: atom() | nil
  def role_from_claims(claims, client_id, role_map)
      when is_binary(client_id) and is_map(role_map) do
    claims
    |> get_in_map(["resource_access", client_id, "roles"])
    |> List.wrap()
    |> Enum.filter(&is_binary/1)
    |> Enum.map(&Map.get(role_map, &1))
    |> Enum.reject(&is_nil/1)
    |> Enum.max_by(&Map.fetch!(@rank, &1), fn -> nil end)
  end

  def role_from_claims(_claims, _client_id, _role_map), do: nil

  @doc "Whether the role mapping is in use (single sign-on with a role map)."
  @spec enabled?() :: boolean()
  def enabled? do
    config = Plausible.Auth.OIDC.config()
    Keyword.get(config, :enabled, false) == true and is_map(Keyword.get(config, :role_map))
  end

  @doc "The managed team, when it exists."
  @spec managed_team() :: Teams.Team.t() | nil
  def managed_team do
    with %Auth.User{} = owner <- Plausible.Provisioning.owner(),
         {:ok, team} <- Teams.get_owned_team(owner) do
      team
    else
      _ -> nil
    end
  end

  @doc """
  `:ok` unless `subject` (a team or a site) belongs to the managed team
  while the role mapping is in use; then `{:error, :permission_denied}`.
  """
  @spec check_unmanaged(Teams.Team.t() | Plausible.Site.t() | nil) ::
          :ok | {:error, :permission_denied}
  def check_unmanaged(subject) do
    team_id =
      case subject do
        %Teams.Team{id: id} -> id
        %Plausible.Site{team_id: id} -> id
        _ -> nil
      end

    with true <- not is_nil(team_id) and enabled?(),
         %Teams.Team{id: ^team_id} <- managed_team() do
      {:error, :permission_denied}
    else
      _ -> :ok
    end
  end

  @doc """
  Applies `role` (from `role_from_claims/3`) to the user's membership of
  the managed team. Without a managed team there is nothing to apply.
  """
  @spec sync(Auth.User.t(), atom()) :: :ok
  def sync(%Auth.User{} = user, role) when is_map_key(@rank, role) do
    case managed_team() do
      nil -> :ok
      team -> sync_membership(team, user, role)
    end
  end

  @doc """
  Removes a person who holds no mapped role any more: their membership of
  the managed team (never its owner's) and their sessions.
  """
  @spec revoke(Auth.User.t()) :: :ok
  def revoke(%Auth.User{} = user) do
    team = managed_team()

    tokens =
      Repo.transaction(fn ->
        removed = if team, do: delete_membership(team, user)
        tokens = Plausible.Auth.OIDC.Users.delete_sessions(user.id)
        {removed, tokens}
      end)

    case tokens do
      {:ok, {removed, tokens}} ->
        Plausible.Auth.OIDC.Users.disconnect(tokens)
        if removed, do: audit(user, team, :none, removed)

      _ ->
        :ok
    end

    :ok
  end

  defp sync_membership(team, user, role) do
    case Repo.get_by(Teams.Membership, team_id: team.id, user_id: user.id) do
      %Teams.Membership{role: :owner} ->
        :ok

      %Teams.Membership{role: ^role} ->
        :ok

      %Teams.Membership{role: previous} = membership ->
        membership = membership |> Ecto.Changeset.change(role: role) |> Repo.update!()

        # A guest becoming a member keeps no per-site guest access.
        if previous == :guest, do: Repo.delete_all(Ecto.assoc(membership, :guest_memberships))

        audit(user, team, role, previous)

      nil ->
        team
        |> Teams.Membership.changeset(user, role)
        |> Repo.insert!()

        audit(user, team, role, :none)
    end

    :ok
  end

  defp delete_membership(team, user) do
    case Repo.one(
           from(m in Teams.Membership,
             where: m.team_id == ^team.id and m.user_id == ^user.id and m.role != :owner
           )
         ) do
      nil ->
        nil

      membership ->
        Repo.delete!(membership)
        Plausible.Segments.after_user_removed_from_team(team, user)
        membership.role
    end
  end

  defp audit(user, _team, role, previous) do
    Avora.Audit.record(
      action: "role.sync",
      principal: Avora.Audit.person_principal(user),
      target_type: "user",
      target_id: Avora.Audit.person_id(user),
      role: role,
      previous_role: previous,
      via: "sign_in"
    )
  end

  defp get_in_map(map, [key | rest]) when is_map(map), do: get_in_map(Map.get(map, key), rest)
  defp get_in_map(value, []), do: value
  defp get_in_map(_value, _keys), do: nil
end
