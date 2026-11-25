defmodule Plausible.Teams.Invitations.InviteToTeam do
  @moduledoc """
  Service for inviting new or existing users to team.
  """

  alias Plausible.Repo
  alias Plausible.Teams

  @valid_roles Plausible.Teams.Invitation.roles() -- [:guest]
  @valid_roles @valid_roles ++ Enum.map(@valid_roles, &to_string/1)

  def invite(team, inviter, invitee_email, role, opts \\ [])

  def invite(team, inviter, invitee_email, role, opts) when role in @valid_roles do
    # Fork addition: the managed team's members come from the identity provider.
    with :ok <- Avora.Roles.check_unmanaged(team),
         team <- Repo.preload(team, [:owners]),
         :ok <- Teams.Invitations.check_invitation_permissions(team, inviter, role, opts),
         :ok <- Teams.Invitations.check_team_member_limit(team, role, invitee_email),
         invitee = Plausible.Auth.find_user_by(email: invitee_email),
         :ok <- Teams.Invitations.ensure_new_membership(team, invitee, role),
         {:ok, invitation} <- Teams.Invitations.invite(team, invitee_email, role, inviter) do
      # The invitee is known only by email address, which is not recorded.
      Avora.Audit.record(
        action: "team.invitation_create",
        principal: Avora.Audit.person_principal(inviter),
        target_type: "team",
        target_id: team.id,
        role: role,
        via: "ui"
      )

      if Keyword.get(opts, :send_email?, true) do
        send_invitation_email(invitation, invitee)
      end

      {:ok, invitation}
    end
  end

  def invite(_team, _inviter, _invitee_email, role, _opts) do
    raise "Invalid role passed: #{inspect(role)}"
  end

  def send_invitation_email(invitation, invitee) do
    invitation
    |> Repo.preload([:team, :inviter])
    |> Teams.Invitations.send_invitation_email(invitee)
  end
end
