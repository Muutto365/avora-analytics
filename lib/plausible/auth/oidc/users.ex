defmodule Plausible.Auth.OIDC.Users do
  @moduledoc """
  Maps validated OIDC ID token claims to a local user (fork addition).

    * `email` must be present and `email_verified` must be `true`.
    * The ID token must grant a role through `OIDC_ROLE_MAP` (client roles
      of this application's client; see `Avora.Roles`). A bound account
      without one is refused and loses its managed-team membership and
      sessions. After a successful sign-in the role is applied.
    * Users are bound to the provider's identity, the (`iss`, `sub`) pair.
      A bound user is found by that pair; when the provider reports a new
      email address, the local one follows if no other user has it.
    * An identity seen for the first time is linked once to the local user
      with the same email (case-insensitive), but only if that user's email
      is verified, no email change is pending and the user is not bound to
      another identity. Otherwise the login is refused. Linking revokes the
      account's existing sessions and API keys and, with password login
      disabled, removes its password.
    * With no such user, one is created with a verified email, no password
      and the identity bound.
  """

  alias Plausible.Auth
  alias Plausible.Repo

  @max_name_length 255

  @type error() ::
          :email_missing
          | :email_unverified
          | :role_not_granted
          | :subject_missing
          | :email_taken
          | :account_not_linkable
          | :user_create_failed

  @spec resolve(map(), Keyword.t()) :: {:ok, Auth.User.t()} | {:error, error()}
  def resolve(claims, config \\ Plausible.Auth.OIDC.config()) when is_map(claims) do
    with {:ok, email} <- verified_email(claims),
         {:ok, issuer, subject} <- identity(claims),
         {:ok, role} <- granted_role(claims, config, issuer, subject),
         {:ok, user} <- find_or_create(issuer, subject, email, claims) do
      :ok = Avora.Roles.sync(user, role)
      {:ok, user}
    end
  end

  defp find_or_create(issuer, subject, email, claims) do
    case find_bound(issuer, subject) do
      %Auth.User{} = user -> follow_email(user, email)
      nil -> link_or_create(issuer, subject, email, claims)
    end
  end

  defp granted_role(claims, config, issuer, subject) do
    case Avora.Roles.role_from_claims(
           claims,
           Keyword.get(config, :client_id),
           Keyword.get(config, :role_map)
         ) do
      nil ->
        # Removed at the provider: the account here loses its access too.
        case find_bound(issuer, subject) do
          %Auth.User{} = user -> Avora.Roles.revoke(user)
          nil -> :ok
        end

        {:error, :role_not_granted}

      role ->
        {:ok, role}
    end
  end

  defp verified_email(claims) do
    case claims do
      %{"email" => email, "email_verified" => true} when is_binary(email) ->
        case String.trim(email) do
          "" -> {:error, :email_missing}
          email -> {:ok, email}
        end

      %{"email" => email} when is_binary(email) and email != "" ->
        {:error, :email_unverified}

      _ ->
        {:error, :email_missing}
    end
  end

  defp identity(%{"iss" => issuer, "sub" => subject})
       when is_binary(issuer) and issuer != "" and is_binary(subject) and subject != "" do
    {:ok, issuer, subject}
  end

  defp identity(_claims), do: {:error, :subject_missing}

  defp find_bound(issuer, subject) do
    Repo.get_by(Auth.User, oidc_issuer: issuer, oidc_subject: subject)
  end

  # The provider owns the address of a bound user.
  defp follow_email(user, email) do
    if String.downcase(user.email) == String.downcase(email) do
      {:ok, user}
    else
      if Repo.exists?(from_email(email)) do
        {:error, :email_taken}
      else
        user
        |> Ecto.Changeset.change(email: email, email_verified: true, previous_email: nil)
        |> Ecto.Changeset.unique_constraint(:email)
        |> Repo.update()
        |> case do
          {:ok, user} -> {:ok, user}
          {:error, _} -> {:error, :email_taken}
        end
      end
    end
  end

  defp link_or_create(issuer, subject, email, claims) do
    case Repo.one(from_email(email)) do
      nil ->
        create(issuer, subject, email, claims)

      %Auth.User{oidc_subject: nil, email_verified: true, previous_email: nil} = user ->
        link(user, issuer, subject)

      %Auth.User{} ->
        {:error, :account_not_linkable}
    end
  end

  @doc false
  # The first link of an existing account. The conditions are checked again
  # in the update itself, so of two identities racing for the same account
  # only one can bind it. Sessions started before the link (for example by
  # whoever created the account) are revoked, and with password login
  # disabled the password is removed.
  @spec link(Auth.User.t(), String.t(), String.t()) ::
          {:ok, Auth.User.t()} | {:error, :account_not_linkable}
  def link(user, issuer, subject) do
    import Ecto.Query

    changes =
      [oidc_issuer: issuer, oidc_subject: subject] ++
        if Plausible.Auth.OIDC.password_login_disabled?(), do: [password_hash: nil], else: []

    Repo.transaction(fn ->
      {count, _} =
        Repo.update_all(
          from(u in Auth.User,
            where:
              u.id == ^user.id and is_nil(u.oidc_issuer) and is_nil(u.oidc_subject) and
                u.email_verified == true and is_nil(u.previous_email)
          ),
          set: changes
        )

      if count != 1, do: Repo.rollback(:account_not_linkable)

      Repo.delete_all(from(k in Auth.ApiKey, where: k.user_id == ^user.id))
      tokens = delete_sessions(user.id)

      {Repo.get!(Auth.User, user.id), tokens}
    end)
    |> case do
      {:ok, {user, tokens}} ->
        disconnect(tokens)

        Avora.Audit.record(
          action: "oidc.binding_change",
          principal: Avora.Audit.person_principal(user),
          target_type: "user",
          target_id: Avora.Audit.person_id(user),
          via: "sign_in"
        )

        {:ok, user}

      {:error, :account_not_linkable} ->
        {:error, :account_not_linkable}
    end
  rescue
    # the identity is already bound to another account
    error in Postgrex.Error ->
      if match?(%{postgres: %{code: :unique_violation}}, error),
        do: {:error, :account_not_linkable},
        else: reraise(error, __STACKTRACE__)
  end

  @doc false
  # Deletes all sessions of the user; call inside the transaction that
  # changes the binding, then `disconnect/1` the returned tokens after it.
  @spec delete_sessions(pos_integer()) :: [binary()]
  def delete_sessions(user_id) do
    import Ecto.Query

    {_, tokens} =
      Repo.delete_all(from(s in Auth.UserSession, where: s.user_id == ^user_id, select: s.token))

    tokens
  end

  @doc false
  # Closes the live connections of deleted sessions. Needs the application's
  # PubSub; where it is not running (a one-off release command) there is
  # nothing to notify on this node, and the deleted sessions are refused
  # at the next request or reconnect.
  @spec disconnect([binary()]) :: :ok
  def disconnect(tokens) do
    if Process.whereis(Plausible.PubSub) do
      Enum.each(tokens, &Auth.UserSessions.disconnect_by_token/1)
    end

    :ok
  end

  defp create(issuer, subject, email, claims) do
    %Auth.User{}
    |> Auth.User.changeset(%{email: email, name: name(claims, email), email_verified: true})
    |> Ecto.Changeset.change(oidc_issuer: issuer, oidc_subject: subject)
    |> Ecto.Changeset.unique_constraint([:oidc_issuer, :oidc_subject])
    |> Repo.insert()
    |> case do
      {:ok, user} ->
        {:ok, user}

      {:error, _changeset} ->
        # A concurrent login for the same identity may have won the race.
        case find_bound(issuer, subject) do
          %Auth.User{} = user -> {:ok, user}
          nil -> {:error, :user_create_failed}
        end
    end
  end

  defp from_email(email) do
    import Ecto.Query
    from(u in Auth.User, where: u.email == ^email)
  end

  defp name(claims, email) do
    given_and_family =
      [claims["given_name"], claims["family_name"]]
      |> Enum.filter(&is_binary/1)
      |> Enum.join(" ")

    [
      claims["name"],
      given_and_family,
      claims["preferred_username"],
      email |> String.split("@") |> hd(),
      "User"
    ]
    |> Enum.find(fn value -> is_binary(value) and String.trim(value) != "" end)
    |> String.trim()
    |> String.slice(0, @max_name_length)
  end
end
