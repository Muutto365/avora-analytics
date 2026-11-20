defmodule Plausible.Auth.OIDC.Users do
  @moduledoc """
  Maps validated OIDC ID token claims to a local user (fork addition).

    * `email` must be present and `email_verified` must be `true`.
    * The groups claim must contain one of `OIDC_ALLOWED_GROUPS` (exact
      string match), unless that is `*`.
    * Users are bound to the provider's identity, the (`iss`, `sub`) pair.
      A bound user is found by that pair; when the provider reports a new
      email address, the local one follows if no other user has it.
    * An identity seen for the first time is linked once to the local user
      with the same email (case-insensitive), but only if that user's email
      is verified, no email change is pending and the user is not bound to
      another identity. Otherwise the login is refused.
    * With no such user, one is created with a verified email, no password
      and the identity bound.
  """

  alias Plausible.Auth
  alias Plausible.Repo

  @max_name_length 255

  @type error() ::
          :email_missing
          | :email_unverified
          | :group_not_allowed
          | :subject_missing
          | :email_taken
          | :account_not_linkable
          | :user_create_failed

  @spec resolve(map(), Keyword.t()) :: {:ok, Auth.User.t()} | {:error, error()}
  def resolve(claims, config \\ Plausible.Auth.OIDC.config()) when is_map(claims) do
    with {:ok, email} <- verified_email(claims),
         :ok <- check_groups(claims, config),
         {:ok, issuer, subject} <- identity(claims) do
      case find_bound(issuer, subject) do
        %Auth.User{} = user -> follow_email(user, email)
        nil -> link_or_create(issuer, subject, email, claims)
      end
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

  defp check_groups(claims, config) do
    case Keyword.get(config, :allowed_groups) do
      :any ->
        :ok

      allowed when is_list(allowed) and allowed != [] ->
        groups = claims |> Map.get(Keyword.get(config, :groups_claim, "groups")) |> List.wrap()

        if Enum.any?(groups, &(is_binary(&1) and &1 in allowed)) do
          :ok
        else
          {:error, :group_not_allowed}
        end

      _ ->
        {:error, :group_not_allowed}
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
        user
        |> Ecto.Changeset.change(oidc_issuer: issuer, oidc_subject: subject)
        |> Ecto.Changeset.unique_constraint([:oidc_issuer, :oidc_subject])
        |> Repo.update()
        |> case do
          {:ok, user} -> {:ok, user}
          {:error, _} -> {:error, :account_not_linkable}
        end

      %Auth.User{} ->
        {:error, :account_not_linkable}
    end
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
