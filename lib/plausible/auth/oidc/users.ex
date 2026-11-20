defmodule Plausible.Auth.OIDC.Users do
  @moduledoc """
  Maps validated OIDC ID token claims to a local user (fork addition).

    * `email` must be present and `email_verified` must be `true`.
    * With `OIDC_ALLOWED_GROUPS` set, the groups claim must contain at
      least one of the listed groups (exact string match).
    * An existing user with the same email (case-insensitive) is used as
      is; otherwise a user is created with a verified email and no
      password.
  """

  alias Plausible.Auth
  alias Plausible.Repo

  @max_name_length 255

  @spec resolve(map()) ::
          {:ok, Auth.User.t()}
          | {:error,
             :email_missing | :email_unverified | :group_not_allowed | :user_create_failed}
  def resolve(claims, config \\ Plausible.Auth.OIDC.config()) when is_map(claims) do
    with {:ok, email} <- verified_email(claims),
         :ok <- check_groups(claims, config) do
      find_or_create(email, claims)
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
    case Keyword.get(config, :allowed_groups, []) do
      [] ->
        :ok

      allowed ->
        groups = claims |> Map.get(Keyword.get(config, :groups_claim, "groups")) |> List.wrap()

        if Enum.any?(groups, &(is_binary(&1) and &1 in allowed)) do
          :ok
        else
          {:error, :group_not_allowed}
        end
    end
  end

  defp find_or_create(email, claims) do
    case Repo.get_by(Auth.User, email: email) do
      %Auth.User{} = user -> {:ok, ensure_verified(user)}
      nil -> create(email, claims)
    end
  end

  # The provider has verified the address, which is what the local
  # activation step would otherwise ask the user to do.
  defp ensure_verified(%Auth.User{email_verified: true} = user), do: user

  defp ensure_verified(user) do
    user |> Ecto.Changeset.change(email_verified: true) |> Repo.update!()
  end

  defp create(email, claims) do
    %Auth.User{}
    |> Auth.User.changeset(%{email: email, name: name(claims, email), email_verified: true})
    |> Repo.insert()
    |> case do
      {:ok, user} ->
        {:ok, user}

      {:error, changeset} ->
        # A concurrent login may have created the same user first.
        if Keyword.has_key?(changeset.errors, :email) do
          case Repo.get_by(Auth.User, email: email) do
            %Auth.User{} = user -> {:ok, ensure_verified(user)}
            nil -> {:error, :user_create_failed}
          end
        else
          {:error, :user_create_failed}
        end
    end
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
