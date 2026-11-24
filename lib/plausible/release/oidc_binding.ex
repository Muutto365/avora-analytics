defmodule Plausible.Release.OIDCBinding do
  @moduledoc """
  Fork addition: sets or clears the single sign-on identity an account is
  bound to (see `Plausible.Auth.OIDC.Users`). Run through
  `Plausible.Release.oidc_binding/0`; see "Single sign-on (OIDC)" in
  README.md.

  Reads `OIDC_BINDING_EMAIL` (the account) and `OIDC_BINDING_ACTION`:

    * `clear` removes the binding; the next single sign-on links the
      account again by email, under the usual conditions.
    * `rebind` binds the account to `OIDC_BINDING_ISSUER` and
      `OIDC_BINDING_SUBJECT` (the provider's `iss` and `sub` values).

  `rebind` accepts only the issuer configured in `OIDC_ISSUER`. A change
  ends the account's sessions; passwords and API keys are not touched.
  Idempotent: an account already in the requested state is left unchanged.
  Exits non-zero on invalid input.
  """

  import Ecto.Query, only: [from: 2]

  alias Plausible.Auth.OIDC.Users
  alias Plausible.Auth.User
  alias Plausible.Repo

  def run do
    result =
      apply_action(
        System.get_env("OIDC_BINDING_ACTION", ""),
        System.get_env("OIDC_BINDING_EMAIL", ""),
        System.get_env("OIDC_BINDING_ISSUER", ""),
        System.get_env("OIDC_BINDING_SUBJECT", "")
      )

    case result do
      {:ok, message} ->
        IO.puts(message)

      {:error, message} ->
        IO.puts(:stderr, message)
        System.halt(1)
    end
  end

  @spec apply_action(String.t(), String.t(), String.t(), String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def apply_action(action, email, issuer, subject) do
    email = String.trim(email)

    with {:ok, user} <- find(email) do
      case String.trim(action) do
        "clear" -> clear(user)
        "rebind" -> rebind(user, String.trim(issuer), String.trim(subject))
        _ -> {:error, "OIDC_BINDING_ACTION must be clear or rebind"}
      end
    end
  end

  defp find(""), do: {:error, "OIDC_BINDING_EMAIL is not set"}

  defp find(email) do
    case Repo.one(from(u in User, where: u.email == ^email)) do
      nil -> {:error, "No account with this email."}
      user -> {:ok, user}
    end
  end

  defp clear(%User{oidc_issuer: nil, oidc_subject: nil}),
    do: {:ok, "The account is not bound; nothing was changed."}

  defp clear(user) do
    previous = Avora.Audit.person_id(user)

    update(user, oidc_issuer: nil, oidc_subject: nil)
    |> audit(previous)
    |> done("Binding cleared.")
  end

  defp rebind(_user, issuer, subject) when issuer == "" or subject == "",
    do: {:error, "OIDC_BINDING_ISSUER and OIDC_BINDING_SUBJECT are required for rebind"}

  defp rebind(user, issuer, subject) do
    configured = Plausible.Auth.OIDC.config()[:issuer]

    cond do
      issuer != configured ->
        {:error,
         "OIDC_BINDING_ISSUER must be the configured OIDC_ISSUER " <>
           "(#{configured || "not set"}); nothing was changed."}

      user.oidc_issuer == issuer and user.oidc_subject == subject ->
        {:ok, "The account is already bound to this identity; nothing was changed."}

      true ->
        rebind_to(user, issuer, subject)
    end
  end

  defp rebind_to(user, issuer, subject) do
    if Repo.exists?(
         from(u in User,
           where: u.oidc_issuer == ^issuer and u.oidc_subject == ^subject and u.id != ^user.id
         )
       ) do
      {:error, "Another account is bound to this identity; nothing was changed."}
    else
      update(user, oidc_issuer: issuer, oidc_subject: subject)
      |> audit(nil)
      |> done("Account bound to the identity.")
    end
  end

  # Changing the binding also ends the account's sessions.
  defp update(user, changes) do
    Repo.transaction(fn ->
      user
      |> Ecto.Changeset.change(changes)
      |> Ecto.Changeset.unique_constraint([:oidc_issuer, :oidc_subject])
      |> Repo.update()
      |> case do
        {:ok, user} -> {user, Users.delete_sessions(user.id)}
        {:error, changeset} -> Repo.rollback(changeset)
      end
    end)
    |> case do
      {:ok, {user, tokens}} ->
        Users.disconnect(tokens)
        {:ok, user}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  # The target is the binding the account had (when cleared) or has now.
  defp audit({:ok, user} = result, previous) do
    Avora.Audit.record(
      action: "oidc.binding_change",
      principal: Avora.Audit.task_principal(),
      target_type: "user",
      target_id: previous || Avora.Audit.person_id(user),
      via: "task"
    )

    result
  end

  defp audit(result, _previous), do: result

  defp done({:ok, _user}, message), do: {:ok, message}

  defp done({:error, _changeset}, _message),
    do: {:error, "Another account is bound to this identity; nothing was changed."}
end
