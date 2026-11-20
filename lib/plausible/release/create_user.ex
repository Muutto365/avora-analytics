defmodule Plausible.Release.CreateUser do
  @moduledoc """
  Fork addition: creates a user account server-side, so a deployment can be
  set up without opening self-registration. Run through
  `Plausible.Release.create_user/0`; see "Registration and creating accounts"
  in README.md.

  Reads `CREATE_USER_EMAIL`, `CREATE_USER_NAME` and `CREATE_USER_PASSWORD_FILE`
  (path to a file holding the password; one trailing newline is ignored).
  The password is validated like registration, the email is marked verified,
  and an existing account with the same email is left unchanged.
  The password is never printed. Exits non-zero on invalid input.
  """

  import Ecto.Query, only: [from: 2]

  alias Plausible.Auth.User
  alias Plausible.Repo

  def run do
    email = System.get_env("CREATE_USER_EMAIL", "")
    name = System.get_env("CREATE_USER_NAME", "")

    result =
      case System.get_env("CREATE_USER_PASSWORD_FILE") do
        path when path in [nil, ""] ->
          {:error, "CREATE_USER_PASSWORD_FILE is not set"}

        path ->
          case File.read(path) do
            {:ok, contents} ->
              create(email, name, String.replace(contents, ~r/\r?\n\z/, ""))

            {:error, reason} ->
              {:error, "cannot read password file: #{:file.format_error(reason)}"}
          end
      end

    case result do
      {:ok, :created} ->
        IO.puts("User created.")

      {:ok, :exists} ->
        IO.puts("A user with this email already exists; nothing was changed.")

      {:error, message} ->
        IO.puts(:stderr, message)
        System.halt(1)
    end
  end

  @spec create(String.t(), String.t(), String.t()) ::
          {:ok, :created | :exists} | {:error, String.t()}
  def create(email, name, password) do
    email = String.trim(email)
    name = String.trim(name)

    cond do
      not String.contains?(email, "@") ->
        {:error, "User not created: email must be an email address"}

      Repo.exists?(from(u in User, where: u.email == ^email)) ->
        {:ok, :exists}

      true ->
        insert(email, name, password)
    end
  end

  defp insert(email, name, password) do
    %{
      "email" => email,
      "name" => name,
      "password" => password,
      "password_confirmation" => password
    }
    |> User.new()
    |> Ecto.Changeset.put_change(:email_verified, true)
    |> Repo.insert()
    |> case do
      {:ok, _user} ->
        {:ok, :created}

      {:error, changeset} ->
        # Only field names and messages; never the changeset, which holds the password.
        errors = for {field, {message, _opts}} <- changeset.errors, do: "#{field} #{message}"
        {:error, "User not created: " <> Enum.join(errors, ", ")}
    end
  end
end
