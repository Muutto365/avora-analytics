defmodule Plausible.ReleaseCreateUserTest do
  use Plausible.DataCase, async: false

  import ExUnit.CaptureIO
  import ExUnit.CaptureLog

  alias Plausible.{Auth, Release, Repo}

  @password "quiet-orbit-#{System.unique_integer([:positive])}-lantern"

  setup do
    patch_env(:selfhost,
      disable_registration: true,
      enable_email_verification: true
    )

    :ok
  end

  # Runs `fun` and returns everything it wrote to stdout, stderr and the log.
  defp capture_all(fun) do
    parent = self()
    original_level = Logger.level()
    Logger.configure(level: :debug)
    on_exit(fn -> Logger.configure(level: original_level) end)

    log =
      capture_log(fn ->
        stderr =
          capture_io(:stderr, fn ->
            stdout = capture_io(fn -> send(parent, {:result, fun.()}) end)
            send(parent, {:stdout, stdout})
          end)

        send(parent, {:stderr, stderr})
      end)

    Logger.configure(level: original_level)

    assert_received {:result, result}
    assert_received {:stdout, stdout}
    assert_received {:stderr, stderr}
    {result, stdout <> stderr <> log}
  end

  defp with_env(vars, fun) do
    originals = Map.new(vars, fn {key, _} -> {key, System.get_env(key)} end)
    System.put_env(vars)

    try do
      fun.()
    after
      Enum.each(originals, fn
        {key, nil} -> System.delete_env(key)
        {key, value} -> System.put_env(key, value)
      end)
    end
  end

  defp password_file(contents) do
    path = Path.join(System.tmp_dir!(), "create-user-#{System.unique_integer([:positive])}")
    File.write!(path, contents)
    on_exit(fn -> File.rm(path) end)
    path
  end

  describe "create_user/0" do
    test "creates a verified user from env and a password file" do
      vars = %{
        "CREATE_USER_EMAIL" => "owner@example.com",
        "CREATE_USER_NAME" => "Owner",
        "CREATE_USER_PASSWORD_FILE" => password_file(@password <> "\n")
      }

      {_, output} = capture_all(fn -> with_env(vars, &Release.create_user/0) end)

      assert output =~ "User created."
      refute output =~ @password

      user = Repo.get_by!(Auth.User, email: "owner@example.com")
      assert user.name == "Owner"
      assert user.email_verified
      refute user.totp_enabled
      assert Auth.Password.match?(@password, user.password_hash)
    end

    test "leaves an existing user unchanged" do
      existing = insert(:user, email: "owner@example.com")

      vars = %{
        "CREATE_USER_EMAIL" => "OWNER@example.com",
        "CREATE_USER_NAME" => "Someone else",
        "CREATE_USER_PASSWORD_FILE" => password_file(@password)
      }

      {_, output} = capture_all(fn -> with_env(vars, &Release.create_user/0) end)

      assert output =~ "already exists; nothing was changed"
      refute output =~ @password

      assert [user] = Repo.all(Auth.User)
      assert user.name == existing.name
      assert user.password_hash == existing.password_hash
    end
  end

  describe "create_user/3" do
    test "rejects a weak password like registration does" do
      weak = "password1234"

      {result, output} =
        capture_all(fn -> Release.create_user("owner@example.com", "Owner", weak) end)

      assert {:error, message} = result
      assert message =~ "password is too weak"
      refute message =~ weak
      refute output =~ weak
      refute Repo.exists?(Auth.User)
    end

    test "rejects a short password" do
      assert {:error, message} = Release.create_user("owner@example.com", "Owner", "short")
      assert message =~ "password has to be at least 12 characters"
      refute Repo.exists?(Auth.User)
    end

    test "rejects missing email and name" do
      assert {:error, message} = Release.create_user("", "", @password)
      assert message =~ "email can't be blank"
      assert message =~ "name can't be blank"
      refute message =~ @password
    end

    test "never writes the password to output or logs on success" do
      {result, output} =
        capture_all(fn -> Release.create_user("owner@example.com", "Owner", @password) end)

      assert result == {:ok, :created}
      refute output =~ @password
    end
  end
end
