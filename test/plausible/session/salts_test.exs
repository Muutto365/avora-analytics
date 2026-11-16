defmodule Plausible.Session.SaltsTest do
  use Plausible.DataCase, async: false

  alias Plausible.Session.Salts
  import Ecto.Query

  setup do
    # start every test from an empty table (rolled back with the sandbox),
    # independent of the salt the application created at boot
    Repo.delete_all(from(s in "salts"))
    :ok
  end

  test "agent starts and responds with current salt" do
    {:ok, _} = Salts.start_link(name: __MODULE__)
    %{current: current, previous: nil} = Salts.fetch(__MODULE__)
    assert is_binary(current)
  end

  test "agent starts and responds with current and previous salt after rotation" do
    {:ok, _} = Salts.start_link(name: __MODULE__)
    %{current: first, previous: nil} = Salts.fetch(__MODULE__)
    :ok = Salts.rotate(__MODULE__)

    %{current: current, previous: ^first} = Salts.fetch(__MODULE__)
    assert is_binary(current)
  end

  test "old salts can be cleaned (daily rotation)" do
    put_rotation(:daily)
    t1 = ~U[2025-06-10 15:29:40Z]

    {:ok, _} = Salts.start_link(name: __MODULE__, now: t1)

    t2 = ~U[2025-06-11 15:29:40Z]

    :ok = Salts.rotate(__MODULE__, t2)

    %{current: old_current, previous: _old_previous} =
      Salts.fetch(__MODULE__)

    q = from(s in "salts")
    count = Repo.aggregate(q, :count)
    assert count == 2

    t3 = ~U[2025-06-13 15:34:40Z]

    :ok = Salts.rotate(__MODULE__, t3)

    %{current: _current, previous: ^old_current} =
      Salts.fetch(__MODULE__)

    q = from(s in "salts")
    count = Repo.aggregate(q, :count)
    assert count == 2
  end

  test "salts refresh when another node rotates them" do
    t1 = ~U[2024-06-10 15:29:40Z]
    {:ok, _} = Salts.start_link(name: :node_1, now: t1)
    {:ok, _} = Salts.start_link(name: :node_2, now: t1)

    t2 = ~U[2024-06-11 15:29:40Z]

    :ok = Salts.rotate(:node_2, t2)

    assert Salts.fetch(:node_1) != Salts.fetch(:node_2)

    send(:node_1, {:refresh, t2})

    assert eventually(fn ->
             {Salts.fetch(:node_1) == Salts.fetch(:node_2), :ok}
           end)
  end

  describe "rotation period" do
    test "defaults to weekly" do
      assert Salts.rotation() == :weekly
      assert Salts.retention_days(:weekly) == 9
      assert Salts.rotation_cron(:weekly) == "0 0 * * 1"
    end

    test "daily keeps salts for three days" do
      assert Salts.retention_days(:daily) == 3
      assert Salts.rotation_cron(:daily) == "0 0 * * *"
    end

    test "parses configured values" do
      assert Salts.parse_rotation!("weekly") == :weekly
      assert Salts.parse_rotation!("daily") == :daily

      assert_raise ArgumentError, ~r/Invalid SALT_ROTATION_PERIOD/, fn ->
        Salts.parse_rotation!("hourly")
      end
    end
  end

  describe "weekly rotation" do
    setup do
      put_rotation(:weekly)
    end

    test "a restart on day 6 keeps the same current salt" do
      t1 = ~U[2025-06-09 00:00:00Z]
      {:ok, pid} = Salts.start_link(name: __MODULE__, now: t1)
      %{current: first, previous: nil} = Salts.fetch(__MODULE__)

      stop(pid)

      day6 = DateTime.shift(t1, day: 6, hour: 12)
      {:ok, _} = Salts.start_link(name: __MODULE__, now: day6)

      assert %{current: ^first, previous: nil} = Salts.fetch(__MODULE__)
      assert salt_count() == 1
    end

    test "the previous salt is still loaded after rotation and a reload" do
      t1 = ~U[2025-06-09 00:00:00Z]
      {:ok, pid} = Salts.start_link(name: __MODULE__, now: t1)
      %{current: first} = Salts.fetch(__MODULE__)

      t2 = DateTime.shift(t1, day: 7)
      :ok = Salts.rotate(__MODULE__, t2)
      %{current: second, previous: ^first} = Salts.fetch(__MODULE__)

      # refresh from the database, as every node does periodically
      send(pid, {:refresh, DateTime.shift(t2, minute: 2)})

      assert eventually(fn ->
               {Salts.fetch(__MODULE__) == %{current: second, previous: first}, :ok}
             end)

      # and after a restart a day later
      stop(pid)
      {:ok, _} = Salts.start_link(name: __MODULE__, now: DateTime.shift(t2, day: 1))
      assert Salts.fetch(__MODULE__) == %{current: second, previous: first}
    end

    test "nothing older than the retention period survives" do
      t0 = ~U[2025-06-02 00:00:00Z]

      Repo.insert_all("salts", [
        %{salt: :crypto.strong_rand_bytes(16), inserted_at: DateTime.shift(t0, day: -30)},
        %{salt: :crypto.strong_rand_bytes(16), inserted_at: DateTime.shift(t0, day: -20)},
        %{salt: :crypto.strong_rand_bytes(16), inserted_at: DateTime.shift(t0, day: -9, hour: 1)},
        %{salt: :crypto.strong_rand_bytes(16), inserted_at: DateTime.shift(t0, day: -2)}
      ])

      {:ok, _} = Salts.start_link(name: __MODULE__, now: t0)
      assert salt_count() == 2
      assert_within_retention(t0)

      Enum.reduce(1..4, t0, fn _, now ->
        next = DateTime.shift(now, day: 7)
        :ok = Salts.rotate(__MODULE__, next)
        assert salt_count() == 2
        assert_within_retention(next)
        next
      end)
    end
  end

  describe "missed rotations" do
    setup do
      put_rotation(:weekly)
    end

    test "a restart after downtime over the rotation rotates, keeping the retired salt as previous" do
      t1 = ~U[2025-06-09 00:00:00Z]
      older = :crypto.strong_rand_bytes(16)
      retired = :crypto.strong_rand_bytes(16)

      Repo.insert_all("salts", [
        %{salt: older, inserted_at: DateTime.shift(t1, day: -7)},
        %{salt: retired, inserted_at: t1}
      ])

      # down from day 1 until day 10, over the scheduled rotation
      restart = DateTime.shift(t1, day: 10)
      {:ok, _} = Salts.start_link(name: __MODULE__, now: restart)

      %{current: current, previous: previous} = Salts.fetch(__MODULE__)
      assert previous == retired
      refute current in [older, retired]

      # the older salt is gone; only the current and the just-retired salt remain
      salts = Repo.all(from(s in "salts", select: s.salt, order_by: s.id))
      assert salts == [retired, current]
    end

    test "rotate_if_due/2 rotates only once the current salt is older than the period" do
      t1 = ~U[2025-06-09 00:00:00Z]
      {:ok, _} = Salts.start_link(name: __MODULE__, now: t1)
      %{current: first} = Salts.fetch(__MODULE__)

      assert :not_due = Salts.rotate_if_due(__MODULE__, DateTime.shift(t1, day: 6, hour: 23))
      assert %{current: ^first} = Salts.fetch(__MODULE__)

      assert :rotated = Salts.rotate_if_due(__MODULE__, DateTime.shift(t1, day: 7, hour: 1))
      assert %{current: second, previous: ^first} = Salts.fetch(__MODULE__)
      assert second != first

      assert :not_due = Salts.rotate_if_due(__MODULE__, DateTime.shift(t1, day: 8))
      assert %{current: ^second} = Salts.fetch(__MODULE__)
    end

    test "concurrent starts after downtime rotate only once" do
      t1 = ~U[2025-06-09 00:00:00Z]
      Repo.insert_all("salts", [%{salt: :crypto.strong_rand_bytes(16), inserted_at: t1}])

      restart = DateTime.shift(t1, day: 10)
      {:ok, _} = Salts.start_link(name: :node_a, now: restart)
      {:ok, _} = Salts.start_link(name: :node_b, now: restart)

      assert Salts.fetch(:node_a) == Salts.fetch(:node_b)
      assert salt_count() == 2
    end
  end

  describe "daily rotation" do
    setup do
      put_rotation(:daily)
    end

    test "a restart after the rotation period rotates the salt" do
      t1 = ~U[2025-06-09 00:00:00Z]
      {:ok, pid} = Salts.start_link(name: __MODULE__, now: t1)
      %{current: first} = Salts.fetch(__MODULE__)

      stop(pid)
      {:ok, _} = Salts.start_link(name: __MODULE__, now: DateTime.shift(t1, day: 4))
      %{current: current} = Salts.fetch(__MODULE__)

      assert current != first
      assert %{previous: ^first} = Salts.fetch(__MODULE__)
      assert salt_count() == 2
    end

    test "rotation keeps the previous salt" do
      t1 = ~U[2025-06-09 00:00:00Z]
      {:ok, pid} = Salts.start_link(name: __MODULE__, now: t1)
      %{current: first} = Salts.fetch(__MODULE__)

      t2 = DateTime.shift(t1, day: 1)
      :ok = Salts.rotate(__MODULE__, t2)
      %{current: second, previous: ^first} = Salts.fetch(__MODULE__)

      stop(pid)
      {:ok, _} = Salts.start_link(name: __MODULE__, now: DateTime.shift(t2, hour: 1))
      assert Salts.fetch(__MODULE__) == %{current: second, previous: first}
    end
  end

  defp put_rotation(rotation) do
    original = Application.get_env(:plausible, Salts)
    Application.put_env(:plausible, Salts, Keyword.put(original || [], :rotation, rotation))
    on_exit(fn -> Application.put_env(:plausible, Salts, original) end)
    :ok
  end

  defp stop(pid) do
    ref = Process.monitor(pid)
    GenServer.stop(pid)
    assert_receive {:DOWN, ^ref, _, _, _}
  end

  defp salt_count, do: Repo.aggregate(from(s in "salts"), :count)

  defp assert_within_retention(now) do
    cutoff = DateTime.shift(now, day: -Salts.retention_days(:weekly))

    for inserted_at <- Repo.all(from(s in "salts", select: s.inserted_at)) do
      assert DateTime.compare(to_utc(inserted_at), cutoff) != :lt
    end
  end

  defp to_utc(%DateTime{} = dt), do: dt
  defp to_utc(%NaiveDateTime{} = dt), do: DateTime.from_naive!(dt, "Etc/UTC")
end
