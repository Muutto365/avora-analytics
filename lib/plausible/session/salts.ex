defmodule Plausible.Session.Salts do
  @moduledoc """
  Keeps the current and previous visitor-hash salts in memory.

  The salt is rotated once per rotation period (`:daily` or `:weekly`,
  configured with `SALT_ROTATION_PERIOD`, default `:weekly`). Salts are
  kept in the database for the rotation period plus two days, so that a
  restart within a period keeps the current salt and the previous salt
  stays available across a rotation. A rotation missed while the app was
  down is caught up at start and by a daily check (`rotate_if_due/2`).
  """
  use GenServer
  use Plausible.Repo

  @rotation_days %{daily: 1, weekly: 7}
  @retention_margin_days 2
  @rotation_lock 7_301_744_215

  @doc "Parses the configured rotation period."
  def parse_rotation!(value) when value in ["daily", "weekly"], do: String.to_atom(value)

  def parse_rotation!(value) do
    raise ArgumentError,
          "Invalid SALT_ROTATION_PERIOD: #{inspect(value)}. Expected one of: daily, weekly"
  end

  @doc "Cron expression for the rotation job."
  def rotation_cron(:daily), do: "0 0 * * *"
  def rotation_cron(:weekly), do: "0 0 * * 1"

  @doc "How long salts are kept, in days: the rotation period plus two days."
  def retention_days(rotation), do: Map.fetch!(@rotation_days, rotation) + @retention_margin_days

  @doc "The configured rotation period."
  def rotation do
    Application.get_env(:plausible, __MODULE__, [])[:rotation] || :weekly
  end

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: opts[:name] || __MODULE__)
  end

  @impl true
  def init(opts) do
    name = opts[:name] || __MODULE__
    now = opts[:now] || DateTime.utc_now()

    # catch up on a rotation missed while the app was down
    rotate_in_db(now, only_if_due?: true)

    ^name =
      :ets.new(name, [
        :named_table,
        :set,
        :protected,
        {:read_concurrency, true}
      ])

    refresh(name, now)

    {:ok, name}
  end

  def refresh(name, now) do
    salts = Repo.all(from s in "salts", select: s.salt, order_by: [desc: s.id], limit: 2)

    state =
      case salts do
        [current, prev] ->
          %{previous: prev, current: current}

        [current] ->
          %{previous: nil, current: current}

        [] ->
          new = generate_and_persist_new_salt(now)
          %{previous: nil, current: new}
      end

    true = :ets.insert(name, {:state, state})
    interval = Application.get_env(:plausible, __MODULE__)[:interval] || :timer.seconds(90)
    Process.send_after(self(), {:refresh, now}, interval)
    :ok
  end

  def rotate(name \\ __MODULE__, now \\ DateTime.utc_now()) do
    GenServer.call(name, {:rotate, now})
  end

  @doc """
  Rotates only if the current salt is older than the rotation period,
  e.g. because a scheduled rotation was missed.
  """
  def rotate_if_due(name \\ __MODULE__, now \\ DateTime.utc_now()) do
    GenServer.call(name, {:rotate_if_due, now})
  end

  def fetch(name \\ __MODULE__) do
    [state: state] = :ets.lookup(name, :state)
    state
  end

  @impl true
  def handle_call({:rotate, now}, _from, name) do
    rotate_in_db(now, only_if_due?: false)
    load_state(name)
    {:reply, :ok, name}
  end

  def handle_call({:rotate_if_due, now}, _from, name) do
    result = rotate_in_db(now, only_if_due?: true)
    load_state(name)
    {:reply, result, name}
  end

  @impl true
  def handle_info({:refresh, now}, name) do
    refresh(name, now)
    {:noreply, name}
  end

  # Inserts the new salt before deleting old ones, under a lock so that
  # nodes starting or rotating at the same time do not rotate twice.
  defp rotate_in_db(now, only_if_due?: only_if_due?) do
    {:ok, result} =
      Repo.transaction(fn ->
        Repo.query!("SELECT pg_advisory_xact_lock($1)", [@rotation_lock])

        result =
          if only_if_due? and not rotation_due?(now) do
            :not_due
          else
            generate_and_persist_new_salt(now)
            :rotated
          end

        clean_old_salts(now)
        result
      end)

    result
  end

  defp rotation_due?(now) do
    newest =
      Repo.one(from s in "salts", select: s.inserted_at, order_by: [desc: s.id], limit: 1)

    case newest do
      nil ->
        true

      inserted_at ->
        rotated_at =
          DateTime.shift(to_utc(inserted_at), day: Map.fetch!(@rotation_days, rotation()))

        DateTime.compare(now, rotated_at) != :lt
    end
  end

  defp load_state(name) do
    state =
      case Repo.all(from s in "salts", select: s.salt, order_by: [desc: s.id], limit: 2) do
        [current, prev] -> %{previous: prev, current: current}
        [current] -> %{previous: nil, current: current}
      end

    true = :ets.insert(name, {:state, state})
  end

  defp to_utc(%DateTime{} = dt), do: dt
  defp to_utc(%NaiveDateTime{} = dt), do: DateTime.from_naive!(dt, "Etc/UTC")

  defp generate_and_persist_new_salt(now) do
    salt = :crypto.strong_rand_bytes(16)
    Repo.insert_all("salts", [%{salt: salt, inserted_at: now}])
    salt
  end

  # Deletes salts older than the retention, except the current and the
  # previous salt: after a missed rotation the previous salt may be older
  # than the retention, but it was only just retired.
  defp clean_old_salts(now) do
    cutoff = DateTime.shift(now, day: -retention_days(rotation()))
    newest_two = from(s in "salts", select: s.id, order_by: [desc: s.id], limit: 2)

    Repo.delete_all(
      from s in "salts", where: s.inserted_at < ^cutoff and s.id not in subquery(newest_two)
    )
  end
end
