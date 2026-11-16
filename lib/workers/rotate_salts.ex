defmodule Plausible.Workers.RotateSalts do
  use Plausible.Repo
  use Oban.Worker, queue: :rotate_salts

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"if_due" => true}}) do
    Plausible.Session.Salts.rotate_if_due()
    :ok
  end

  def perform(_job) do
    Plausible.Session.Salts.rotate()
  end
end
