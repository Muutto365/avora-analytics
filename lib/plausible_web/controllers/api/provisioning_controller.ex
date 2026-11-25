defmodule PlausibleWeb.Api.ProvisioningController do
  @moduledoc """
  Internal API for provisioning sites. See `Plausible.Provisioning`.
  """
  use PlausibleWeb, :controller

  require Logger

  alias Plausible.Provisioning

  plug :fetch_owner

  def create_site(conn, params) do
    case Provisioning.create_site(conn.assigns.owner, params) do
      {:ok, :created, site} ->
        Avora.Audit.record(
          action: "site.create",
          principal: Avora.Audit.provisioning_principal(),
          target_type: "site",
          target_id: site.id,
          via: "provisioning"
        )

        conn
        |> put_status(201)
        |> json(%{domain: site.domain, timezone: site.timezone})

      {:ok, :exists, site} ->
        json(conn, %{domain: site.domain, timezone: site.timezone})

      {:error, :domain_taken} ->
        conn
        |> put_status(409)
        |> json(%{error: "Domain is already in use"})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(422)
        |> json(%{error: "Invalid site", details: errors(changeset)})

      {:error, reason} ->
        Logger.warning("Provisioning: site could not be created: #{inspect(reason)}")

        conn
        |> put_status(422)
        |> json(%{error: "Site could not be created"})
    end
  end

  def delete_site(conn, %{"domain" => domain}) do
    with_site(conn, domain, fn site ->
      :ok = Provisioning.delete_site(site)

      Avora.Audit.record(
        action: "site.delete",
        principal: Avora.Audit.provisioning_principal(),
        target_type: "site",
        target_id: site.id,
        via: "provisioning"
      )

      send_resp(conn, 204, "")
    end)
  end

  defp with_site(conn, domain, fun) do
    case Provisioning.get_site(conn.assigns.owner, domain) do
      nil ->
        conn
        |> put_status(404)
        |> json(%{error: "Site not found"})

      site ->
        fun.(site)
    end
  end

  defp fetch_owner(conn, _opts) do
    case Provisioning.owner() do
      nil ->
        conn
        |> put_status(503)
        |> json(%{error: "Provisioning owner is not configured"})
        |> halt()

      owner ->
        assign(conn, :owner, owner)
    end
  end

  defp errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", format_value(value))
      end)
    end)
  end

  defp format_value(value) when is_binary(value) or is_number(value) or is_atom(value),
    do: to_string(value)

  defp format_value(value), do: inspect(value)
end
