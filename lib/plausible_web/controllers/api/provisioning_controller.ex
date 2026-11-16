defmodule PlausibleWeb.Api.ProvisioningController do
  @moduledoc """
  Internal API for provisioning sites. See `Plausible.Provisioning`.
  """
  use PlausibleWeb, :controller

  alias Plausible.Provisioning

  plug :fetch_owner

  def create_site(conn, params) do
    case Provisioning.create_site(conn.assigns.owner, params) do
      {:ok, site} ->
        conn
        |> put_status(201)
        |> json(%{domain: site.domain, timezone: site.timezone})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(422)
        |> json(%{error: "Invalid site", details: errors(changeset)})

      {:error, reason} ->
        conn
        |> put_status(422)
        |> json(%{error: "Site could not be created", details: inspect(reason)})
    end
  end

  def delete_site(conn, %{"domain" => domain}) do
    with_site(conn, domain, fn site ->
      :ok = Provisioning.delete_site(site)
      send_resp(conn, 204, "")
    end)
  end

  def rotate_shared_link(conn, %{"domain" => domain}) do
    with_site(conn, domain, fn site ->
      case Provisioning.rotate_shared_link(site) do
        {:ok, url} ->
          json(conn, %{url: url})

        {:error, reason} ->
          conn
          |> put_status(422)
          |> json(%{error: "Shared link could not be created", details: inspect(reason)})
      end
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
