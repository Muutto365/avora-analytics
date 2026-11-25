defmodule PlausibleWeb.Api.ProvisioningController do
  @moduledoc """
  Internal API for provisioning a tenant's sites (fork addition). See
  `Plausible.Provisioning`.

      PUT    /internal/avora/v1/tenants/:tenant_id/sites/:domain
      GET    /internal/avora/v1/tenants/:tenant_id/sites
      DELETE /internal/avora/v1/tenants/:tenant_id/sites/:domain
      DELETE /internal/avora/v1/tenants/:tenant_id

  Every call is idempotent: repeating it (for example after a timeout,
  with the same `Idempotency-Key`) gives the same state.
  """
  use PlausibleWeb, :controller

  require Logger

  alias Plausible.Provisioning

  plug :fetch_owner
  plug :fetch_tenant

  def put_site(conn, %{"domain" => domain} = params) do
    %{owner: owner, tenant_id: tenant_id} = conn.assigns

    case Provisioning.put_site(owner, tenant_id, domain, params) do
      {:ok, :created, site} ->
        audit("site.create", tenant_id, "site", site.id)

        conn
        |> put_status(201)
        |> json(site_json(site))

      {:ok, :adopted, site} ->
        audit("site.adopt", tenant_id, "site", site.id)
        json(conn, site_json(site))

      {:ok, :exists, site} ->
        json(conn, site_json(site))

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

  def list_sites(conn, _params) do
    %{owner: owner, tenant_id: tenant_id} = conn.assigns
    json(conn, %{sites: Enum.map(Provisioning.list_sites(owner, tenant_id), &site_json/1)})
  end

  def delete_site(conn, %{"domain" => domain}) do
    %{owner: owner, tenant_id: tenant_id} = conn.assigns

    case Provisioning.get_site(owner, tenant_id, domain) do
      nil ->
        conn
        |> put_status(404)
        |> json(%{error: "Site not found"})

      site ->
        :ok = Provisioning.delete_site(site)
        audit("site.delete", tenant_id, "site", site.id)
        send_resp(conn, 204, "")
    end
  end

  # Deletes every site of the tenant; a tenant with no sites left is a
  # success too, so the call can be repeated.
  def delete_tenant(conn, _params) do
    %{owner: owner, tenant_id: tenant_id} = conn.assigns

    for site <- Provisioning.list_sites(owner, tenant_id) do
      :ok = Provisioning.delete_site(site)
      audit("site.delete", tenant_id, "site", site.id)
    end

    audit("tenant.delete", tenant_id, "tenant", tenant_id)
    send_resp(conn, 204, "")
  end

  defp audit(action, tenant_id, target_type, target_id) do
    Avora.Audit.record(
      action: action,
      principal: Avora.Audit.provisioning_principal(),
      tenant_id: tenant_id,
      target_type: target_type,
      target_id: target_id,
      via: "provisioning"
    )
  end

  defp site_json(site),
    do: %{domain: site.domain, timezone: site.timezone, tenant_id: site.tenant_id}

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

  defp fetch_tenant(conn, _opts) do
    case Provisioning.cast_tenant_id(conn.path_params["tenant_id"]) do
      {:ok, tenant_id} ->
        assign(conn, :tenant_id, tenant_id)

      :error ->
        conn
        |> put_status(400)
        |> json(%{error: "Invalid tenant id"})
        |> halt()
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
