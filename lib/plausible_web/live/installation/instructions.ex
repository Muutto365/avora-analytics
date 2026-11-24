defmodule PlausibleWeb.Live.Installation.Instructions do
  @moduledoc """
  Instruction forms and components for the Installation module
  """
  use PlausibleWeb, :component

  @doc """
  The fallback snippet for a domain whose pages we do not serve, or nil when
  no script URL is configured.
  """
  def fallback_snippet(domain) do
    case Application.get_env(:plausible, :fallback_tracker_script_url) do
      url when is_binary(url) ->
        src = url <> "?" <> URI.encode_query(%{"d" => domain})
        ~s(<script defer src="#{src}"></script>)

      _ ->
        nil
    end
  end

  def automatic_installation_note(assigns) do
    ~H"""
    <div class="text-sm mt-4 leading-6">
      {gettext(
        "On domains Avora hosts, analytics is added to every page automatically. There is nothing to install."
      )}
    </div>
    """
  end

  attr :tracker_script_configuration_form, :map, required: true
  attr :snippet, :string, default: nil

  def manual_instructions(assigns) do
    ~H"""
    <.title class="mt-4">
      {gettext("Installation")}
    </.title>

    <.automatic_installation_note />

    <div :if={@snippet}>
      <div class="text-sm my-4 leading-6">
        {gettext(
          "For a domain Avora does not host, paste this snippet into the site's <head> section. Once done, click the button below to verify the installation."
        )}
      </div>

      <.snippet_form text={@snippet} rows={2} resizable={true} />

      <div class="text-sm mt-2 leading-6 text-gray-600 dark:text-gray-400">
        {gettext("Visits are counted once Avora staff have registered the domain.")}
      </div>
    </div>
    <.h2 class="mt-8 text-sm font-medium">{gettext("Optional measurements")}</.h2>
    <.script_config_control
      field={@tracker_script_configuration_form[:outbound_links]}
      label={gettext("Outbound links")}
      tooltip={gettext("Automatically track clicks on external links.")}
    />
    <.script_config_control
      field={@tracker_script_configuration_form[:file_downloads]}
      label={gettext("File downloads")}
      tooltip={gettext("Automatically track file downloads.")}
    />
    <.script_config_control
      field={@tracker_script_configuration_form[:form_submissions]}
      label={gettext("Form submissions")}
      tooltip={gettext("Automatically track form submissions.")}
    />

    <.disclosure>
      <.disclosure_button class="mt-4 flex items-center group">
        <.h2 class="text-sm font-medium">{gettext("Advanced options")}</.h2>
        <Heroicons.chevron_down mini class="size-4 ml-1 mt-0.5 group-data-[open=true]:rotate-180" />
      </.disclosure_button>
      <.disclosure_panel>
        <ul class="list-disc list-inside mt-2 space-y-2">
          <.advanced_option
            variant="tagged-events"
            label={gettext("Manual tagging")}
            tooltip={
              gettext(
                "Tag site elements like buttons, links and forms to track user activity. Additional action required."
              )
            }
          />
          <.advanced_option
            variant="404"
            label={gettext("404 error pages")}
            tooltip={gettext("Find 404 error pages on your site. Additional action required.")}
          />
          <.advanced_option
            variant="hash"
            label={gettext("Hashed page paths")}
            tooltip={gettext("Automatically track page paths that use a # in the URL.")}
          />
          <.advanced_option
            variant="pageview-props"
            label={gettext("Custom properties")}
            tooltip={
              gettext(
                "Attach custom properties (also known as custom dimensions) to pageviews or custom events to create custom metrics. Additional action required."
              )
            }
          />
          <.advanced_option
            variant="revenue"
            label={gettext("Ecommerce revenue")}
            tooltip={
              gettext(
                "Assign monetary values to purchases and track revenue attribution. Additional action required."
              )
            }
          />
        </ul>
      </.disclosure_panel>
    </.disclosure>
    """
  end

  attr :recommended_installation_type, :string, required: true
  attr :tracker_script_configuration_form, :map, required: true

  def gtm_instructions(assigns) do
    ~H"""
    <.title class="mt-4">
      Tag Manager installation
    </.title>
    <div class="text-sm mt-4 leading-6">
      <span :if={@recommended_installation_type == "gtm"}>
        We've detected your website is using Google Tag Manager. Here's how to integrate Avora Analytics:
      </span>
      <span :if={@recommended_installation_type != "gtm"}>
        Using Google Tag Manager? Here's how to integrate Avora Analytics:
      </span>
      <div class="mt-4">
        <.focus_list>
          <:item>
            Copy your site's Script ID:
            <.snippet_form
              text={@tracker_script_configuration_form.data.id}
              rows={1}
              resizable={false}
            />
          </:item>

          <:item>
            Add a Custom HTML tag with the script snippet to your container, triggered on all pages.
          </:item>

          <:item>
            Publish the container and click the button below to verify your installation.
          </:item>
        </.focus_list>
      </div>
    </div>
    """
  end

  attr :field, :any, required: true
  attr :label, :string, required: true
  attr :tooltip, :string, required: true

  defp script_config_control(assigns) do
    ~H"""
    <div class="mt-2 p-1 text-sm">
      <div class="flex items-center">
        <.input mt?={false} field={@field} label={@label} type="checkbox" />
        <.info_tooltip text={@tooltip} />
      </div>
    </div>
    """
  end

  attr :label, :string, required: true
  attr :tooltip, :string, required: true
  attr :variant, :string, default: nil

  defp advanced_option(assigns) do
    ~H"""
    <li class="p-1 text-sm">
      <div class="inline-flex items-center">
        <div>{@label}</div>
        <.info_tooltip text={@tooltip} />
      </div>
    </li>
    """
  end

  attr :text, :string, required: true

  defp info_tooltip(assigns) do
    ~H"""
    <div class="ml-2">
      <.tooltip sticky?={false}>
        <:tooltip_content>
          {@text}
        </:tooltip_content>
        <Heroicons.information_circle
          class="inline-block text-indigo-700 dark:text-gray-500 size-5"
          aria-label={@text}
        />
      </.tooltip>
    </div>
    """
  end

  defp snippet_form(assigns) do
    ~H"""
    <div class="relative">
      <textarea
        id="snippet"
        class={"w-full border-1 border-gray-300 rounded-md p-4 text-sm text-gray-700 dark:border-gray-750 dark:bg-gray-750 dark:text-gray-300 #{if !@resizable, do: "resize-none"}"}
        rows={@rows}
        readonly
      ><%= @text %></textarea>

      <a
        onclick="var input = document.getElementById('snippet'); input.focus(); input.select(); document.execCommand('copy'); event.stopPropagation();"
        href="javascript:void(0)"
        class="absolute flex items-center text-xs font-medium text-indigo-600 no-underline bottom-2 right-4 p-2 bg-white transition-colors duration-150 hover:text-indigo-700 dark:text-indigo-500 dark:hover:text-indigo-400 dark:bg-gray-750"
      >
        <Heroicons.document_duplicate class="pr-1 text-current size-5" />
        <span>
          {gettext("COPY")}
        </span>
      </a>
    </div>
    """
  end
end
