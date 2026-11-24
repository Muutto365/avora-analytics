defmodule PlausibleWeb.Components.Layout do
  @moduledoc false

  use Phoenix.Component
  use Gettext, backend: PlausibleWeb.Gettext

  def favicon(assigns) do
    ~H"""
    <link
      rel="icon"
      type="image/svg+xml"
      href={PlausibleWeb.Router.Helpers.static_path(@conn, logo_path("favicon.svg"))}
    />
    <link
      rel="apple-touch-icon"
      sizes="180x180"
      href={PlausibleWeb.Router.Helpers.static_path(@conn, logo_path("apple-touch-icon.png"))}
    />
    <link
      rel="icon"
      type="image/png"
      sizes="32x32"
      href={PlausibleWeb.Router.Helpers.static_path(@conn, logo_path("favicon-32x32.png"))}
    />
    <link
      rel="icon"
      type="image/png"
      sizes="16x16"
      href={PlausibleWeb.Router.Helpers.static_path(@conn, logo_path("favicon-16x16.png"))}
    />
    """
  end

  def theme_script(assigns) do
    ~H"""
    <script blocking="rendering">
      (function(){
        var themePref = '<%= theme_preference(assigns) %>';
        function reapplyTheme() {
          var darkMediaPref = window.matchMedia('(prefers-color-scheme: dark)').matches;
          var htmlRef = document.querySelector('html');
          var hcaptchaRefs = Array.from(document.getElementsByClassName('h-captcha'));

          var isDark = themePref === 'dark' || (themePref === 'system' && darkMediaPref);

          if (isDark) {
              htmlRef.classList.add('dark')
              hcaptchaRefs.forEach(function(ref) { ref.dataset.theme = "dark"; });
          } else {
              htmlRef.classList.remove('dark');
              hcaptchaRefs.forEach(function(ref) { ref.dataset.theme = "light"; });
          }
        }

        reapplyTheme();
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', reapplyTheme);
      })()
    </script>
    """
  end

  attr(:selected_fn, :any, required: true)
  attr(:prefix, :string, default: "")
  attr(:options, :list, required: true)

  def settings_sidebar(assigns) do
    ~H"""
    <div class="flex flex-col gap-0.5 -ml-2" data-testid="settings-sidebar">
      <.settings_top_tab
        :for={%{key: key, value: value, icon: icon} = opts <- @options}
        selected_fn={@selected_fn}
        prefix={@prefix}
        icon={icon}
        text={key}
        badge={opts[:badge]}
        value={value}
      />
    </div>
    """
  end

  attr(:selected_fn, :any)
  attr(:prefix, :string, default: "")
  attr(:icon, :any, default: nil)
  attr(:text, :string, required: true)
  attr(:badge, :any, default: nil)
  attr(:value, :any, default: nil)

  defp settings_top_tab(assigns) do
    ~H"""
    <%= if is_binary(@value) do %>
      <.settings_tab
        selected_fn={@selected_fn}
        prefix={@prefix}
        icon={@icon}
        text={@text}
        badge={@badge}
        value={@value}
      />
    <% else %>
      <.settings_tab icon={@icon} text={@text} />

      <div class="flex flex-col gap-0.5 ml-7">
        <.settings_tab
          :for={%{key: key, value: value} = opts <- @value}
          selected_fn={@selected_fn}
          prefix={@prefix}
          icon={nil}
          text={key}
          badge={opts[:badge]}
          value={value}
          submenu?={true}
        />
      </div>
    <% end %>
    """
  end

  attr(:selected_fn, :any, default: nil)
  attr(:prefix, :string, default: "")
  attr(:value, :any, default: nil)
  attr(:icon, :any, default: nil)
  attr(:submenu?, :boolean, default: false)
  attr(:text, :string, required: true)
  attr(:badge, :any, default: nil)

  defp settings_tab(assigns) do
    current_tab? = assigns[:selected_fn] != nil and assigns.selected_fn.(assigns[:value])
    assigns = assign(assigns, :current_tab?, current_tab?)

    ~H"""
    <a
      href={@value && @prefix <> "/settings/" <> @value}
      class={[
        "text-sm flex items-center px-2 py-2 leading-5 font-medium rounded-md outline-none focus:outline-none transition ease-in-out duration-150",
        @current_tab? &&
          "text-gray-900 dark:text-gray-100 bg-gray-150 font-semibold dark:bg-gray-850 hover:text-gray-900 dark:hover:text-gray-100 focus:bg-gray-200 dark:focus:bg-gray-800",
        @value && not @current_tab? &&
          "text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-850 focus:text-gray-900 focus:bg-gray-50 dark:focus:text-gray-100 dark:focus:bg-gray-800",
        !@value && "text-gray-600 dark:text-gray-300"
      ]}
    >
      <PlausibleWeb.Components.Generic.dynamic_icon
        :if={not @submenu? && @icon}
        name={@icon}
        class="size-5 mr-2"
      />
      {@text}
      <PlausibleWeb.Components.Generic.pill :if={@badge == :new} color={:indigo} class="ml-2">
        NEW 🔥
      </PlausibleWeb.Components.Generic.pill>
      <Heroicons.chevron_down
        :if={is_nil(@value)}
        class="h-3 w-3 ml-2 text-gray-400 dark:text-gray-500"
      />
    </a>
    """
  end

  defp theme_preference(%{theme: theme}) when not is_nil(theme), do: theme

  defp theme_preference(%{current_user: %Plausible.Auth.User{theme: theme}})
       when not is_nil(theme) do
    theme
  end

  defp theme_preference(_assigns), do: "system"

  attr :conn, :map, required: true

  @doc """
  Finnish/English switch. Each link posts the choice (with the CSRF token),
  which is kept in a cookie that holds only the language code, and returns
  to the current page.
  """
  def language_switch(assigns) do
    assigns =
      assign(assigns,
        current: assigns.conn.assigns[:locale] || PlausibleWeb.Locale.default(),
        return_to: return_to(assigns.conn)
      )

    ~H"""
    <nav class="flex items-center gap-1 text-xs font-medium" aria-label={gettext("Language")}>
      <.link
        :for={{code, label, name} <- [{"fi", "FI", "Suomi"}, {"en", "EN", "English"}]}
        href={"/locale?" <> URI.encode_query(%{"locale" => code, "return_to" => @return_to})}
        method="post"
        lang={code}
        title={name}
        aria-current={if @current == code, do: "true"}
        class={[
          "rounded-md px-2 py-1 transition-colors duration-150",
          if(@current == code,
            do: "bg-gray-150 text-gray-900 dark:bg-gray-750 dark:text-gray-100",
            else: "text-gray-500 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-100"
          )
        ]}
      >
        {label}
      </.link>
    </nav>
    """
  end

  defp return_to(conn) do
    case conn.query_string do
      "" -> conn.request_path
      query -> conn.request_path <> "?" <> query
    end
  end

  defdelegate logo_path(path), to: PlausibleWeb.LayoutView
end
