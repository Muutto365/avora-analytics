defmodule PlausibleWeb.Gettext do
  @moduledoc """
  Translations for the user interface (English source strings, Finnish in
  `priv/gettext/fi`). See `PlausibleWeb.Locale` for how the language is chosen.
  """
  use Gettext.Backend, otp_app: :plausible, default_locale: "en"
end
