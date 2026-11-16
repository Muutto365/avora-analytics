defmodule PlausibleWeb.SourceCodeUrlTest do
  use ExUnit.Case, async: false

  alias PlausibleWeb.LayoutView

  setup do
    original = Application.get_env(:plausible, :source_commit)
    on_exit(fn -> Application.put_env(:plausible, :source_commit, original) end)
    :ok
  end

  test "links to the build's commit when known" do
    Application.put_env(:plausible, :source_commit, "0123456789abcdef0123456789abcdef01234567")

    assert LayoutView.source_code_url() ==
             "https://github.com/Muutto365/avora-analytics/tree/0123456789abcdef0123456789abcdef01234567"
  end

  test "falls back to the repository" do
    Application.put_env(:plausible, :source_commit, nil)
    assert LayoutView.source_code_url() == "https://github.com/Muutto365/avora-analytics"
  end
end
