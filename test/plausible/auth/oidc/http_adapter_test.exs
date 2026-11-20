defmodule Plausible.Auth.OIDC.HTTPAdapterTest do
  # Fork addition
  use ExUnit.Case, async: true

  alias Plausible.Auth.OIDC.HTTPAdapter

  @public "https://id.example.com/tenant"
  @internal "http://id.internal:8080/tenant"

  test "sends requests for the public issuer to the internal address" do
    assert {"http://id.internal:8080/tenant/protocol/token", [], ~c"ct", "body"} ==
             HTTPAdapter.rewrite(
               {"https://id.example.com/tenant/protocol/token", [], ~c"ct", "body"},
               @public,
               @internal
             )

    assert {"http://id.internal:8080/tenant/.well-known/openid-configuration", []} ==
             HTTPAdapter.rewrite(
               {~c"https://id.example.com/tenant/.well-known/openid-configuration", []},
               @public,
               @internal
             )
  end

  test "leaves other URLs alone" do
    for url <- ["https://id.example.com/tenantx/keys", "https://other.example.com/tenant/keys"] do
      assert {url, []} == HTTPAdapter.rewrite({url, []}, @public, @internal)
    end

    assert {"https://id.example.com/tenant/keys", []} ==
             HTTPAdapter.rewrite({"https://id.example.com/tenant/keys", []}, @public, nil)
  end
end
