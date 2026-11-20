defmodule Plausible.Auth.OIDC.HTTPAdapter do
  @moduledoc """
  HTTP transport for the OIDC client (fork addition).

  Wraps `:httpc` and does two things:

    * verifies TLS peers against the system CA store for `https` requests;
    * when `OIDC_INTERNAL_ISSUER_URL` is set, sends server-to-provider
      requests whose URL starts with the public issuer to the internal
      address instead. Only the transport changes: the discovery document,
      endpoint URLs and the expected `iss` claim stay the public ones.
  """

  @behaviour :oidcc_http_adapter

  @impl true
  def request(method, request, http_options, request_options, config) do
    request = rewrite(request, config[:public_base], config[:internal_base])
    url = request |> elem(0) |> to_string()

    http_options =
      if String.starts_with?(url, "https://") and not Keyword.has_key?(http_options, :ssl) do
        [{:ssl, :httpc.ssl_verify_host_options(true)} | http_options]
      else
        http_options
      end

    :httpc.request(method, request, http_options, request_options, :default)
  end

  @doc false
  def rewrite(request, public_base, internal_base)
      when is_binary(public_base) and is_binary(internal_base) do
    url = request |> elem(0) |> to_string()
    public_base = String.trim_trailing(public_base, "/")

    if url == public_base or String.starts_with?(url, public_base <> "/") do
      new_url =
        String.trim_trailing(internal_base, "/") <> String.replace_prefix(url, public_base, "")

      put_elem(request, 0, new_url)
    else
      request
    end
  end

  def rewrite(request, _public_base, _internal_base), do: request
end
