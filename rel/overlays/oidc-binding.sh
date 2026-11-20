#!/bin/sh
# Sets or clears an account's single sign-on binding. See "Single sign-on
# (OIDC)" in README.md.

BIN_DIR=$(dirname "$0")

"${BIN_DIR}"/bin/plausible eval Plausible.Release.oidc_binding
