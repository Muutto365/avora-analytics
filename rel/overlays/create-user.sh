#!/bin/sh
# Creates a user account. See "Creating accounts" in README.md.

BIN_DIR=$(dirname "$0")

"${BIN_DIR}"/bin/plausible eval Plausible.Release.create_user
