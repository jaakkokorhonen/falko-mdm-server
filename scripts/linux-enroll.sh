#!/usr/bin/env bash
# Falko MDM Linux enrollment bootstrap script.
# Usage: sudo bash scripts/linux-enroll.sh --token <one_time_token> [--server <url>]
# Requires: bash 4+, Python 3.9+, systemd, curl
# Tested on: Ubuntu 22.04, Ubuntu 24.04
# Ref: LINUX.md — Enrollment section, issue #43
set -euo pipefail

FALKO_SERVER="${FALKO_SERVER:-https://mdm-api.falko.fi}"
ONE_TIME_TOKEN=""

# --- argument parsing ---
while [[ $# -gt 0 ]]; do
  case $1 in
    --token)
      ONE_TIME_TOKEN="$2"
      shift 2
      ;;
    --server)
      FALKO_SERVER="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$ONE_TIME_TOKEN" ]]; then
  echo "Error: --token is required" >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Error: Run as root (sudo)" >&2
  exit 1
fi

echo "Initializing Falko MDM Linux Enrollment bootstrap..."
# (Real implementation will download the agent, setup directories, and write the token file)
