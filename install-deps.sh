#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Debe ejecutarse como root: sudo bash $0"
  exit 1
fi

apt update -y
DEBIAN_FRONTEND=noninteractive apt install -y iptables iproute2 iptables-persistent
