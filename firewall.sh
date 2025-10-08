#!/usr/bin/env bash
set -euo pipefail

# === Archivos estándar al lado del script ===
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MAC_FILE="${SCRIPT_DIR}/acceso.mac"
IP_FILE="${SCRIPT_DIR}/acceso.ip"

SSH_PORT=22

# --- Utilidades ---
sanitize_line() {
  local s
  s="$(echo "$1" | sed 's/#.*//;s/^\s*//;s/\s*$//')"
  echo "$s"
}

is_mac() {
  # aa:bb:cc:dd:ee:ff
  [[ "$1" =~ ^([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}$ ]]
}

is_ip_or_cidr() {
  # 1.2.3.4 o 1.2.3.0/24
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]
}

# --- Inicialización base ---
initialize_firewall() {
  iptables -F
  iptables -t nat -F
  iptables -t mangle -F

  iptables -X
  iptables -t nat -X
  iptables -t mangle -X

  iptables -P INPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT

  # Mantener SSH accesible
  iptables -A INPUT -p tcp --dport ${SSH_PORT} -j ACCEPT
  iptables -A FORWARD -p tcp --dport ${SSH_PORT} -j ACCEPT

  # Política por defecto: todo cerrado en INPUT/FORWARD
  iptables -P INPUT DROP
  iptables -P FORWARD DROP

  echo "Base de firewall aplicada (SSH:${SSH_PORT} permitido, INPUT/FORWARD en DROP)."
}

# --- Reglas por MAC ---
allow_mac() {
  local mac="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  # Quita bloqueos previos de esa MAC
  iptables -D INPUT   -m mac --mac-source "$mac" -j DROP 2>/dev/null || true
  iptables -D FORWARD -m mac --mac-source "$mac" -j DROP 2>/dev/null || true
  # Permite
  iptables -A INPUT   -m mac --mac-source "$mac" -j ACCEPT
  iptables -A FORWARD -m mac --mac-source "$mac" -j ACCEPT
  echo "✓ MAC permitida: $mac"
}

block_mac() {
  local mac="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  # Quita allows previos de esa MAC
  iptables -D INPUT   -m mac --mac-source "$mac" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -m mac --mac-source "$mac" -j ACCEPT 2>/dev/null || true
  # Bloquea
  iptables -A INPUT   -m mac --mac-source "$mac" -j DROP
  iptables -A FORWARD -m mac --mac-source "$mac" -j DROP
  echo "✓ MAC bloqueada: $mac"
}

# --- Reglas por IP/CIDR ---
allow_ip() {
  local ip="$1"
  # Quita bloqueos previos de esa IP/red
  iptables -D INPUT   -s "$ip" -j DROP 2>/dev/null || true
  iptables -D FORWARD -s "$ip" -j DROP 2>/dev/null || true
  iptables -D FORWARD -d "$ip" -j DROP 2>/dev/null || true
  # Permite (INPUT como origen; FORWARD como origen y como destino)
  iptables -A INPUT   -s "$ip" -j ACCEPT
  iptables -A FORWARD -s "$ip" -j ACCEPT
  iptables -A FORWARD -d "$ip" -j ACCEPT
  echo "✓ IP/CIDR permitida: $ip"
}

block_ip() {
  local ip="$1"
  # Quita allows previos de esa IP/red
  iptables -D INPUT   -s "$ip" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -s "$ip" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -d "$ip" -j ACCEPT 2>/dev/null || true
  # Bloquea
  iptables -A INPUT   -s "$ip" -j DROP
  iptables -A FORWARD -s "$ip" -j DROP
  iptables -A FORWARD -d "$ip" -j DROP
  echo "✓ IP/CIDR bloqueada: $ip"
}

# --- Procesadores de archivos ---
allow_from_files() {
  # MACs
  if [[ -f "$MAC_FILE" ]]; then
    while IFS= read -r line; do
      local mac="$(sanitize_line "$line" | tr '[:upper:]' '[:lower:]')"
      [[ -z "$mac" ]] && continue
      if is_mac "$mac"; then allow_mac "$mac"; fi
    done < "$MAC_FILE"
  else
    echo "(No existe ${MAC_FILE}, omitiendo MACs)"
  fi

  # IPs
  if [[ -f "$IP_FILE" ]]; then
    while IFS= read -r line; do
      local ip="$(sanitize_line "$line")"
      [[ -z "$ip" ]] && continue
      if is_ip_or_cidr "$ip"; then allow_ip "$ip"; fi
    done < "$IP_FILE"
  else
    echo "(No existe ${IP_FILE}, omitiendo IPs)"
  fi
}

block_from_files() {
  # MACs
  if [[ -f "$MAC_FILE" ]]; then
    while IFS= read -r line; do
      local mac="$(sanitize_line "$line" | tr '[:upper:]' '[:lower:]')"
      [[ -z "$mac" ]] && continue
      if is_mac "$mac"; then block_mac "$mac"; fi
    done < "$MAC_FILE"
  else
    echo "(No existe ${MAC_FILE}, omitiendo MACs)"
  fi

  # IPs
  if [[ -f "$IP_FILE" ]]; then
    while IFS= read -r line; do
      local ip="$(sanitize_line "$line")"
      [[ -z "$ip" ]] && continue
      if is_ip_or_cidr "$ip"; then block_ip "$ip"; fi
    done < "$IP_FILE"
  else
    echo "(No existe ${IP_FILE}, omitiendo IPs)"
  fi
}

persist_rules() {
  if command -v iptables-save >/dev/null 2>&1; then
    mkdir -p /etc/iptables
    iptables-save  > /etc/iptables/rules.v4
  fi
  if command -v ip6tables-save >/dev/null 2>&1; then
    ip6tables-save > /etc/iptables/rules.v6 || true
  fi
}

usage() {
  cat <<USAGE
Uso:
  $(basename "$0") allow                # inicializa + permite todo lo listado en acceso.mac / acceso.ip
  $(basename "$0") block                # inicializa + bloquea todo lo listado en acceso.mac / acceso.ip

  $(basename "$0") allow mac <MAC>      # inicializa + permite esa MAC (y listas)
  $(basename "$0") allow ip  <IP/CIDR>  # inicializa + permite esa IP/red (y listas)
  $(basename "$0") block mac <MAC>      # inicializa + bloquea esa MAC (y listas)
  $(basename "$0") block ip  <IP/CIDR>  # inicializa + bloquea esa IP/red (y listas)

  # Modo autodetección (MAC vs IP/CIDR) si pasas solo el valor:
  $(basename "$0") allow <MAC|IP/CIDR>
  $(basename "$0") block <MAC|IP/CIDR>

Archivos (si existen, se aplican además del valor directo):
  ${MAC_FILE}  (una MAC por línea, ej: aa:bb:cc:dd:ee:ff)
  ${IP_FILE}   (una IP o CIDR por línea, ej: 192.168.1.23 o 10.0.0.0/24)
USAGE
}

main() {
  local action="${1:-}"
  local type="${2:-}"
  local value="${3:-}"

  case "$action" in
    allow|block)
      initialize_firewall

      if [[ -n "$value" ]]; then
        if [[ "$type" == "mac" ]]; then
          is_mac "$value" || { echo "MAC inválida: $value"; exit 1; }
          [[ "$action" == "allow" ]] && allow_mac "$value" || block_mac "$value"
        elif [[ "$type" == "ip" ]]; then
          is_ip_or_cidr "$value" || { echo "IP/CIDR inválida: $value"; exit 1; }
          [[ "$action" == "allow" ]] && allow_ip "$value" || block_ip "$value"
        else
          # Autodetect con $2 si no vino 'mac'/'ip'
          if is_mac "$type"; then
            [[ "$action" == "allow" ]] && allow_mac "$type" || block_mac "$type"
          elif is_ip_or_cidr "$type"; then
            [[ "$action" == "allow" ]] && allow_ip "$type" || block_ip "$type"
          fi
        fi
      elif [[ -n "$type" ]]; then
        # Modo autodetección cuando hay solo 2 args: allow <valor> / block <valor>
        if is_mac "$type"; then
          [[ "$action" == "allow" ]] && allow_mac "$type" || block_mac "$type"
        elif is_ip_or_cidr "$type"; then
          [[ "$action" == "allow" ]] && allow_ip "$type" || block_ip "$type"
        elif [[ "$type" == "mac" || "$type" == "ip" ]]; then
          echo "Falta valor para '$type'"; usage; exit 1
        fi
      fi

      # Luego aplica listas de archivos
      if [[ "$action" == "allow" ]]; then
        allow_from_files
      else
        block_from_files
      fi

      persist_rules
      ;;

    ""|-h|--help|help)
      usage
      ;;

    *)
      echo "Acción inválida: $action"
      usage
      exit 1
      ;;
  esac
}

main "$@"
