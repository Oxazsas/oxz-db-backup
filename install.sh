#!/usr/bin/env bash
# install.sh — Installeur pour oxz-db-backup
# Rôle : Installe les scripts oxz-db-backup, migre les configs existantes et configure le système.
# Version : 1.0

set -euo pipefail
IFS=$'\n\t'

# === Configuration ===
readonly APP_NAME="oxz-db-backup"
readonly OLD_APP_NAME="db-backup"

readonly INSTALL_DIR_DEFAULT="/usr/local/lib/${APP_NAME}"
readonly BIN_DIR="/usr/local/bin"
readonly BIN_NAME="${APP_NAME}"

# Dossiers système FHS
readonly ETC_DIR="/etc/${APP_NAME}"
readonly VAR_LIB="/var/lib/${APP_NAME}"
readonly VAR_LOG="/var/log/${APP_NAME}"
readonly VAR_BACKUP="/var/backups/${APP_NAME}"

# Dossiers legacy pour migration
readonly OLD_ETC_DIR="/etc/${OLD_APP_NAME}"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# === Variables Globales ===
DRY_RUN=false
FORCE=false
MIGRATE_MODE="copy" # none, copy, move
INSTALL_DIR="${INSTALL_DIR_DEFAULT}"

# === Fonctions Utilitaires ===

log_info() { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
log_ok()   { printf "${GREEN}[OK]${NC}   %s\n" "$*"; }
log_warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
log_err()  { printf "${RED}[ERR]${NC}  %s\n" "$*" >&2; }

die() {
  log_err "$1"
  exit 1
}

# Vérifie si une commande existe
check_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    die "Dépendance manquante : $1. Installez-la via apt (jq, age, zstd, rsync, mysql-client)."
  fi
}

# Exécute une commande ou l'affiche en dry-run
run() {
  if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] $*"
  else
    "$@"
  fi
}

# === Pré-vérifications ===

pre_checks() {
  log_info "Vérification des prérequis..."

  # 1. Root
  if [ "$(id -u)" -ne 0 ]; then
    die "Ce script doit être exécuté en root (sudo)."
  fi

  # 2. Fichiers sources
  local files=("db-backup-wizard.sh" "db-backup-runner.sh" "db-backup-restore.sh")
  for f in "${files[@]}"; do
    if [ ! -f "./$f" ]; then
      die "Fichier source introuvable : ./$f. Lancez install.sh depuis le dossier contenant les scripts."
    fi
    # Syntax check
    if ! bash -n "./$f"; then
      die "Erreur de syntaxe détectée dans $f."
    fi
    # Check CRLF
    if file "./$f" | grep -q 'CRLF'; then
      die "Fichier $f contient des retours à la ligne DOS (CRLF). Convertissez-le (dos2unix)."
    fi
  done

  # 3. Dépendances
  check_cmd jq
  check_cmd age
  check_cmd zstd
  check_cmd rsync
  check_cmd mysql   # mysql-client

  log_ok "Prérequis validés."
}

# === Installation Système ===

install_files() {
  log_info "Installation dans ${INSTALL_DIR}..."

  if [ -d "${INSTALL_DIR}" ] && [ "$FORCE" = false ]; then
    log_warn "Le répertoire d'installation ${INSTALL_DIR} existe déjà."
    log_warn "Utilisez --force pour écraser."
    exit 1
  fi

  # Création du dossier d'installation
  run mkdir -p "${INSTALL_DIR}"
  
  # Copie des scripts
  run cp ./db-backup-wizard.sh "${INSTALL_DIR}/"
  run cp ./db-backup-runner.sh "${INSTALL_DIR}/"
  run cp ./db-backup-restore.sh "${INSTALL_DIR}/"

  # Permissions sécurisées
  run chown -R root:root "${INSTALL_DIR}"
  run chmod 0755 "${INSTALL_DIR}"
  run chmod 0755 "${INSTALL_DIR}"/*.sh

  # Wrapper binaire global
  log_info "Création de la commande ${BIN_NAME}..."
  
  if [ "$DRY_RUN" = false ]; then
    cat <<EOF > "${BIN_DIR}/${BIN_NAME}"
#!/bin/bash
exec "${INSTALL_DIR}/db-backup-wizard.sh" "\$@"
EOF
    chmod +x "${BIN_DIR}/${BIN_NAME}"
  else
    echo "[DRY-RUN] Création du wrapper ${BIN_DIR}/${BIN_NAME}"
  fi

  log_ok "Fichiers installés."
}

setup_namespaces() {
  log_info "Création des répertoires de données..."

  # /etc/oxz-db-backup (Config)
  run mkdir -p "${ETC_DIR}/jobs"
  run mkdir -p "${ETC_DIR}/keys"
  run mkdir -p "${ETC_DIR}/secrets"
  
  # Permissions secrets
  run chmod 0700 "${ETC_DIR}/secrets"
  run chmod 0700 "${ETC_DIR}/keys" # Les clés privées y sont temporairement ou non, sécurité max

  # /var/lib/oxz-db-backup (State)
  run mkdir -p "${VAR_LIB}/state"

  # /var/log/oxz-db-backup (Logs)
  run mkdir -p "${VAR_LOG}"
  run chmod 0750 "${VAR_LOG}"

  # /var/backups/oxz-db-backup (Stockage local)
  run mkdir -p "${VAR_BACKUP}/.tmp"
  
  log_ok "Structure de dossiers créée."
}

# === Migration ===

migrate_legacy() {
  if [ ! -d "${OLD_ETC_DIR}" ]; then
    return # Rien à migrer
  fi

  if [ "${MIGRATE_MODE}" == "none" ]; then
    log_info "Ancienne configuration détectée dans ${OLD_ETC_DIR}, mais migration désactivée (--migrate none)."
    return
  fi
  
  # Si le mode est par défaut "copy" (auto) mais qu'on a détecté une vieille config
  # et qu'on est en interactif, on demande confirmation/choix
  if [ "${MIGRATE_MODE}" == "copy" ] && [ -t 0 ]; then
     echo ""
     log_warn "Une ancienne configuration a été trouvée dans ${OLD_ETC_DIR}."
     echo "Que voulez-vous faire ?"
     echo "  [1] Copier vers ${ETC_DIR} (Défaut - Sûr)"
     echo "  [2] Déplacer vers ${ETC_DIR} (Supprime l'ancien)"
     echo "  [3] Ne rien faire (Ignorer)"
     read -r -p "Choix [1]: " ans
     case "$ans" in
       2) MIGRATE_MODE="move" ;;
       3) MIGRATE_MODE="none" ;;
       *) MIGRATE_MODE="copy" ;;
     esac
     echo ""
  fi

  if [ "${MIGRATE_MODE}" == "none" ]; then
    return
  fi

  log_info "Migration des configurations depuis ${OLD_ETC_DIR} (Mode: ${MIGRATE_MODE})..."

  # Fonction interne de copie/move
  do_migrate() {
    local src="$1"
    local dest="$2"
    if [ -d "$src" ] && [ "$(ls -A "$src")" ]; then
       log_info "Integration de $src vers $dest..."
       # On utilise rsync pour merger proprement sans écraser brutalement si existant
       run rsync -a "$src/" "$dest/"
       if [ "${MIGRATE_MODE}" == "move" ]; then
         run rm -rf "$src"
       fi
    fi
  }

  do_migrate "${OLD_ETC_DIR}/jobs" "${ETC_DIR}/jobs"
  do_migrate "${OLD_ETC_DIR}/keys" "${ETC_DIR}/keys"
  do_migrate "${OLD_ETC_DIR}/secrets" "${ETC_DIR}/secrets"
  
  # Migration du state (important pour history)
  if [ -d "/var/lib/${OLD_APP_NAME}/state" ]; then
    do_migrate "/var/lib/${OLD_APP_NAME}/state" "${VAR_LIB}/state"
  fi

  log_ok "Migration terminée."
}

# === Logrotate ===

setup_logrotate() {
  log_info "Configuration de logrotate..."
  local lr_file="/etc/logrotate.d/${APP_NAME}"
  
  if [ "$DRY_RUN" = false ]; then
    cat <<EOF > "${lr_file}"
${VAR_LOG}/*.log
${VAR_LOG}/*.out
${VAR_LOG}/*.err
{
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        # Si le runner tourne, il logue via redirection, pas besoin de reload daemon
        true
    endscript
}
EOF
    chmod 0644 "${lr_file}"
  else
    echo "[DRY-RUN] Création fichier ${lr_file}"
  fi
  log_ok "Logrotate configuré."
}

# === Help ===

usage() {
  cat <<EOF
Usage: ./install.sh [OPTIONS]

Installe oxz-db-backup sur le système.

Options:
  --install-dir DIR   Répertoire d'installation (Défaut: ${INSTALL_DIR_DEFAULT})
  --migrate MODE      Mode de migration pour les anciennes configs 'db-backup'
                      Modes: copy (défaut), move, none
  --force             Forcer l'installation même si le dossier existe déjà
  --dry-run           Affiche les commandes sans les exécuter
  --help              Affiche cette aide

EOF
  exit 0
}

# === Main ===

while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --install-dir)
      INSTALL_DIR="$2"
      shift; shift
      ;;
    --migrate)
      MIGRATE_MODE="$2"
      shift; shift
      ;;
    --force)
      FORCE=true
      shift
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --help|-h)
      usage
      ;;
    *)
      log_err "Option inconnue : $1"
      usage
      ;;
  esac
done

echo "========================================"
echo "    Installation de ${APP_NAME}       "
echo "========================================"

pre_checks
setup_namespaces
migrate_legacy
install_files
setup_logrotate

echo ""
log_ok "Installation terminée avec succès !"
log_info "Vous pouvez maintenant utiliser la commande : ${BIN_NAME}"
log_info "Les fichiers de config sont dans : ${ETC_DIR}"
