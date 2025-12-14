#!/usr/bin/env bash
# install.sh — Installeur pour oxz-db-backup (safe + idempotent)
# Version : 1.1

set -euo pipefail
IFS=$'\n\t'
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# === Configuration ===
readonly APP_NAME="oxz-db-backup"
readonly OLD_APP_NAME="db-backup"

readonly INSTALL_DIR_DEFAULT="/usr/local/lib/${APP_NAME}"
readonly BIN_DIR_DEFAULT="/usr/local/bin"
readonly BIN_NAME_DEFAULT="${APP_NAME}"
readonly ALIAS_NAME_DEFAULT="oxzbkp"   # alias sympa (optionnel)

# FHS
readonly ETC_DIR="/etc/${APP_NAME}"
readonly VAR_LIB="/var/lib/${APP_NAME}"
readonly VAR_LOG="/var/log/${APP_NAME}"
readonly VAR_BACKUP="/var/backups/${APP_NAME}"

# Legacy
readonly OLD_ETC_DIR="/etc/${OLD_APP_NAME}"
readonly OLD_VAR_LIB="/var/lib/${OLD_APP_NAME}"
readonly OLD_VAR_LOG="/var/log/${OLD_APP_NAME}"
readonly OLD_VAR_BACKUP="/var/backups/${OLD_APP_NAME}"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# === Variables globales ===
DRY_RUN=false
FORCE=false
UNINSTALL=false
PURGE_DATA=false
MIGRATE_MODE="copy"   # none|copy|move (copy = safe)
INSTALL_DIR="${INSTALL_DIR_DEFAULT}"
BIN_DIR="${BIN_DIR_DEFAULT}"
BIN_NAME="${BIN_NAME_DEFAULT}"
ALIAS_NAME="${ALIAS_NAME_DEFAULT}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
SRC_WIZ="${SCRIPT_DIR}/db-backup-wizard.sh"
SRC_RUN="${SCRIPT_DIR}/db-backup-runner.sh"
SRC_RST="${SCRIPT_DIR}/db-backup-restore.sh"

DST_WIZ=""
DST_RUN=""
DST_RST=""

log_info() { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
log_ok()   { printf "${GREEN}[OK]${NC}   %s\n" "$*"; }
log_warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
log_err()  { printf "${RED}[ERR]${NC}  %s\n" "$*" >&2; }

die() { log_err "$1"; exit 1; }

is_tty() { [ -t 0 ] && [ -t 1 ]; }

run() {
  if [ "$DRY_RUN" = true ]; then
    printf "[DRY-RUN] %q " "$@"
    printf "\n"
  else
    "$@"
  fi
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "Lancez en root (ex: sudo ./install.sh)"
  fi
}

check_cmd() {
  local c="$1"
  command -v "$c" >/dev/null 2>&1 || die "Dépendance manquante: $c"
}

check_one_of() {
  # usage: check_one_of "mysql or mariadb" mysql mariadb
  local label="$1"; shift
  local c
  for c in "$@"; do
    if command -v "$c" >/dev/null 2>&1; then
      return 0
    fi
  done
  die "Dépendance manquante: ${label} (installez un des suivants: $*)"
}

has_crlf() {
  # 0 si CRLF détecté
  local f="$1"
  LC_ALL=C grep -n $'\r' "$f" >/dev/null 2>&1
}

print_intro_install() {
  cat >&2 <<EOF

============================================================
${APP_NAME} — install.sh
============================================================

Ce script va :
- Vérifier les prérequis (binaires, syntaxe bash, CRLF)
- Créer les dossiers FHS :
  * ${ETC_DIR} (jobs/keys/secrets)
  * ${VAR_LIB} (state)
  * ${VAR_LOG} (logs)
  * ${VAR_BACKUP} (backups + .tmp)
- Migrer (optionnel) l'existant depuis "${OLD_APP_NAME}" :
  * ${OLD_ETC_DIR} -> ${ETC_DIR}
  * ${OLD_VAR_LIB} -> ${VAR_LIB}
- Installer les 3 scripts dans : ${INSTALL_DIR}
- Créer une commande système : ${BIN_DIR}/${BIN_NAME} (lance le wizard)
- Installer logrotate : /etc/logrotate.d/${APP_NAME}

Par défaut, RIEN n'est supprimé côté legacy (mode migration = copy).
EOF
}

pre_checks() {
  log_info "Préchecks…"

  require_root

  # Fichiers sources
  local files=("$SRC_WIZ" "$SRC_RUN" "$SRC_RST")
  local f
  for f in "${files[@]}"; do
    [ -f "$f" ] || die "Fichier source introuvable: $f (lancez install.sh depuis le dossier des scripts)"
    bash -n "$f" >/dev/null 2>&1 || die "Erreur de syntaxe bash: $(basename "$f")"
    if has_crlf "$f"; then
      die "CRLF détecté dans $(basename "$f") (faites un dos2unix)."
    fi
  done

  # Dépendances utilisées par l’outil (wizard/runner/restore)
  check_cmd jq
  check_cmd age
  check_cmd age-keygen
  check_cmd zstd
  check_cmd rsync
  check_cmd ssh
  check_cmd curl
  check_cmd sha256sum
  check_one_of "mysql or mariadb client" mysql mariadb
  check_one_of "mysqldump or mariadb-dump" mysqldump mariadb-dump
  check_cmd awk
  check_cmd sed
  check_cmd grep

  # Sanity: les scripts doivent *déjà* être renames en namespace oxz-db-backup
  # (sinon vous aurez un wrapper oxz-db-backup qui continue d'écrire dans /etc/db-backup etc.)
  if grep -q 'readonly APP_NAME="db-backup"' "$SRC_WIZ" "$SRC_RUN" "$SRC_RST" 2>/dev/null; then
    log_warn "Au moins un script contient encore: readonly APP_NAME=\"db-backup\""
    log_warn "=> l'installation fonctionnera, MAIS vos scripts utiliseront encore /etc/db-backup/..."
    log_warn "=> faites le renommage APP_NAME dans les 3 scripts avant (ou acceptez ce comportement)."
  fi

  log_ok "Préchecks OK"
}

ensure_dirs() {
  log_info "Création des dossiers FHS…"

  # /etc
  run install -d -m 700 -o root -g root "${ETC_DIR}"
  run install -d -m 700 -o root -g root "${ETC_DIR}/jobs" "${ETC_DIR}/secrets"
  run install -d -m 755 -o root -g root "${ETC_DIR}/keys"

  # /var/lib
  run install -d -m 700 -o root -g root "${VAR_LIB}"
  run install -d -m 700 -o root -g root "${VAR_LIB}/state"

  # /var/log
  run install -d -m 750 -o root -g root "${VAR_LOG}"

  # /var/backups
  run install -d -m 750 -o root -g root "${VAR_BACKUP}"
  run install -d -m 750 -o root -g root "${VAR_BACKUP}/.tmp"

  log_ok "Dossiers prêts"
}

dir_has_content() {
  local d="$1"
  [ -d "$d" ] || return 1
  find "$d" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null | grep -q .
}

rsync_merge() {
  local src="$1" dst="$2"
  local -a args=(rsync -a)
  if [ "$FORCE" = false ]; then
    args+=(--ignore-existing)
  fi
  args+=("${src%/}/" "${dst%/}/")
  run "${args[@]}"
}

fix_perms() {
  # best-effort: on remet des perms cohérentes après migration
  run chown -R root:root "${ETC_DIR}" "${VAR_LIB}" "${VAR_LOG}" "${VAR_BACKUP}" >/dev/null 2>&1 || true

  run chmod 700 "${ETC_DIR}" "${ETC_DIR}/jobs" "${ETC_DIR}/secrets" "${VAR_LIB}" "${VAR_LIB}/state" >/dev/null 2>&1 || true
  run chmod 755 "${ETC_DIR}/keys" >/dev/null 2>&1 || true
  run chmod 750 "${VAR_LOG}" "${VAR_BACKUP}" "${VAR_BACKUP}/.tmp" >/dev/null 2>&1 || true

  # fichiers typiques
  if [ "$DRY_RUN" = false ]; then
    find "${ETC_DIR}/jobs" -maxdepth 1 -type f -name "*.json" -exec chmod 600 {} \; 2>/dev/null || true
    find "${ETC_DIR}/keys" -maxdepth 1 -type f -name "*.age.pub" -exec chmod 644 {} \; 2>/dev/null || true
    find "${ETC_DIR}/secrets" -maxdepth 1 -type f -exec chmod 600 {} \; 2>/dev/null || true
    find "${VAR_LIB}/state" -maxdepth 1 -type f -name "*.json" -exec chmod 600 {} \; 2>/dev/null || true
  fi
}

migrate_legacy() {
  if [ ! -d "${OLD_ETC_DIR}" ] && [ ! -d "${OLD_VAR_LIB}" ]; then
    log_info "Pas de legacy ${OLD_APP_NAME} détecté (skip migration)."
    return 0
  fi

  if [ "${MIGRATE_MODE}" = "none" ]; then
    log_info "Legacy détecté, mais migration désactivée (--migrate none)."
    return 0
  fi

  if is_tty && [ "${MIGRATE_MODE}" = "copy" ] && ( [ -d "${OLD_ETC_DIR}" ] || [ -d "${OLD_VAR_LIB}" ] ); then
    echo "" >&2
    log_warn "Legacy détecté (${OLD_APP_NAME}). Mode actuel: copy."
    echo "Choix migration:" >&2
    echo "  [1] Copier (safe, ne supprime pas l'ancien)  <-- défaut" >&2
    echo "  [2] Déplacer (supprime l'ancien une fois migré)" >&2
    echo "  [3] Ne rien faire" >&2
    read -r -p "Choix [1]: " ans || true
    case "${ans:-1}" in
      2) MIGRATE_MODE="move" ;;
      3) MIGRATE_MODE="none" ;;
      *) MIGRATE_MODE="copy" ;;
    esac
    echo "" >&2
  fi

  if [ "${MIGRATE_MODE}" = "none" ]; then
    return 0
  fi

  log_info "Migration legacy (mode: ${MIGRATE_MODE})…"

  # /etc/db-backup -> /etc/oxz-db-backup
  if dir_has_content "${OLD_ETC_DIR}/jobs"; then
    log_info "Merge: ${OLD_ETC_DIR}/jobs -> ${ETC_DIR}/jobs"
    rsync_merge "${OLD_ETC_DIR}/jobs" "${ETC_DIR}/jobs"
    [ "${MIGRATE_MODE}" = "move" ] && run rm -rf "${OLD_ETC_DIR}/jobs"
  fi
  if dir_has_content "${OLD_ETC_DIR}/keys"; then
    log_info "Merge: ${OLD_ETC_DIR}/keys -> ${ETC_DIR}/keys"
    rsync_merge "${OLD_ETC_DIR}/keys" "${ETC_DIR}/keys"
    [ "${MIGRATE_MODE}" = "move" ] && run rm -rf "${OLD_ETC_DIR}/keys"
  fi
  if dir_has_content "${OLD_ETC_DIR}/secrets"; then
    log_info "Merge: ${OLD_ETC_DIR}/secrets -> ${ETC_DIR}/secrets"
    rsync_merge "${OLD_ETC_DIR}/secrets" "${ETC_DIR}/secrets"
    [ "${MIGRATE_MODE}" = "move" ] && run rm -rf "${OLD_ETC_DIR}/secrets"
  fi

  # /var/lib/db-backup/state -> /var/lib/oxz-db-backup/state
  if dir_has_content "${OLD_VAR_LIB}/state"; then
    log_info "Merge: ${OLD_VAR_LIB}/state -> ${VAR_LIB}/state"
    rsync_merge "${OLD_VAR_LIB}/state" "${VAR_LIB}/state"
    [ "${MIGRATE_MODE}" = "move" ] && run rm -rf "${OLD_VAR_LIB}/state"
  fi

  # (on ne touche PAS aux backups/logs legacy ici : trop risqué + potentiellement volumineux)
  fix_perms
  log_ok "Migration terminée"
}

install_files() {
  log_info "Installation des scripts dans ${INSTALL_DIR}…"

  run install -d -m 755 -o root -g root "${INSTALL_DIR}"

  DST_WIZ="${INSTALL_DIR}/db-backup-wizard.sh"
  DST_RUN="${INSTALL_DIR}/db-backup-runner.sh"
  DST_RST="${INSTALL_DIR}/db-backup-restore.sh"

  run install -m 755 -o root -g root "$SRC_WIZ" "$DST_WIZ"
  run install -m 755 -o root -g root "$SRC_RUN" "$DST_RUN"
  run install -m 755 -o root -g root "$SRC_RST" "$DST_RST"

  # Wrapper commande
  run install -d -m 755 -o root -g root "${BIN_DIR}"
  local wrapper="${BIN_DIR}/${BIN_NAME}"

  if [ "$DRY_RUN" = false ]; then
    cat >"$wrapper" <<EOF
#!/usr/bin/env bash
exec "${DST_WIZ}" "\$@"
EOF
    chmod 755 "$wrapper"
    chown root:root "$wrapper"
  else
    echo "[DRY-RUN] Écriture wrapper: ${wrapper}"
  fi

  # Alias optionnel
  if [ -n "${ALIAS_NAME}" ] && [ "${ALIAS_NAME}" != "${BIN_NAME}" ]; then
    local alias_path="${BIN_DIR}/${ALIAS_NAME}"
    if [ "$DRY_RUN" = false ]; then
      ln -sf "${wrapper}" "${alias_path}"
    else
      echo "[DRY-RUN] ln -sf ${wrapper} ${alias_path}"
    fi
  fi

  log_ok "Installation scripts + commande OK"
}

setup_logrotate() {
  log_info "Configuration logrotate…"

  local lr="/etc/logrotate.d/${APP_NAME}"
  local grp="adm"
  if ! getent group adm >/dev/null 2>&1; then
    grp="root"
  fi

  if [ "$DRY_RUN" = false ]; then
    cat >"$lr" <<EOF
${VAR_LOG}/*.log ${VAR_LOG}/*.out ${VAR_LOG}/*.err {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 root ${grp}
    sharedscripts
    postrotate
        true
    endscript
}
EOF
    chmod 644 "$lr"
    chown root:root "$lr"
  else
    echo "[DRY-RUN] Écriture logrotate: ${lr}"
  fi

  log_ok "Logrotate OK"
}

do_uninstall() {
  log_info "Désinstallation… (ne supprime pas les données par défaut)"

  local wrapper="${BIN_DIR}/${BIN_NAME}"
  local alias_path="${BIN_DIR}/${ALIAS_NAME}"
  local lr="/etc/logrotate.d/${APP_NAME}"

  [ -f "$wrapper" ] && run rm -f "$wrapper" || true
  [ -n "${ALIAS_NAME}" ] && [ -f "$alias_path" ] && run rm -f "$alias_path" || true
  [ -f "$lr" ] && run rm -f "$lr" || true
  [ -d "${INSTALL_DIR}" ] && run rm -rf "${INSTALL_DIR}" || true

  if [ "$PURGE_DATA" = true ]; then
    log_warn "PURGE activé: suppression des données ${ETC_DIR} ${VAR_LIB} ${VAR_LOG} (pas les backups)."
    [ -d "${ETC_DIR}" ] && run rm -rf "${ETC_DIR}" || true
    [ -d "${VAR_LIB}" ] && run rm -rf "${VAR_LIB}" || true
    [ -d "${VAR_LOG}" ] && run rm -rf "${VAR_LOG}" || true
  fi

  log_ok "Désinstallation terminée"
}

usage() {
  cat >&2 <<EOF
Usage: sudo ./install.sh [OPTIONS]

Options:
  --install-dir DIR     Répertoire d'installation (défaut: ${INSTALL_DIR_DEFAULT})
  --bin-dir DIR         Répertoire des binaires (défaut: ${BIN_DIR_DEFAULT})
  --cmd NAME            Nom de commande (défaut: ${BIN_NAME_DEFAULT})
  --alias NAME          Alias (défaut: ${ALIAS_NAME_DEFAULT}, vide = désactiver)
  --migrate MODE        Migration legacy db-backup: none|copy|move (défaut: copy)
  --force               Écrase/merge plus agressif (migration overwrite + réinstall)
  --dry-run             Affiche les actions sans exécuter
  --uninstall           Désinstalle (sans effacer les données)
  --purge-data          Avec --uninstall: supprime aussi /etc, /var/lib, /var/log (pas /var/backups)
  --help                Aide

EOF
  exit 0
}

# === CLI ===
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-dir) INSTALL_DIR="${2:-}"; shift 2 ;;
    --bin-dir) BIN_DIR="${2:-}"; shift 2 ;;
    --cmd) BIN_NAME="${2:-}"; shift 2 ;;
    --alias) ALIAS_NAME="${2:-}"; shift 2 ;;
    --migrate) MIGRATE_MODE="${2:-}"; shift 2 ;;
    --force) FORCE=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --uninstall) UNINSTALL=true; shift ;;
    --purge-data) PURGE_DATA=true; shift ;;
    --help|-h) usage ;;
    *) die "Option inconnue: $1 (--help)" ;;
  esac
done

print_intro_install

if [ "$UNINSTALL" = true ]; then
  require_root
  do_uninstall
  exit 0
fi

pre_checks
ensure_dirs
migrate_legacy
install_files
setup_logrotate

echo "" >&2
log_ok "Installation terminée."
log_info "Commande: ${BIN_DIR}/${BIN_NAME}"
[ -n "${ALIAS_NAME}" ] && log_info "Alias:   ${BIN_DIR}/${ALIAS_NAME}"
log_info "Config:  ${ETC_DIR}"
log_info "Logs:    ${VAR_LOG}"
log_info "Backups: ${VAR_BACKUP}"
