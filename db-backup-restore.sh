#!/usr/bin/env bash
# db-backup-restore.sh — V1.1 (fix/optimisations intégrées)
# Script 3/3: Restore d'un dump .sql.zst.age vers une DB cible + clone grants (olddb.*) avec détection fine-grained.
# - Interactif (wizard) par défaut
# - Support: dumps des jobs (local/remote), dossier custom, fichier direct
# - Clé privée age: collée au moment du restore, stockée temporairement (0600) et supprimée via trap
# - SAFE: précheck (decrypt+decompress+markers) AVANT toute destruction de DB
# - Réécriture SQL: supprime CREATE/DROP DATABASE, force USE vers DB cible

set -u -o pipefail
IFS=$'\n\t'

###############################################
# Constantes
###############################################
readonly APP_NAME="db-backup"
readonly SCRIPT_VERSION="1.1"

readonly CONFIG_DIR="/etc/${APP_NAME}/jobs"
readonly STATE_DIR="/var/lib/${APP_NAME}/state"
readonly LOG_DIR="/var/log/${APP_NAME}"

readonly DEFAULT_LOCAL_BASE="/var/backups/${APP_NAME}"
SELECTED_TARGET_DB=""

###############################################
# Logs / UI
###############################################
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
info() { printf "%s [INFO] %s\n" "$(ts)" "$*" >&2; }
warn() { printf "%s [WARN] %s\n" "$(ts)" "$*" >&2; }
err()  { printf "%s [ERR ] %s\n" "$(ts)" "$*" >&2; }

pause() { read -r -p "Appuyez sur Entrée pour continuer..." _; }

###############################################
# Sécurité / helpers
###############################################
require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "Ce script doit être exécuté en root (sudo)."
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# IMPORTANT: ne pas casser les tabulations (mysql --batch renvoie des colonnes tab-séparées)
trim() {
  local s="${1:-}"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf "%s" "$s"
}

is_system_db() {
  case "${1:-}" in
    information_schema|performance_schema|mysql|sys|phpmyadmin) return 0 ;;
    *) return 1 ;;
  esac
}

sql_ident() {
  local s="${1:-}"
  s="${s//\`/\`\`}"
  printf '`%s`' "$s"
}

sql_quote() {
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\'/\'\'}"
  printf "'%s'" "$s"
}

ask_yes_no() {
  local prompt="$1" default="${2:-Y}" ans=""
  while true; do
    if [ "$default" = "Y" ]; then
      read -r -p "${prompt} [Y/n] " ans
      ans="${ans:-Y}"
    else
      read -r -p "${prompt} [y/N] " ans
      ans="${ans:-N}"
    fi
    if [[ "$ans" =~ ^[YyNn]$ ]]; then
      if [[ "$ans" =~ ^[Yy]$ ]]; then
        return 0
      else
        return 1
      fi
    fi
    warn "Répondez par Y ou N."
  done
}

ask_input() {
  local prompt="$1" default="${2:-}" ans=""
  if [ -n "$default" ]; then
    read -r -p "${prompt} [${default}] : " ans
    ans="${ans:-$default}"
  else
    read -r -p "${prompt} : " ans
  fi
  printf "%s" "$ans"
}

ask_int() {
  local prompt="$1" default="${2:-}" min="${3:-0}" max="${4:-999999999}" ans=""
  while true; do
    ans="$(ask_input "$prompt" "$default")"
    ans="$(trim "$ans")"
    if [[ "$ans" =~ ^[0-9]+$ ]] && [ "$ans" -ge "$min" ] && [ "$ans" -le "$max" ]; then
      printf "%s" "$ans"
      return 0
    fi
    warn "Entrez un entier entre ${min} et ${max}."
  done
}

tty_out() {
  if [ -c /dev/tty ]; then
    printf "%s" "/dev/tty"
  else
    printf "%s" "/dev/stderr"
  fi
}

ensure_dirs() {
  install -d -m 750 -o root -g root "${LOG_DIR}"
}

###############################################
# Dépendances minimales
###############################################
require_deps() {
  local missing=()

  for c in jq age zstd ssh rsync sha256sum; do
    have_cmd "$c" || missing+=("$c")
  done
  if ! have_cmd mysql && ! have_cmd mariadb; then
    missing+=("mariadb-client (mysql)")
  fi
  if ! have_cmd mysqldump && ! have_cmd mariadb-dump; then
    missing+=("mysqldump OU mariadb-dump")
  fi

  if [ "${#missing[@]}" -gt 0 ]; then
    err "Dépendances manquantes: ${missing[*]}"
    err "Installez-les (apt) puis relancez."
    exit 1
  fi
}

###############################################
# Intro (néophyte-friendly)
###############################################
print_intro() {
  cat >&2 <<'EOF'
============================================================
db-backup-restore.sh — Outil de restauration (sécurisé)
============================================================

But
- Restaurer un dump chiffré/compressé (*.sql.zst.age) vers une base MySQL/MariaDB cible.
- Éviter les catastrophes : le script fait un PRÉ-TEST (déchiffrement + décompression + marqueurs SQL)
  avant toute suppression de données.
- Option “DB temporaire (test de restauration)” : restaure dans une DB de test, puis la SUPPRIME
  à la fin. Idéal pour vérifier régulièrement que vos backups sont réellement restaurables.

Comment ça marche (simplifié)
1) Vous sélectionnez un dump (depuis un job local/remote, un dossier, ou un fichier direct)
2) Le script vérifie le SHA256 si un .sha256 est présent
3) Vous choisissez une DB cible :
   - nouvelle DB
   - DB temporaire de test (supprimée à la fin)
   - une DB existante (⚠️ destructif si non vide)
4) Vous collez la clé privée age (temporaire, supprimée automatiquement)
5) Le script restaure en forçant "USE <db_cible>" (et en neutralisant CREATE/DROP DATABASE)

Pré-requis
- Lancer en root (sudo)
- Outils : age, zstd, mysql/mariadb, jq, sha256sum (+ ssh/rsync si restore remote)
- Accès local au serveur MySQL/MariaDB (socket), typiquement via l’utilisateur root

Important
- Si vous restaurez sur une DB existante non vide : vous serez forcé de confirmer explicitement.
- Le “test de restauration” (DB temporaire) ne touche pas vos DB existantes.
EOF
}
###############################################
# MySQL/MariaDB helpers
###############################################
mysql_bin() {
  if have_cmd mysql; then
    printf "mysql"
  else
    printf "mariadb"
  fi
}

mysql_exec() {
  local sql="$1"
  "$(mysql_bin)" --batch --raw --skip-column-names -e "$sql"
}

db_exists() {
  local db="$1"
  local q
  q="SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=$(sql_quote "$db");"
  mysql_exec "$q" 2>/dev/null | grep -qx "$db"
}

db_table_counts() {
  local db="$1"
  local q
  q="SELECT
        COALESCE(SUM(TABLE_TYPE='BASE TABLE'),0) AS tables_count,
        COALESCE(SUM(TABLE_TYPE='VIEW'),0)       AS views_count,
        COALESCE(COUNT(*),0)                     AS total
     FROM information_schema.TABLES
     WHERE TABLE_SCHEMA=$(sql_quote "$db");"

  local line
  line="$(mysql_exec "$q" 2>/dev/null | head -n 1 || true)"
  if [ -z "$line" ]; then
    printf "0\t0\t0"
    return 0
  fi
  printf "%s" "$line"
}

list_databases() {
  mysql_exec "SHOW DATABASES;" 2>/dev/null | while IFS= read -r d; do
    if ! is_system_db "$d"; then
      printf "%s\n" "$d"
    fi
  done
}

select_target_database() {
  local source_hint="$1"

  # reset (important si on enchaîne plusieurs restores dans le même run)
  RESTORE_TEMP_DB="false"
  TEMP_DB_DROP_ON_EXIT="false"
  TEMP_DB_NAME=""
  SELECTED_TARGET_DB=""

  local default_new
  default_new="${source_hint}_restore_$(date -u +%Y%m%d_%H%M%S)"
  default_new="$(printf "%s" "$default_new" | tr -cd 'a-zA-Z0-9_')"

  local default_tmp
  default_tmp="${source_hint}_tmp_restore_$(date -u +%Y%m%d_%H%M%S)"
  default_tmp="$(printf "%s" "$default_tmp" | tr -cd 'a-zA-Z0-9_')"

  local -a dbs=()
  mapfile -t dbs < <(list_databases)

  printf "\nDB cible:\n" >&2
  printf "  [0] Créer une nouvelle DB\n" >&2
  printf "  [T] DB temporaire (test de restauration, supprimée à la fin)\n" >&2

  local i=1
  local d
  for d in "${dbs[@]}"; do
    printf "  [%d] %s\n" "$i" "$d" >&2
    i=$((i+1))
  done

  while true; do
    local raw
    raw="$(ask_input "Choisissez la DB cible (0, T, ou numéro)" "0")"
    raw="$(trim "$raw")"

    if [[ "$raw" =~ ^[Tt]$ ]]; then
      local tmpdb="$default_tmp"
      local n=1
      while db_exists "$tmpdb"; do
        tmpdb="${default_tmp}_${n}"
        n=$((n+1))
      done

      RESTORE_TEMP_DB="true"
      TEMP_DB_DROP_ON_EXIT="true"   # armé dès maintenant (même si abort avant la fin)
      TEMP_DB_NAME="$tmpdb"
      SELECTED_TARGET_DB="$tmpdb"
      return 0
    fi

    if [[ "$raw" =~ ^[0-9]+$ ]]; then
      local choice="$raw"

      if [ "$choice" -eq 0 ]; then
        local newdb
        while true; do
          newdb="$(ask_input "Nom de la nouvelle DB" "$default_new")"
          newdb="$(trim "$newdb")"
          if [[ ! "$newdb" =~ ^[a-zA-Z0-9_]{1,64}$ ]]; then
            warn "Nom invalide. Autorisé: a-zA-Z0-9_ (max 64)."
            continue
          fi
          if db_exists "$newdb"; then
            warn "La DB existe déjà: $newdb"
            ask_yes_no "Choisir un autre nom ?" "Y" || return 1
            continue
          fi
          SELECTED_TARGET_DB="$newdb"
          return 0
        done
      fi

      if [ "$choice" -ge 1 ] && [ "$choice" -le "${#dbs[@]}" ]; then
        SELECTED_TARGET_DB="${dbs[$((choice-1))]}"
        return 0
      fi

      warn "Choix invalide (0, T, ou 1..${#dbs[@]})."
      continue
    fi

    warn "Choix invalide. Entrez 0, T, ou un numéro."
  done
}


sql_stream_force_target_db() {
  local target_db="$1"
  local use_line
  use_line="USE $(sql_ident "$target_db");"

  awk -v use_line="$use_line" '
    BEGIN { printed_use=0 }

    function ensure_use() {
      if (printed_use == 0) {
        print use_line
        printed_use=1
      }
    }

    /^[[:space:]]*CREATE[[:space:]]+DATABASE[[:space:]]/ { next }
    /^[[:space:]]*DROP[[:space:]]+DATABASE[[:space:]]/   { next }
    /^[[:space:]]*USE[[:space:]]+/ { ensure_use(); next }

    { ensure_use(); print }
  '
}

###############################################
# Jobs / configs / state
###############################################
job_cfg_path() { printf "%s/%s.json" "$CONFIG_DIR" "$1"; }
job_state_path() { printf "%s/%s.json" "$STATE_DIR" "$1"; }

list_jobs() {
  shopt -s nullglob
  local -a cfgs=( "${CONFIG_DIR}"/*.json )
  shopt -u nullglob
  if [ "${#cfgs[@]}" -eq 0 ]; then
    return 0
  fi
  local f
  for f in "${cfgs[@]}"; do
    basename "$f" .json
  done
}

last_success_from_state() {
  local job_id="$1"
  local st
  st="$(job_state_path "$job_id")"
  if [ -f "$st" ]; then
    jq -r '.last_success_at // empty' "$st" 2>/dev/null || true
  fi
}

get_job_db_name() {
  local job_id="$1" cfg
  cfg="$(job_cfg_path "$job_id")"
  jq -r '.db.name // empty' "$cfg" 2>/dev/null || true
}

get_job_local_dir() {
  local job_id="$1" cfg
  cfg="$(job_cfg_path "$job_id")"
  local enabled path
  enabled="$(jq -r '.destinations.local.enabled // false' "$cfg" 2>/dev/null || echo "false")"
  path="$(jq -r '.destinations.local.path // ""' "$cfg" 2>/dev/null || echo "")"
  if [ "$enabled" = "true" ] && [ -n "$path" ]; then
    printf "%s" "$path"
    return 0
  fi
  printf ""
}

get_job_remote_info() {
  local job_id="$1" cfg
  cfg="$(job_cfg_path "$job_id")"
  local enabled
  enabled="$(jq -r '.destinations.remote_rsync.enabled // false' "$cfg" 2>/dev/null || echo "false")"
  if [ "$enabled" != "true" ]; then
    return 1
  fi
  local target port idf base
  target="$(jq -r '.destinations.remote_rsync.target // empty' "$cfg")"
  port="$(jq -r '.destinations.remote_rsync.ssh_port // 22' "$cfg")"
  idf="$(jq -r '.destinations.remote_rsync.ssh_identity_file // ""' "$cfg")"
  base="$(jq -r '.destinations.remote_rsync.remote_base_path // empty' "$cfg")"
  printf "%s\t%s\t%s\t%s" "$target" "$port" "$idf" "$base"
  return 0
}

get_job_recipient_pubkey_file() {
  local job_id="$1" cfg
  cfg="$(job_cfg_path "$job_id")"
  jq -r '.encryption.recipient_pubkey_file // empty' "$cfg" 2>/dev/null || true
}

###############################################
# Listing dumps (local / remote / folder)
###############################################
normalize_filter() {
  local f="${1:-}"
  f="$(trim "$f")"
  f="${f//-/}"
  f="${f//:/}"
  f="${f// /}"
  printf "%s" "$f"
}

list_dumps_local() {
  local dir="$1" filter="$2"
  [ -d "$dir" ] || return 0
  local f
  while IFS= read -r -d '' f; do
    local base
    base="$(basename "$f")"
    if [ -n "$filter" ]; then
      if [[ "${base}" != *"${filter}"* ]]; then
        continue
      fi
    fi
    printf "%s\n" "$f"
  done < <(find "$dir" -maxdepth 1 -type f -name "*.sql.zst.age" -print0 2>/dev/null | sort -z -r)
}

remote_job_dir() {
  local base="$1" job_id="$2"
  local host_short
  host_short="$(hostname -s | tr -cd 'a-zA-Z0-9_-')"
  if [ -z "$host_short" ]; then
    host_short="host"
  fi
  printf "%s/%s/%s" "${base%/}" "$host_short" "$job_id"
}

list_dumps_remote_job() {
  local target="$1" port="$2" identity="$3" remote_dir="$4" filter="$5"
  local -a ssh=(ssh -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
  if [ -n "$identity" ]; then
    ssh+=(-i "$identity")
  fi

  local out
  if ! out="$("${ssh[@]}" "$target" "ls -1 -- '$remote_dir' 2>/dev/null | grep -E '\.sql\.zst\.age$' || true")"; then
    return 1
  fi

  local line
  while IFS= read -r line; do
    line="$(trim "$line")"
    [ -z "$line" ] && continue
    if [ -n "$filter" ]; then
      if [[ "$line" != *"$filter"* ]]; then
        continue
      fi
    fi
    printf "%s\t%s\n" "$remote_dir" "$line"
  done <<<"$out"
  return 0
}

download_remote_dump() {
  local target="$1" port="$2" identity="$3" remote_dir="$4" filename="$5" outdir="$6"
  install -d -m 750 -o root -g root "$outdir"

  local ssh_e="ssh -p ${port} -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
  if [ -n "$identity" ]; then
    ssh_e+=" -i ${identity}"
  fi

  info "Download remote: ${target}:${remote_dir}/${filename} -> ${outdir}/"
  rsync -a -e "$ssh_e" "${target}:${remote_dir}/${filename}" "${outdir}/" || return 1

  rsync -a -e "$ssh_e" "${target}:${remote_dir}/${filename}.sha256" "${outdir}/" >/dev/null 2>&1 || true
  local meta="${filename%.sql.zst.age}.meta.json"
  rsync -a -e "$ssh_e" "${target}:${remote_dir}/${meta}" "${outdir}/" >/dev/null 2>&1 || true

  printf "%s/%s" "$outdir" "$filename"
}

###############################################
# Checksum / metadata
###############################################
dump_sidecar_sha() { printf "%s.sha256" "$1"; }

verify_sha256_if_present() {
  local dump_file="$1"
  local sha_file
  sha_file="$(dump_sidecar_sha "$dump_file")"
  if [ ! -f "$sha_file" ]; then
    warn "Pas de .sha256 trouvé (skip vérif): $(basename "$sha_file")"
    return 0
  fi

  local expected
  expected="$(awk '{print $1}' "$sha_file" | head -n 1 | tr -d '\r\n' || true)"
  if [[ ! "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
    warn "SHA attendu invalide dans $sha_file (skip)."
    return 0
  fi

  info "Vérif SHA256: $(basename "$dump_file")"
  local got
  got="$(sha256sum "$dump_file" | awk '{print $1}' | tr -d '\r\n')"
  if [ "$got" != "$expected" ]; then
    err "SHA mismatch: attendu=$expected / obtenu=$got"
    return 1
  fi
  info "SHA OK"
  return 0
}

show_meta_if_present() {
  local dump_file="$1"
  local meta_file
  meta_file="$(dirname "$dump_file")/$(basename "$dump_file" .sql.zst.age).meta.json"
  if [ -f "$meta_file" ]; then
    info "Metadata: $meta_file"
    jq -r 'to_entries|map("\(.key)=\(.value|tostring)")|.[]' "$meta_file" 2>/dev/null | sed 's/^/  /' >&2 || true
  fi
}

###############################################
# Clé privée age (coller -> fichier temp)
###############################################
KEY_TMP=""
TMP_DIR=""
DL_TMP_DIR=""

cleanup() {
  # cleanup clé privée
  if [ -n "${KEY_TMP:-}" ] && [ -f "$KEY_TMP" ]; then
    if have_cmd shred; then
      shred -u "$KEY_TMP" >/dev/null 2>&1 || rm -f "$KEY_TMP"
    else
      rm -f "$KEY_TMP"
    fi
  fi

  # cleanup tmpdirs
  if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR" >/dev/null 2>&1 || true
  fi
  if [ -n "${DL_TMP_DIR:-}" ] && [ -d "$DL_TMP_DIR" ]; then
    rm -rf "$DL_TMP_DIR" >/dev/null 2>&1 || true
  fi

  # IMPORTANT: cleanup DB temporaire (si armé)
  if [ "${TEMP_DB_DROP_ON_EXIT:-false}" = "true" ] && [ -n "${TEMP_DB_NAME:-}" ]; then
    info "Cleanup: suppression DB temporaire: ${TEMP_DB_NAME}"
    if mysql_exec "DROP DATABASE IF EXISTS $(sql_ident "$TEMP_DB_NAME");" >/dev/null 2>&1; then
      info "Cleanup: DB temporaire supprimée: ${TEMP_DB_NAME}"
    else
      warn "Cleanup: impossible de supprimer la DB temporaire: ${TEMP_DB_NAME}"
    fi
  fi
}
trap cleanup EXIT INT TERM

read_age_private_key_to_temp() {
  local out
  out="$(tty_out)"

  TMP_DIR="$(mktemp -d -p /run "${APP_NAME}-restore.XXXXXX" 2>/dev/null || mktemp -d)"
  chmod 700 "$TMP_DIR"
  KEY_TMP="${TMP_DIR}/age-identity.key"
  umask 077
  : >"$KEY_TMP"
  chmod 600 "$KEY_TMP"

  {
    printf "\nCollez la clé PRIVÉE age (commence par AGE-SECRET-KEY-...)\n"
    printf "Terminez par une ligne contenant seulement: END\n\n"
  } >"$out"

  while true; do
    local line
    read -r -p "> " line || true
    line="$(trim "$line")"
    if [ "$line" = "END" ]; then
      break
    fi
    printf "%s\n" "$line" >>"$KEY_TMP"
  done

  if ! grep -q '^AGE-SECRET-KEY-' "$KEY_TMP"; then
    err "Clé privée invalide (pas de ligne AGE-SECRET-KEY-)."
    return 1
  fi

  info "Clé privée chargée en fichier temporaire (${KEY_TMP}). Elle sera supprimée automatiquement."
  return 0
}

###############################################
# Grants clone (Option A: olddb.*) + détection fine-grained
###############################################
detect_fine_grained_grants() {
  local olddb="$1"

  if mysql_exec "SELECT 1 FROM mysql.tables_priv WHERE Db=$(sql_quote "$olddb") LIMIT 1;" 2>/dev/null | grep -q '^1$'; then
    return 0
  fi
  if mysql_exec "SELECT 1 FROM mysql.columns_priv WHERE Db=$(sql_quote "$olddb") LIMIT 1;" 2>/dev/null | grep -q '^1$'; then
    return 0
  fi
  if mysql_exec "SELECT 1 FROM mysql.procs_priv WHERE Db=$(sql_quote "$olddb") LIMIT 1;" 2>/dev/null | grep -q '^1$'; then
    return 0
  fi

  return 1
}

user_exists() {
  local u="$1" h="$2"
  mysql_exec "SELECT 1 FROM mysql.user WHERE User=$(sql_quote "$u") AND Host=$(sql_quote "$h") LIMIT 1;" 2>/dev/null | grep -q '^1$'
}

clone_db_grants_simple() {
  local olddb="$1" newdb="$2"

  if ! db_exists "$olddb"; then
    warn "DB modèle grants introuvable: $olddb (skip clone grants)"
    return 0
  fi
  if ! db_exists "$newdb"; then
    warn "DB cible introuvable: $newdb (skip clone grants)"
    return 0
  fi

  local q
  q="SELECT Host, User,
            Select_priv, Insert_priv, Update_priv, Delete_priv,
            Create_priv, Drop_priv, Grant_priv, References_priv, Index_priv, Alter_priv,
            Create_tmp_table_priv, Lock_tables_priv, Create_view_priv, Show_view_priv,
            Create_routine_priv, Alter_routine_priv, Execute_priv, Event_priv, Trigger_priv
     FROM mysql.db
     WHERE Db=$(sql_quote "$olddb");"

  local lines
  lines="$(mysql_exec "$q" 2>/dev/null || true)"
  if [ -z "$lines" ]; then
    warn "Aucun grant DB-level trouvé dans mysql.db pour ${olddb}.*"
    return 0
  fi

  info "Clonage grants (simple) : ${olddb}.* -> ${newdb}.*"

  local applied=0
  local line
  while IFS= read -r line; do
    [ -z "$line" ] && continue

    local -a cols=()
    IFS=$'\t' read -r -a cols <<<"$line"

    if [ "${#cols[@]}" -lt 21 ]; then
      warn "Ligne grants inattendue (cols=${#cols[@]}), skip."
      continue
    fi

    local host user
    host="$(trim "${cols[0]}")"
    user="$(trim "${cols[1]}")"
    [ -z "$user" ] && continue

    if ! user_exists "$user" "$host"; then
      warn "Compte absent, skip: ${user}@${host}"
      continue
    fi

    local sel ins upd del cre drp gopt ref idx alt ctt lkt cview sview crout arout execp ev tr
    sel="${cols[2]}";  ins="${cols[3]}";  upd="${cols[4]}";  del="${cols[5]}"
    cre="${cols[6]}";  drp="${cols[7]}";  gopt="${cols[8]}"; ref="${cols[9]}"
    idx="${cols[10]}"; alt="${cols[11]}"; ctt="${cols[12]}"; lkt="${cols[13]}"
    cview="${cols[14]}"; sview="${cols[15]}"; crout="${cols[16]}"; arout="${cols[17]}"
    execp="${cols[18]}"; ev="${cols[19]}"; tr="${cols[20]}"

    local -a privs=()
    [ "${sel:-N}"   = "Y" ] && privs+=("SELECT")
    [ "${ins:-N}"   = "Y" ] && privs+=("INSERT")
    [ "${upd:-N}"   = "Y" ] && privs+=("UPDATE")
    [ "${del:-N}"   = "Y" ] && privs+=("DELETE")
    [ "${cre:-N}"   = "Y" ] && privs+=("CREATE")
    [ "${drp:-N}"   = "Y" ] && privs+=("DROP")
    [ "${ref:-N}"   = "Y" ] && privs+=("REFERENCES")
    [ "${idx:-N}"   = "Y" ] && privs+=("INDEX")
    [ "${alt:-N}"   = "Y" ] && privs+=("ALTER")
    [ "${ctt:-N}"   = "Y" ] && privs+=("CREATE TEMPORARY TABLES")
    [ "${lkt:-N}"   = "Y" ] && privs+=("LOCK TABLES")
    [ "${cview:-N}" = "Y" ] && privs+=("CREATE VIEW")
    [ "${sview:-N}" = "Y" ] && privs+=("SHOW VIEW")
    [ "${crout:-N}" = "Y" ] && privs+=("CREATE ROUTINE")
    [ "${arout:-N}" = "Y" ] && privs+=("ALTER ROUTINE")
    [ "${execp:-N}" = "Y" ] && privs+=("EXECUTE")
    [ "${ev:-N}"    = "Y" ] && privs+=("EVENT")
    [ "${tr:-N}"    = "Y" ] && privs+=("TRIGGER")

    if [ "${#privs[@]}" -eq 0 ]; then
      continue
    fi

    local priv_list
    priv_list="$(IFS=", "; printf "%s" "${privs[*]}")"

    local stmt
    stmt="GRANT ${priv_list} ON $(sql_ident "$newdb").* TO $(sql_quote "$user")@$(sql_quote "$host")"
    if [ "${gopt:-N}" = "Y" ]; then
      stmt="${stmt} WITH GRANT OPTION"
    fi
    stmt="${stmt};"

    if ! mysql_exec "$stmt" >/dev/null 2>&1; then
      warn "GRANT KO pour ${user}@${host} (continue)."
      continue
    fi

    applied=$((applied+1))
  done <<<"$lines"

  info "Grants clonés (règles appliquées): ${applied}"
  return 0
}

###############################################
# Restore pipeline (DB ops)
###############################################
create_database() {
  local db="$1"
  mysql_exec "CREATE DATABASE $(sql_ident "$db");" >/dev/null
}

drop_and_create_database() {
  local db="$1"
  mysql_exec "DROP DATABASE $(sql_ident "$db");" >/dev/null
  mysql_exec "CREATE DATABASE $(sql_ident "$db");" >/dev/null
}

drop_all_tables_in_db() {
  local db="$1"
  local q
  q="SELECT CONCAT('DROP TABLE IF EXISTS \`', TABLE_SCHEMA, '\`.\`', TABLE_NAME, '\`;')
     FROM information_schema.TABLES
     WHERE TABLE_SCHEMA=$(sql_quote "$db") AND TABLE_TYPE='BASE TABLE';"
  local drops
  drops="$(mysql_exec "$q" 2>/dev/null || true)"
  if [ -n "$drops" ]; then
    mysql_exec "SET FOREIGN_KEY_CHECKS=0;" >/dev/null 2>&1 || true
    while IFS= read -r stmt; do
      stmt="$(trim "$stmt")"
      [ -z "$stmt" ] && continue
      mysql_exec "$stmt" >/dev/null 2>&1 || true
    done <<<"$drops"
    mysql_exec "SET FOREIGN_KEY_CHECKS=1;" >/dev/null 2>&1 || true
  fi
}

###############################################
# Vérifie qu'on voit des marqueurs "dump réel" avant d'importer
###############################################
precheck_dump_has_sql_markers() {
  local dump_file="$1"
  local sample_file
  sample_file="$(mktemp "${TMPDIR:-/run}/db-backup-precheck.XXXXXX.sql")" || return 1
  chmod 600 "$sample_file" >/dev/null 2>&1 || true

  if ! age -d -i "$KEY_TMP" "$dump_file" 2>/dev/null | zstd -d -c 2>/dev/null | head -n 4000 >"$sample_file"; then
    rm -f "$sample_file" >/dev/null 2>&1 || true
    return 1
  fi

  if ! grep -qE '^(CREATE TABLE|INSERT INTO|DROP TABLE|LOCK TABLES|CREATE VIEW|CREATE PROCEDURE|CREATE FUNCTION|CREATE TRIGGER|CREATE EVENT)' "$sample_file"; then
    rm -f "$sample_file" >/dev/null 2>&1 || true
    return 2
  fi

  if grep -qE '^[[:space:]]*(USE |CREATE DATABASE|DROP DATABASE)' "$sample_file"; then
    warn "Le dump contient des instructions de DB (USE/CREATE/DROP DATABASE) -> elles seront forcées vers la DB cible."
  fi

  rm -f "$sample_file" >/dev/null 2>&1 || true
  return 0
}

###############################################
# Restore: prétest + réécriture USE/CREATE DATABASE
###############################################
restore_dump_to_db() {
  local dump_file="$1" target_db="$2" skip_precheck="${3:-false}"

  info "Restore: $(basename "$dump_file") -> DB=${target_db}"

  if [ ! -f "$dump_file" ]; then
    err "Dump introuvable: $dump_file"
    return 1
  fi
  if [ -z "${KEY_TMP:-}" ] || [ ! -f "$KEY_TMP" ]; then
    err "Clé privée temp manquante."
    return 1
  fi

  if [ "$skip_precheck" != "true" ]; then
    precheck_dump_has_sql_markers "$dump_file"
    local pc="$?"
    if [ "$pc" -eq 1 ]; then
      err "Prétest KO: impossible de lire/déchiffrer/décompresser le dump."
      return 1
    fi
    if [ "$pc" -eq 2 ]; then
      err "Prétest KO: aucun marqueur SQL (CREATE TABLE/INSERT/...) détecté dans le début du dump. Import annulé."
      return 1
    fi
  fi

  age -d -i "$KEY_TMP" "$dump_file" \
    | zstd -d -c \
    | sql_stream_force_target_db "$target_db" \
    | "$(mysql_bin)" --database="$target_db"

  local -a ps=( "${PIPESTATUS[@]}" )
  local ec_age="${ps[0]:-127}"
  local ec_zst="${ps[1]:-127}"
  local ec_rw="${ps[2]:-127}"
  local ec_mysql="${ps[3]:-127}"

  if [ "$ec_age" -ne 0 ]; then
    err "Decrypt age KO (exit=$ec_age) — mauvaise clé privée ?"
    return 1
  fi
  if [ "$ec_zst" -ne 0 ]; then
    err "Decompress zstd KO (exit=$ec_zst) — fichier corrompu ?"
    return 1
  fi
  if [ "$ec_rw" -ne 0 ]; then
    err "Rewrite SQL KO (exit=$ec_rw)."
    return 1
  fi
  if [ "$ec_mysql" -ne 0 ]; then
    err "Import mysql KO (exit=$ec_mysql)."
    return 1
  fi

  info "Restore: OK"
  return 0
}

###############################################
# Sélection utilitaire (numéro OU nom exact)
###############################################
select_from_list_num_or_name() {
  local -n list="$1"
  local label="$2"

  if [ "${#list[@]}" -eq 0 ]; then
    err "Liste vide (${label})."
    return 1
  fi

  printf "\n%s:\n" "$label" >&2
  local i=1
  local item
  for item in "${list[@]}"; do
    printf "  [%d] %s\n" "$i" "$item" >&2
    i=$((i+1))
  done

  local raw
  raw="$(ask_input "Choix (numéro OU nom exact)" "1")"
  raw="$(trim "$raw")"

  if [[ "$raw" =~ ^[0-9]+$ ]]; then
    local idx="$raw"
    if [ "$idx" -lt 1 ] || [ "$idx" -gt "${#list[@]}" ]; then
      warn "Numéro invalide (1..${#list[@]})."
      return 1
    fi
    printf "%s" "${list[$((idx-1))]}"
    return 0
  fi

  for item in "${list[@]}"; do
    if [ "$item" = "$raw" ]; then
      printf "%s" "$item"
      return 0
    fi
  done

  err "Choix inconnu: '$raw'"
  return 1
}

###############################################
# Sélection dump (jobs / folder / file)
###############################################
wizard_select_job() {
  local -a jobs=()
  mapfile -t jobs < <(list_jobs)

  if [ "${#jobs[@]}" -eq 0 ]; then
    warn "Aucun job trouvé dans ${CONFIG_DIR}"
    return 1
  fi

  printf "\nJobs disponibles:\n" >&2
  printf '%s\n' '---------------------------------------------------------------' >&2
  printf "%-3s %-20s %-14s %-22s %s\n" "#" "job_id" "db" "last_success" "local_dir" >&2
  printf '%s\n' '---------------------------------------------------------------' >&2

  local i=1
  local j
  for j in "${jobs[@]}"; do
    local db last local_dir
    db="$(get_job_db_name "$j")"
    last="$(last_success_from_state "$j")"
    [ -n "$last" ] || last="—"
    local_dir="$(get_job_local_dir "$j")"
    [ -n "$local_dir" ] || local_dir="(local off)"
    printf "%-3s %-20s %-14s %-22s %s\n" "$i" "$j" "$db" "$last" "$local_dir" >&2
    i=$((i+1))
  done
  printf '%s\n' '---------------------------------------------------------------' >&2

  local choice
  choice="$(ask_int "Choisissez un job (numéro)" "1" 1 "${#jobs[@]}")"
  printf "%s" "${jobs[$((choice-1))]}"
  return 0
}

wizard_select_dump_from_paths() {
  local -n arr="$1"
  local label="$2"

  if [ "${#arr[@]}" -eq 0 ]; then
    warn "Aucun dump trouvé (${label})."
    return 1
  fi

  local -a names=()
  local p
  for p in "${arr[@]}"; do
    names+=( "$(basename "$p")" )
  done

  local picked_name
  while true; do
    if picked_name="$(select_from_list_num_or_name names "Dumps disponibles (${label})")"; then
      break
    fi
    ask_yes_no "Réessayer ?" "Y" || return 1
  done

  for p in "${arr[@]}"; do
    if [ "$(basename "$p")" = "$picked_name" ]; then
      printf "%s" "$p"
      return 0
    fi
  done

  err "Fichier introuvable après sélection (incohérent)."
  return 1
}

wizard_pick_dump_from_job() {
  local job_id="$1"
  local filter="$2"

  local local_dir
  local_dir="$(get_job_local_dir "$job_id")"

  local -a dumps=()
  if [ -n "$local_dir" ]; then
    mapfile -t dumps < <(list_dumps_local "$local_dir" "$filter")
  fi

  if [ "${#dumps[@]}" -eq 0 ]; then
    local ri
    if ri="$(get_job_remote_info "$job_id")"; then
      local target port idf base remote_dir
      target="$(printf "%s" "$ri" | awk -F'\t' '{print $1}')"
      port="$(printf "%s" "$ri" | awk -F'\t' '{print $2}')"
      idf="$(printf "%s" "$ri" | awk -F'\t' '{print $3}')"
      base="$(printf "%s" "$ri" | awk -F'\t' '{print $4}')"
      remote_dir="$(remote_job_dir "$base" "$job_id")"

      local -a remote_files=()
      mapfile -t remote_files < <(list_dumps_remote_job "$target" "$port" "$idf" "$remote_dir" "$filter" | awk -F'\t' '{print $2}' | sort -r)

      if [ "${#remote_files[@]}" -eq 0 ]; then
        warn "Aucun dump local et aucun dump remote trouvé pour ce job."
        return 1
      fi

      local picked
      while true; do
        if picked="$(select_from_list_num_or_name remote_files "Dumps remote (job=${job_id})")"; then
          break
        fi
        ask_yes_no "Réessayer ?" "Y" || return 1
      done

      DL_TMP_DIR="$(mktemp -d -p /run "${APP_NAME}-restore-dl.XXXXXX" 2>/dev/null || mktemp -d)"
      chmod 700 "$DL_TMP_DIR"
      local dl_dir="${DL_TMP_DIR}/download"

      local dl_file
      dl_file="$(download_remote_dump "$target" "$port" "$idf" "$remote_dir" "$picked" "$dl_dir")" || {
        err "Download remote KO."
        return 1
      }
      printf "%s" "$dl_file"
      return 0
    fi
  fi

  wizard_select_dump_from_paths dumps "local job=${job_id}"
}

wizard_pick_dump_from_folder() {
  local path="$1"
  local filter="$2"
  if [ ! -d "$path" ]; then
    err "Dossier introuvable: $path"
    return 1
  fi
  local -a dumps=()
  mapfile -t dumps < <(list_dumps_local "$path" "$filter")
  wizard_select_dump_from_paths dumps "folder=${path}"
}

wizard_pick_dump_from_file() {
  local file="$1"
  if [ ! -f "$file" ]; then
    err "Fichier introuvable: $file"
    return 1
  fi
  if [[ "$file" != *.sql.zst.age ]]; then
    warn "Extension inattendue (attendu *.sql.zst.age). On continue quand même."
  fi
  printf "%s" "$file"
}

###############################################
# Pré-backup DB cible (optionnel)
###############################################
mysqldump_bin() {
  if have_cmd mysqldump; then
    printf "mysqldump"
    return 0
  fi
  if have_cmd mariadb-dump; then
    printf "mariadb-dump"
    return 0
  fi
  printf "mysqldump"
  return 0
}

dump_supports_column_statistics() {
  local bin
  bin="$(mysqldump_bin)"

  if ! "$bin" --help 2>&1 | grep -q -- '--column-statistics'; then
    return 1
  fi

  local out ec
  ec=0
  out="$("$bin" --column-statistics=0 --help 2>&1)" || ec=$?
  if [ "$ec" -ne 0 ]; then
    return 1
  fi
  if printf "%s" "$out" | grep -qiE 'unknown (variable|option)|unrecognized option|illegal option'; then
    return 1
  fi

  return 0
}

pre_backup_db() {
  local db="$1" out_dir="$2" pubkey_file="$3"

  if [ -z "$pubkey_file" ] || [ ! -f "$pubkey_file" ]; then
    err "Pas de clé publique age disponible pour chiffrer le pre-backup. (skip)"
    return 1
  fi

  local bin
  bin="$(mysqldump_bin)"

  install -d -m 750 -o root -g root "$out_dir"

  local tsu
  tsu="$(date -u +%Y%m%d_%H%M%S)"
  local out_file="${out_dir}/pre_restore_${db}_${tsu}.sql.zst.age"
  local sha_file="${out_file}.sha256"

  local -a dump_args=( --single-transaction --routines --triggers --events )
  if dump_supports_column_statistics; then
    dump_args+=( --column-statistics=0 )
  fi

  info "Pre-backup: ${db} -> ${out_file}"

  "$bin" "${dump_args[@]}" "$db" \
    | zstd -6 -c \
    | age -R "$pubkey_file" -o "${out_file}.partial"

  local -a ps=( "${PIPESTATUS[@]}" )
  local ec_dump="${ps[0]:-127}"
  local ec_zst="${ps[1]:-127}"
  local ec_age="${ps[2]:-127}"

  if [ "$ec_dump" -ne 0 ] || [ "$ec_zst" -ne 0 ] || [ "$ec_age" -ne 0 ]; then
    rm -f "${out_file}.partial" >/dev/null 2>&1 || true
    err "Pre-backup KO (mysqldump=$ec_dump zstd=$ec_zst age=$ec_age)"
    return 1
  fi

  mv -f "${out_file}.partial" "$out_file"
  sha256sum "$out_file" | awk '{print $1}' >"$sha_file"
  info "Pre-backup OK: $(basename "$out_file")"
  return 0
}

###############################################
# Wizard principal restore
###############################################

finish_temp_restore_and_cleanup() {
  # args: target_db post_total
  local target_db="${1:-}"
  local post_total="${2:-0}"

  if [ -z "$target_db" ]; then
    warn "Test restore: target_db vide, impossible de nettoyer."
    return 0
  fi

  if [ "${post_total:-0}" -le 0 ]; then
    warn "Test restore: la DB temporaire est vide (total=0). Le dump est peut-être vide, ou le restore a été partiel."
  fi

  # On arme le cleanup au cas où (CTRL+C, crash, ou DROP qui échoue)
  TEMP_DB_DROP_ON_EXIT="true"
  TEMP_DB_NAME="$target_db"

  info "Test restore terminé. Tentative de suppression de la DB temporaire: ${target_db}"
  if mysql_exec "DROP DATABASE IF EXISTS $(sql_ident "$target_db");" >/dev/null 2>&1; then
    info "DB temporaire supprimée: ${target_db}"
    TEMP_DB_DROP_ON_EXIT="false"
    TEMP_DB_NAME=""
  else
    warn "DROP DATABASE a échoué. La DB temporaire sera retentée à la sortie (trap)."
    # IMPORTANT: on NE désarme PAS le cleanup ici
    TEMP_DB_DROP_ON_EXIT="true"
    TEMP_DB_NAME="$target_db"
  fi

  return 0
}

restore_flow() {
  local source_mode="$1"    # job|folder|file
  local source_job_id="$2"  # si mode job
  local source_path="$3"    # folder/file path
  local filter="$4"

  local dump_file=""
  local source_db_hint="dump"

  if [ "$source_mode" = "job" ]; then
    source_db_hint="$(get_job_db_name "$source_job_id")"
    [ -n "$source_db_hint" ] || source_db_hint="$source_job_id"
    dump_file="$(wizard_pick_dump_from_job "$source_job_id" "$filter")" || return 1
  elif [ "$source_mode" = "folder" ]; then
    dump_file="$(wizard_pick_dump_from_folder "$source_path" "$filter")" || return 1
  else
    dump_file="$(wizard_pick_dump_from_file "$source_path")" || return 1
  fi

  info "Dump sélectionné: $dump_file"
  show_meta_if_present "$dump_file"

  if ! verify_sha256_if_present "$dump_file"; then
    err "Checksum invalide => stop."
    return 1
  fi

  # >>> ICI le fix: on n'utilise plus $(...) car ça lance la fonction en subshell
  local target_db=""
  select_target_database "$source_db_hint" || return 1
  target_db="${SELECTED_TARGET_DB:-}"
  if [ -z "$target_db" ]; then
    err "DB cible vide (incohérent)."
    return 1
  fi
  # <<<

  local target_exists=false
  if db_exists "$target_db"; then
    target_exists=true
  fi

  if [ "$target_exists" = "true" ]; then
    local counts tables views total
    counts="$(db_table_counts "$target_db")"
    tables="$(printf "%s" "$counts" | awk -F'\t' '{print $1}')"
    views="$(printf "%s" "$counts" | awk -F'\t' '{print $2}')"
    total="$(printf "%s" "$counts" | awk -F'\t' '{print $3}')"

    info "DB cible existe: ${target_db} (tables=${tables}, views=${views}, total=${total})"
    if [ "$total" -gt 0 ]; then
      warn "La DB cible n'est pas vide. Tout sera PERDU."
      if ! ask_yes_no "Continuer ?" "N"; then
        return 1
      fi
      local confirm
      confirm="$(ask_input "Tapez exactement: RESTORE ${target_db}" "")"
      if [ "$confirm" != "RESTORE ${target_db}" ]; then
        err "Confirmation incorrecte."
        return 1
      fi
    fi
  else
    info "DB cible n'existe pas: ${target_db} (sera créée)"
  fi

  local pubkey_for_prebackup=""
  if [ "$source_mode" = "job" ]; then
    pubkey_for_prebackup="$(get_job_recipient_pubkey_file "$source_job_id")"
  fi

  if [ "$target_exists" = "true" ]; then
    if ask_yes_no "Faire un backup de la DB cible AVANT restore ? (recommandé)" "Y"; then
      local outdir="${DEFAULT_LOCAL_BASE}/_pre_restore/${target_db}"
      if ! pre_backup_db "$target_db" "$outdir" "$pubkey_for_prebackup"; then
        warn "Pre-backup a échoué."
        ask_yes_no "Continuer sans pre-backup ?" "N" || return 1
      else
        info "Pre-backup stocké dans: ${outdir}"
      fi
    fi
  fi

  # SAFE: clé + précheck AVANT toute destruction
  if ! read_age_private_key_to_temp; then
    return 1
  fi
  precheck_dump_has_sql_markers "$dump_file"
  local pc="$?"
  if [ "$pc" -eq 1 ]; then
    err "Prétest KO: impossible de lire/déchiffrer/décompresser le dump."
    return 1
  fi
  if [ "$pc" -eq 2 ]; then
    err "Prétest KO: dump sans marqueurs SQL détectés. Annulé avant destruction."
    return 1
  fi

  if [ "$target_exists" = "true" ]; then
    local counts2 total2
    counts2="$(db_table_counts "$target_db")"
    total2="$(printf "%s" "$counts2" | awk -F'\t' '{print $3}')"
    if [ "$total2" -gt 0 ]; then
      printf "\nMéthode d'écrasement:\n" >&2
      printf "  [1] DROP DATABASE + CREATE DATABASE (clean)\n" >&2
      printf "  [2] DROP TABLES (laisse la DB)\n" >&2
      local wipe
      wipe="$(ask_int "Choix" "1" 1 2)"
      if [ "$wipe" -eq 1 ]; then
        info "DROP+CREATE: ${target_db}"
        drop_and_create_database "$target_db" || { err "DROP+CREATE KO"; return 1; }
      else
        info "DROP TABLES: ${target_db}"
        drop_all_tables_in_db "$target_db" || { err "DROP TABLES KO"; return 1; }
      fi
    fi
  else
    create_database "$target_db" || { err "CREATE DATABASE KO"; return 1; }
  fi

  if ! restore_dump_to_db "$dump_file" "$target_db" "true"; then
    return 1
  fi

  local post post_total
  post="$(db_table_counts "$target_db")"
  post_total="$(printf "%s" "$post" | awk -F'\t' '{print $3}')"
  info "Post-restore: DB=${target_db} (tables=$(printf "%s" "$post" | awk -F'\t' '{print $1}'), views=$(printf "%s" "$post" | awk -F'\t' '{print $2}'))"

  if [ "${RESTORE_TEMP_DB:-false}" = "true" ]; then
    finish_temp_restore_and_cleanup "$target_db" "$post_total"
    return 0
  fi

  local do_grants=false
  local grants_from_db=""

  if ask_yes_no "Cloner les droits (GRANT) depuis une DB modèle vers ${target_db} ? (recommandé si new DB)" "Y"; then
    do_grants=true
    if [ "$source_mode" = "job" ]; then
      grants_from_db="$(get_job_db_name "$source_job_id")"
    fi
    if [ -z "$grants_from_db" ]; then
      grants_from_db="$(ask_input "DB modèle pour grants (olddb)" "")"
    else
      grants_from_db="$(ask_input "DB modèle pour grants (olddb)" "$grants_from_db")"
    fi
    grants_from_db="$(trim "$grants_from_db")"
  fi

  if [ "$do_grants" = "true" ] && [ -n "$grants_from_db" ]; then
    if detect_fine_grained_grants "$grants_from_db"; then
      warn "Détection: il existe des grants fins (table/col/proc) sur ${grants_from_db}."
      warn "Ce script clone uniquement ${grants_from_db}.* (DB-level)."
      ask_yes_no "Continuer le clonage simple quand même ?" "Y" || do_grants=false
    fi

    if [ "$do_grants" = "true" ]; then
      clone_db_grants_simple "$grants_from_db" "$target_db" || true
    fi
  fi

  local dump_dir
  dump_dir="$(dirname "$dump_file")"
  printf "\n" >&2
  info "Dump utilisé : $dump_file"
  info "Dossier dump: $dump_dir"
  printf "Pour aller voir: cd %q\n" "$dump_dir" >&2

  return 0
}

###############################################
# Wizard menu
###############################################
wizard_main() {
  while true; do
    printf "\n=== %s restore (wizard) ===\n" "$APP_NAME" >&2
    printf "1) Restore depuis un job (local/remote)\n" >&2
    printf "2) Restore depuis un dossier custom\n" >&2
    printf "3) Restore depuis un fichier direct\n" >&2
    printf "4) Quitter\n" >&2

    local choice
    choice="$(ask_int "Choix" "4" 1 4)"

    if [ "$choice" -eq 4 ]; then
      exit 0
    fi

    if [ "$choice" -eq 1 ]; then
      local job_id
      job_id="$(wizard_select_job)" || { pause; continue; }

      local filter_raw filter
      filter_raw="$(ask_input "Filtre (contient) (ex: 2025-12 ou 202512). Vide=aucun" "")"
      filter="$(normalize_filter "$filter_raw")"

      if restore_flow "job" "$job_id" "" "$filter"; then
        info "Restore terminé: OK"
      else
        err "Restore terminé: ECHEC"
      fi
      pause
      continue
    fi

    if [ "$choice" -eq 2 ]; then
      local p
      p="$(ask_input "Dossier à analyser" "/tmp")"
      p="$(trim "$p")"

      local filter_raw filter
      filter_raw="$(ask_input "Filtre (contient) (ex: 2025-12 ou 202512). Vide=aucun" "")"
      filter="$(normalize_filter "$filter_raw")"

      if restore_flow "folder" "" "$p" "$filter"; then
        info "Restore terminé: OK"
      else
        err "Restore terminé: ECHEC"
      fi
      pause
      continue
    fi

    if [ "$choice" -eq 3 ]; then
      local f
      f="$(ask_input "Chemin du fichier dump (*.sql.zst.age)" "")"
      f="$(trim "$f")"
      if restore_flow "file" "" "$f" ""; then
        info "Restore terminé: OK"
      else
        err "Restore terminé: ECHEC"
      fi
      pause
      continue
    fi
  done
}

###############################################
# Entrée
###############################################
require_root
ensure_dirs
require_deps
print_intro
wizard_main
