#!/usr/bin/env bash
# db-backup-runner.sh — V1.2 (Ubuntu)
# Script 2/3: Runner (cron hourly) + mini-wizard interactif quand lancé à la main (TTY)
#
# - Mode CRON (non-interactif): fait juste le boulot (backup + rsync + rétention + webhook).
# - Mode MANUEL (TTY, sans args): affiche un wizard (liste jobs + stats + run forcé + setup cron)
#   + accès au db-backup-restore.sh si présent.
#
# NEW V1.2:
# - "restore_test" PARTIEL (sans clé privée): vérifs présence + checksum + meta + header age,
#   selon .restore_test.every_days (0=off). Envoie une notif webhook pour pousser au test manuel de restore.
#
# Usage:
#   sudo /opt/db-backup/db-backup-runner.sh                 # wizard (si TTY)
#   sudo /opt/db-backup/db-backup-runner.sh --cron          # force mode non-interactif
#   sudo /opt/db-backup/db-backup-runner.sh --job iemf-prod --force
#   sudo /opt/db-backup/db-backup-runner.sh --dry-run
#
# Cron recommandé (/etc/cron.d/db-backup):
#   0 * * * * root /opt/db-backup/db-backup-runner.sh --cron

set -u -o pipefail
IFS=$'\n\t'
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

###############################################
# Constantes / chemins
###############################################
readonly APP_NAME="db-backup"
readonly SCRIPT_VERSION="1.2"

readonly CONFIG_DIR="/etc/${APP_NAME}/jobs"
readonly STATE_DIR="/var/lib/${APP_NAME}/state"
readonly LOG_DIR="/var/log/${APP_NAME}"

readonly DEFAULT_LOCAL_BASE="/var/backups/${APP_NAME}"
readonly TMP_BASE="${DEFAULT_LOCAL_BASE}/.tmp"

readonly LOCK_FILE="/run/${APP_NAME}.lock"

# Scripts frères (pont)
readonly SELF_PATH="$(readlink -f "$0" 2>/dev/null || printf "%s" "$0")"
readonly SELF_DIR="$(cd "$(dirname "$SELF_PATH")" >/dev/null 2>&1 && pwd -P || printf "%s" ".")"
readonly RESTORE_SH="${SELF_DIR}/db-backup-restore.sh"

INTRO_SHOWN="false"

# Sécurité disque (désactivable: DB_BACKUP_MIN_FREE_GB=0)
_min_free_gb_raw="${DB_BACKUP_MIN_FREE_GB:-1}"
if [[ ! "${_min_free_gb_raw}" =~ ^[0-9]+$ ]]; then
  _min_free_gb_raw="1"
fi
readonly MIN_FREE_GB_DEFAULT="${_min_free_gb_raw}"
unset _min_free_gb_raw

###############################################
# Logs
###############################################
ts_utc() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

log_line() {
  local level="$1" msg="$2"
  local line
  line="$(printf "%s [%s] %s" "$(ts_utc)" "$level" "$msg")"
  printf "%s\n" "$line" >&2
  printf "%s\n" "$line" >>"${LOG_DIR}/runner.log"
}

info() { log_line "INFO" "$*"; }
warn() { log_line "WARN" "$*"; }
err()  { log_line "ERR " "$*"; }

###############################################
# Helpers
###############################################
require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "Lancez ce script en root (ex: sudo $0)"
    exit 1
  fi
}

is_interactive_tty() {
  if [ -c /dev/tty ] && [ -t 0 ] && [ -t 1 ]; then
    return 0
  fi
  return 1
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

ensure_dirs() {
  install -d -m 700 -o root -g root "${STATE_DIR}"
  install -d -m 750 -o root -g root "${LOG_DIR}"
  install -d -m 750 -o root -g root "${DEFAULT_LOCAL_BASE}" "${TMP_BASE}"
}

ensure_deps() {
  local -a need=(jq age zstd sha256sum rsync ssh curl date stat find flock df awk grep sed basename readlink mktemp head)
  local missing=()

  for c in "${need[@]}"; do
    have_cmd "$c" || missing+=("$c")
  done

  if ! have_cmd mysqldump && ! have_cmd mariadb-dump; then
    missing+=("mysqldump|mariadb-dump (mariadb-client)")
  fi
  if ! have_cmd mysql && ! have_cmd mariadb; then
    missing+=("mysql|mariadb (mariadb-client)")
  fi

  if [ "${#missing[@]}" -gt 0 ]; then
    err "Dépendances manquantes: ${missing[*]}"
    err "Installez: sudo apt-get update && sudo apt-get install -y mariadb-client age jq zstd rsync curl"
    exit 2
  fi
}

mysql_bin() { if have_cmd mysql; then printf "mysql"; else printf "mariadb"; fi; }
dump_bin()  { if have_cmd mysqldump; then printf "mysqldump"; else printf "mariadb-dump"; fi; }

# Trim sûr (ne détruit pas les tabs)
trim() {
  local s="${1:-}"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf "%s" "$s"
}

safe_state_path() { printf "%s/%s.json" "$STATE_DIR" "$1"; }
job_cfg_path() { printf "%s/%s.json" "$CONFIG_DIR" "$1"; }

safe_write_atomic() {
  local path="$1" mode="$2" owner="$3" group="$4" content="$5"
  local tmp
  tmp="$(mktemp)" || return 1
  umask 077
  printf "%s" "$content" >"$tmp" || { rm -f "$tmp"; return 1; }
  install -m "$mode" -o "$owner" -g "$group" "$tmp" "$path" || { rm -f "$tmp"; return 1; }
  rm -f "$tmp"
}

# Quote safe for remote sh single-quoted contexts: ' -> '"'"'
sh_q() {
  local s="${1:-}"
  s="${s//\'/\'\"\'\"\'/}"
  printf "'%s'" "$s"
}

pubkey_fingerprint() {
  local pubfile="$1"
  sha256sum "$pubfile" | awk '{print $1}'
}

# FIX robuste (certaines variantes affichent l’option mais la refusent)
dump_supports_column_statistics() {
  local bin out ec
  bin="$(dump_bin)"

  if ! "$bin" --help 2>&1 | grep -q -- '--column-statistics'; then
    return 1
  fi

  ec=0
  out="$("$bin" --column-statistics=0 --help 2>&1)" || ec=$?
  if [ "${ec:-0}" -ne 0 ]; then
    return 1
  fi
  if printf "%s" "$out" | grep -qiE 'unknown (variable|option)|unrecognized option|illegal option'; then
    return 1
  fi

  return 0
}

print_intro_runner() {
  # Ne rien afficher si :
  # - cron / non-interactif (pas de TTY)
  # - ou si l’env var force le silence
  if [ "${DB_BACKUP_NO_INTRO:-0}" = "1" ]; then
    return 0
  fi
  if ! is_interactive_tty && [ "${DB_BACKUP_FORCE_INTRO:-0}" != "1" ]; then
    return 0
  fi

  # Une seule fois par exécution
  if [ "${INTRO_SHOWN:-false}" = "true" ]; then
    return 0
  fi
  INTRO_SHOWN="true"

  local out
  out="/dev/tty"

  {
    printf "\n"
    printf "============================================================\n"
    printf "%s — Runner (script 2/3) — V%s\n" "${APP_NAME}" "${SCRIPT_VERSION}"
    printf "============================================================\n\n"
    printf "Rôle : exécuter les jobs dus (selon schedule), écrire logs/state,\n"
    printf "et pousser vers destinations (local/remote) + notifications webhook.\n\n"
    printf "Jobs : %s\n" "${CONFIG_DIR}"
    printf "State: %s\n" "${STATE_DIR}"
    printf "Logs : %s\n\n" "${LOG_DIR}"
    printf "\n"

    printf "\n"

    printf "But\n"
    printf "Exécuter automatiquement (cron) des jobs de backup/restore définis en JSON.\n"
    printf "Même philosophie SAFE : vérifications, logs clairs, erreurs explicites.\n"
    printf "\n"

    printf "Fonctionnement (simplifié)\n"
    printf "1) Le runner charge la configuration des jobs (ex: /etc/db-backup/jobs/*.json)\n"
    printf "2) Il détermine les jobs \"dus\" (selon schedule) et les exécute séquentiellement\n"
    printf "3) Il écrit l'état (succès/échec) dans /var/lib/db-backup/state\n"
    printf "4) Il logge tout (stdout/stderr) pour être exploitable via cron/systemd\n"
    printf "\n"

    printf "Pré-requis\n"
    printf "Lancer en root (sudo) (recommandé : accès aux répertoires de backup/état/logs)\n"
    printf "Outils : jq, age, zstd, mysql/mariadb, sha256sum\n"
    printf "Si destination remote : ssh + rsync (clé SSH et accès OK)\n"
    printf "\n"

    printf "Sécurité / bonnes pratiques\n"
    printf "Ne mettez pas de secrets en arguments (historique shell) : utilisez fichiers (0600) ou variables d'env.\n"
    printf "Vérifiez les droits MySQL/MariaDB et les chemins des clés avant planification.\n"
    printf "Testez régulièrement la restaurabilité : utilisez la DB temporaire côté restore.\n"
    printf "\n"
  } >"$out"

  read -r -n 1 -s -p "Appuyez sur une touche pour continuer..." _ </dev/tty
  printf "\n" >"$out"
}

###############################################
# SSH options (anti-hang cron)
###############################################
ssh_base_opts() {
  # stdout: options (sans -p / -i)
  printf "%s" "-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=1"
}

ssh_cmd_build() {
  # args: port identity
  local port="$1" identity="$2"
  local -a cmd=(ssh)
  cmd+=(-p "$port")
  # shellcheck disable=SC2206
  cmd+=($(ssh_base_opts))
  if [ -n "$identity" ]; then
    cmd+=(-i "$identity")
  fi
  printf "%s\0" "${cmd[@]}"
}

rsync_ssh_e() {
  # args: port identity
  local port="$1" identity="$2"
  local e="ssh -p ${port} $(ssh_base_opts)"
  if [ -n "$identity" ]; then
    e="${e} -i ${identity}"
  fi
  printf "%s" "$e"
}

###############################################
# Webhook
###############################################
webhook_send() {
  local cfg="$1" payload="$2"

  local enabled url headers_file
  enabled="$(jq -r '.webhook.enabled // false' "$cfg")"
  [ "$enabled" = "true" ] || return 0

  url="$(jq -r '.webhook.url // ""' "$cfg")"
  [ -n "$url" ] || return 0

  headers_file="$(jq -r '.webhook.headers_secret_file // ""' "$cfg")"

  local -a cmd=(curl -fsS -X POST -H "Content-Type: application/json" --data "$payload")
  if [ -n "$headers_file" ] && [ -f "$headers_file" ]; then
    while IFS= read -r line; do
      line="$(trim "$line")"
      [ -z "$line" ] && continue
      cmd+=(-H "$line")
    done <"$headers_file"
  fi

  cmd+=("$url")
  "${cmd[@]}" >/dev/null 2>&1 || true
}

webhook_event() {
  local cfg="$1" event="$2" job_id="$3" db="$4" step="$5" exit_code="$6" error="$7" duration_ms="$8" size_bytes="$9"
  local dest_local="${10}" dest_remote="${11}" file="${12}"

  # Slack Incoming Webhooks aiment (souvent) au moins un champ "text"
  local text
  text="[$(hostname -s)] ${event} job=${job_id} db=${db} step=${step} code=${exit_code}"
  if [ -n "$error" ]; then
    text="${text} error=${error}"
  fi

  local payload
  payload="$(jq -c -n \
    --arg text "$text" \
    --arg event "$event" \
    --arg job_id "$job_id" \
    --arg db "$db" \
    --arg hostname "$(hostname -s)" \
    --arg at "$(ts_utc)" \
    --arg step "$step" \
    --argjson exit_code "${exit_code:-0}" \
    --arg error "${error:-}" \
    --argjson duration_ms "${duration_ms:-0}" \
    --argjson size_bytes "${size_bytes:-0}" \
    --argjson dest_local "${dest_local:-false}" \
    --argjson dest_remote "${dest_remote:-false}" \
    --arg file "${file:-}" \
    '{text:$text, event:$event, job_id:$job_id, db:$db, hostname:$hostname, at:$at, step:$step, exit_code:$exit_code, error:$error, duration_ms:$duration_ms, size_bytes:$size_bytes, destinations:{local:$dest_local, remote_rsync:$dest_remote}, file:$file}')"

  webhook_send "$cfg" "$payload"
}

webhook_restore_test() {
  # event: restore_test.reminder | restore_test.partial_failure
  local cfg="$1" event="$2" job_id="$3" db="$4" status="$5" message="$6" backup_file="$7" every_days="$8"

  local text
  text="[$(hostname -s)] ${event} job=${job_id} db=${db} status=${status}"
  if [ -n "$backup_file" ]; then
    text="${text} backup=${backup_file}"
  fi
  if [ "${every_days:-0}" -gt 0 ]; then
    text="${text} every_days=${every_days}"
  fi
  if [ -n "$message" ]; then
    text="${text} msg=${message}"
  fi

  local payload
  payload="$(jq -c -n \
    --arg text "$text" \
    --arg event "$event" \
    --arg job_id "$job_id" \
    --arg db "$db" \
    --arg hostname "$(hostname -s)" \
    --arg at "$(ts_utc)" \
    --arg status "$status" \
    --arg message "$message" \
    --arg backup_file "$backup_file" \
    --argjson every_days "${every_days:-0}" \
    '{
      text:$text,
      event:$event,
      job_id:$job_id,
      db:$db,
      hostname:$hostname,
      at:$at,
      restore_test:{
        status:$status,
        message:(if $message=="" then null else $message end),
        backup_file:(if $backup_file=="" then null else $backup_file end),
        every_days:$every_days,
        note:"Test partiel effectué (sans clé privée). Faites un restore complet MANUEL périodiquement."
      }
    }')"

  webhook_send "$cfg" "$payload"
}

###############################################
# Scheduling
###############################################
iso_to_epoch_utc() {
  local iso="${1:-}"
  if [ -z "$iso" ] || [ "$iso" = "null" ]; then
    printf "%s" ""
    return 0
  fi
  date -u -d "$iso" +%s 2>/dev/null || printf "%s" ""
}

utc_stamp_now() { date -u +%Y%m%d_%H%M%S; }

utc_cutoff_stamp_days_ago() { date -u -d "-${1} days" +%Y%m%d_%H%M%S; }
utc_cutoff_stamp_years_ago() { date -u -d "-${1} years" +%Y%m%d_%H%M%S; }

is_due() {
  local cfg="$1" st="$2" force="$3"
  if [ "$force" = "true" ]; then
    printf "true"
    return 0
  fi

  local enabled
  enabled="$(jq -r '.enabled // false' "$cfg")"
  [ "$enabled" = "true" ] || { printf "false"; return 0; }

  local schedule_type every_hours daily_time timezone
  schedule_type="$(jq -r '.schedule.type // ""' "$cfg")"
  every_hours="$(jq -r '.schedule.every_hours // empty' "$cfg")"
  daily_time="$(jq -r '.schedule.daily_time // empty' "$cfg")"
  timezone="$(jq -r '.schedule.timezone // "UTC"' "$cfg")"

  local last_success_iso last_success_epoch
  last_success_iso=""
  if [ -f "$st" ]; then
    last_success_iso="$(jq -r '.last_success_at // empty' "$st" 2>/dev/null || true)"
  fi
  last_success_epoch="$(iso_to_epoch_utc "$last_success_iso")"

  local now_epoch
  now_epoch="$(date -u +%s)"

  if [ "$schedule_type" = "hourly" ]; then
    if [[ ! "${every_hours:-}" =~ ^[0-9]+$ ]] || [ "${every_hours:-0}" -lt 1 ]; then
      printf "false"
      return 0
    fi
    if [ -z "${last_success_epoch:-}" ]; then
      printf "true"
      return 0
    fi
    local delta needed
    delta=$(( now_epoch - last_success_epoch ))
    needed=$(( every_hours * 3600 ))
    if [ "$delta" -ge "$needed" ]; then printf "true"; else printf "false"; fi
    return 0
  fi

  if [ "$schedule_type" = "daily" ]; then
    if [[ ! "${daily_time:-}" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]; then
      printf "false"
      return 0
    fi

    local today due_epoch now_tz_epoch
    today="$(TZ="$timezone" date +%F)"
    now_tz_epoch="$(TZ="$timezone" date +%s)"
    due_epoch="$(TZ="$timezone" date -d "${today} ${daily_time}:00" +%s 2>/dev/null || printf "%s" "")"

    [ -n "$due_epoch" ] || { printf "false"; return 0; }
    [ "$now_tz_epoch" -ge "$due_epoch" ] || { printf "false"; return 0; }
    if [ -n "${last_success_epoch:-}" ] && [ "$last_success_epoch" -ge "$due_epoch" ]; then
      printf "false"
      return 0
    fi
    printf "true"
    return 0
  fi

  printf "false"
  return 0
}

###############################################
# Validation config
###############################################
validate_cfg_or_fail() {
  local cfg="$1"

  local job_id db_name
  job_id="$(jq -r '.job_id // empty' "$cfg")"
  db_name="$(jq -r '.db.name // empty' "$cfg")"
  if [ -z "$job_id" ] || [ -z "$db_name" ]; then
    err "Config invalide (job_id/db.name manquant): $cfg"
    return 1
  fi

  if [[ "$db_name" =~ ^- ]] || [[ ! "$db_name" =~ ^[a-zA-Z0-9_@.-]+$ ]]; then
    err "DB name invalide/suspect: '$db_name' (cfg=$cfg)"
    return 1
  fi

  local local_enabled rem_enabled
  local_enabled="$(jq -r '.destinations.local.enabled // false' "$cfg")"
  rem_enabled="$(jq -r '.destinations.remote_rsync.enabled // false' "$cfg")"
  if [ "$local_enabled" != "true" ] && [ "$rem_enabled" != "true" ]; then
    err "Aucune destination activée (local+remote off): $cfg"
    return 1
  fi

  local pubfile
  pubfile="$(jq -r '.encryption.recipient_pubkey_file // empty' "$cfg")"
  if [ -z "$pubfile" ] || [ ! -f "$pubfile" ]; then
    err "Clé publique age introuvable: $pubfile (cfg=$cfg)"
    return 1
  fi
  if ! grep -Eq '^age1[0-9a-z]+$' "$pubfile"; then
    err "Clé publique age invalide dans: $pubfile"
    return 1
  fi

  local schedule_type
  schedule_type="$(jq -r '.schedule.type // empty' "$cfg")"
  if [ "$schedule_type" != "hourly" ] && [ "$schedule_type" != "daily" ]; then
    err "Schedule.type invalide: '$schedule_type' (cfg=$cfg)"
    return 1
  fi

  local ztype
  ztype="$(jq -r '.compression.type // empty' "$cfg")"
  if [ "$ztype" != "zstd" ]; then
    err "Compression.type non supportée: '$ztype' (cfg=$cfg) — attendu: zstd"
    return 1
  fi

  local etype
  etype="$(jq -r '.encryption.type // empty' "$cfg")"
  if [ "$etype" != "age" ]; then
    err "Encryption.type non supportée: '$etype' (cfg=$cfg) — attendu: age"
    return 1
  fi

  return 0
}

###############################################
# Espace disque
###############################################
check_min_free_space() {
  local path="$1" min_gb="$2"
  if [ "$min_gb" -le 0 ]; then
    return 0
  fi
  local avail_kb need_kb
  avail_kb="$(df -Pk "$path" | awk 'NR==2{print $4}' 2>/dev/null || printf "0")"
  need_kb=$(( min_gb * 1024 * 1024 ))
  [ "$avail_kb" -ge "$need_kb" ]
}

###############################################
# Metadata + state
###############################################
write_metadata() {
  # args: out_meta job_id db stamp dump_file sha size_bytes duration_ms zlevel loc_enabled rem_enabled pub_fpr
  local out="$1" job_id="$2" db="$3" stamp="$4" dump_file="$5" sha="$6" size="$7" duration_ms="$8" zlevel="$9"
  local loc="${10}" rem="${11}" pubfpr="${12}"

  jq -n \
    --arg job_id "$job_id" \
    --arg db "$db" \
    --arg created_at "$(ts_utc)" \
    --arg hostname "$(hostname -s)" \
    --arg stamp "$stamp" \
    --arg compression_type "zstd" \
    --argjson compression_level "$zlevel" \
    --arg encryption_type "age" \
    --arg recipient_pubkey_fingerprint "$pubfpr" \
    --arg dump_file "$dump_file" \
    --arg sha256 "$sha" \
    --argjson size_bytes "$size" \
    --argjson duration_ms "$duration_ms" \
    --argjson dest_local "$loc" \
    --argjson dest_remote "$rem" \
    '{
      job_id:$job_id,
      db:$db,
      created_at:$created_at,
      hostname:$hostname,
      stamp:$stamp,
      compression:{type:$compression_type, level:$compression_level},
      encryption:{type:$encryption_type, recipient_pubkey_fingerprint:$recipient_pubkey_fingerprint},
      dump:{file:$dump_file, sha256:$sha256, size_bytes:$size_bytes, duration_ms:$duration_ms},
      destinations:{local:$dest_local, remote_rsync:$dest_remote}
    }' >"$out"
}

update_state() {
  local job_id="$1" last_attempt="$2" last_success="$3" exit_code="$4" error="$5" dump_file="$6" size_bytes="$7" sha="$8"
  local local_path="$9" remote_path="${10}" duration_ms="${11}"

  local st content
  st="$(safe_state_path "$job_id")"

  content="$(jq -c -n \
    --arg job_id "$job_id" \
    --arg last_attempt_at "$last_attempt" \
    --arg last_success_at "$last_success" \
    --argjson last_exit_code "$exit_code" \
    --arg last_error "$error" \
    --arg dump_filename "$dump_file" \
    --argjson size_bytes "$size_bytes" \
    --arg sha256 "$sha" \
    --arg local_path "$local_path" \
    --arg remote_path "$remote_path" \
    --argjson duration_ms "$duration_ms" \
    '{
      job_id:$job_id,
      last_attempt_at:$last_attempt_at,
      last_success_at:(if $last_success_at=="" then null else $last_success_at end),
      last_exit_code:$last_exit_code,
      last_error:(if $last_error=="" then null else $last_error end),
      last_backup:(if $dump_filename=="" then null else
        {filename:$dump_filename, size_bytes:$size_bytes, sha256:$sha256, local_path:(if $local_path=="" then null else $local_path end), remote_path:(if $remote_path=="" then null else $remote_path end), duration_ms:$duration_ms}
      end)
    }')"

  safe_write_atomic "$st" 600 root root "$content" || true
}

update_restore_test_state() {
  # args: job_id status message backup_file
  local job_id="$1" status="$2" message="$3" backup_file="$4"
  local st tmp now
  st="$(safe_state_path "$job_id")"
  now="$(ts_utc)"
  tmp="$(mktemp)" || return 0
  umask 077

  if [ -f "$st" ]; then
    if ! jq -c \
      --arg at "$now" \
      --arg status "$status" \
      --arg message "$message" \
      --arg backup "$backup_file" \
      '
      .last_restore_test_at = $at
      | .last_restore_test = {
          at:$at,
          status:$status,
          message:(if $message=="" then null else $message end),
          backup_filename:(if $backup=="" then null else $backup end)
        }
      ' "$st" >"$tmp" 2>/dev/null; then
      jq -c -n \
        --arg job_id "$job_id" \
        --arg at "$now" \
        --arg status "$status" \
        --arg message "$message" \
        --arg backup "$backup_file" \
        '{
          job_id:$job_id,
          last_restore_test_at:$at,
          last_restore_test:{
            at:$at,
            status:$status,
            message:(if $message=="" then null else $message end),
            backup_filename:(if $backup=="" then null else $backup end)
          }
        }' >"$tmp" 2>/dev/null || true
    fi
  else
    jq -c -n \
      --arg job_id "$job_id" \
      --arg at "$now" \
      --arg status "$status" \
      --arg message "$message" \
      --arg backup "$backup_file" \
      '{
        job_id:$job_id,
        last_restore_test_at:$at,
        last_restore_test:{
          at:$at,
          status:$status,
          message:(if $message=="" then null else $message end),
          backup_filename:(if $backup=="" then null else $backup end)
        }
      }' >"$tmp" 2>/dev/null || true
  fi

  install -m 600 -o root -g root "$tmp" "$st" >/dev/null 2>&1 || true
  rm -f "$tmp" >/dev/null 2>&1 || true
}

###############################################
# Remote rsync
###############################################
remote_prepare_dir() {
  local target="$1" port="$2" identity="$3" rdir="$4"

  local -a ssh_cmd=()
  IFS=$'\0' read -r -d '' -a ssh_cmd < <(ssh_cmd_build "$port" "$identity" && printf '\0')
  "${ssh_cmd[@]}" "$target" "mkdir -p -- $(sh_q "$rdir") && chmod 700 -- $(sh_q "$rdir")" >/dev/null
}

remote_upload_atomic() {
  local target="$1" port="$2" identity="$3" rdir="$4" src_dir="$5"
  shift 5
  local -a files=("$@")

  local ssh_e
  ssh_e="$(rsync_ssh_e "$port" "$identity")"

  local -a ssh_cmd=()
  IFS=$'\0' read -r -d '' -a ssh_cmd < <(ssh_cmd_build "$port" "$identity" && printf '\0')

  local f
  for f in "${files[@]}"; do
    rsync -a --chmod=F600 -e "$ssh_e" "${src_dir}/${f}" "${target}:${rdir}/${f}.partial" >/dev/null || return 1
    "${ssh_cmd[@]}" "$target" "mv -f -- $(sh_q "${rdir}/${f}.partial") $(sh_q "${rdir}/${f}")" >/dev/null || return 1
  done
}

remote_verify_sha256() {
  local target="$1" port="$2" identity="$3" rdir="$4" sha="$5"

  local -a ssh_cmd=()
  IFS=$'\0' read -r -d '' -a ssh_cmd < <(ssh_cmd_build "$port" "$identity" && printf '\0')
  "${ssh_cmd[@]}" "$target" "cd -- $(sh_q "$rdir") && sha256sum -c -- $(sh_q "$sha")" >/dev/null
}

###############################################
# Retention (local + remote)
###############################################
delete_backup_set_local() {
  local dir="$1" dump="$2"
  local base meta sha
  base="${dump%.sql.zst.age}"
  meta="${base}.meta.json"
  sha="${dump}.sha256"
  rm -f -- "${dir}/${dump}" "${dir}/${sha}" "${dir}/${meta}" 2>/dev/null || true
}

retention_local() {
  local cfg="$1"
  local job_id local_enabled local_dir
  job_id="$(jq -r '.job_id' "$cfg")"
  local_enabled="$(jq -r '.destinations.local.enabled // false' "$cfg")"
  [ "$local_enabled" = "true" ] || return 0
  local_dir="$(jq -r '.destinations.local.path // empty' "$cfg")"
  [ -n "$local_dir" ] || return 0
  [ -d "$local_dir" ] || return 0

  local daily_days monthly_years
  daily_days="$(jq -r '.retention.daily_days // 0' "$cfg")"
  monthly_years="$(jq -r '.retention.monthly_years // 0' "$cfg")"

  if [ "${daily_days:-0}" -le 0 ] && [ "${monthly_years:-0}" -le 0 ]; then
    return 0
  fi

  local cutoff_daily cutoff_monthly
  cutoff_daily="00000000_000000"
  if [ "${daily_days:-0}" -gt 0 ]; then
    cutoff_daily="$(utc_cutoff_stamp_days_ago "$daily_days")"
  fi

  cutoff_monthly="00000000_000000"
  if [ "${monthly_years:-0}" -gt 0 ]; then
    cutoff_monthly="$(utc_cutoff_stamp_years_ago "$monthly_years")"
  fi

  local -a dumps=()
  mapfile -t dumps < <(find "$local_dir" -maxdepth 1 -type f -name '*_full.sql.zst.age' -printf '%f\n' 2>/dev/null | sort || true)
  [ "${#dumps[@]}" -gt 0 ] || return 0

  declare -A month_latest_stamp=()
  declare -A month_latest_dump=()

  local d stamp month
  for d in "${dumps[@]}"; do
    if [[ "$d" =~ _([0-9]{8}_[0-9]{6})_full\.sql\.zst\.age$ ]]; then
      stamp="${BASH_REMATCH[1]}"
      month="${stamp:0:6}"
      if [ -z "${month_latest_stamp[$month]+x}" ] || [[ "$stamp" > "${month_latest_stamp[$month]}" ]]; then
        month_latest_stamp["$month"]="$stamp"
        month_latest_dump["$month"]="$d"
      fi
    fi
  done

  local keep
  for d in "${dumps[@]}"; do
    keep="false"
    if [[ "$d" =~ _([0-9]{8}_[0-9]{6})_full\.sql\.zst\.age$ ]]; then
      stamp="${BASH_REMATCH[1]}"
      month="${stamp:0:6}"

      if [ "${daily_days:-0}" -gt 0 ] && ( [[ "$stamp" > "$cutoff_daily" ]] || [ "$stamp" = "$cutoff_daily" ] ); then
        keep="true"
      else
        if [ "${monthly_years:-0}" -gt 0 ] && ( [[ "$stamp" > "$cutoff_monthly" ]] || [ "$stamp" = "$cutoff_monthly" ] ); then
          if [ "${month_latest_dump[$month]:-}" = "$d" ]; then
            keep="true"
          fi
        fi
      fi
    fi

    if [ "$keep" != "true" ]; then
      info "Retention local: suppression ${job_id}/${d}"
      delete_backup_set_local "$local_dir" "$d"
    fi
  done
}

remote_ls() {
  local target="$1" port="$2" identity="$3" rdir="$4"

  local -a ssh_cmd=()
  IFS=$'\0' read -r -d '' -a ssh_cmd < <(ssh_cmd_build "$port" "$identity" && printf '\0')
  "${ssh_cmd[@]}" "$target" "ls -1 -- $(sh_q "$rdir") 2>/dev/null" 2>/dev/null || true
}

remote_rm_set() {
  local target="$1" port="$2" identity="$3" rdir="$4" dump="$5"
  local base meta sha
  base="${dump%.sql.zst.age}"
  meta="${base}.meta.json"
  sha="${dump}.sha256"

  local -a ssh_cmd=()
  IFS=$'\0' read -r -d '' -a ssh_cmd < <(ssh_cmd_build "$port" "$identity" && printf '\0')
  "${ssh_cmd[@]}" "$target" "rm -f -- $(sh_q "${rdir}/${dump}") $(sh_q "${rdir}/${sha}") $(sh_q "${rdir}/${meta}")" >/dev/null 2>&1 || true
}

retention_remote() {
  local cfg="$1"
  local job_id rem_enabled
  job_id="$(jq -r '.job_id' "$cfg")"
  rem_enabled="$(jq -r '.destinations.remote_rsync.enabled // false' "$cfg")"
  [ "$rem_enabled" = "true" ] || return 0

  local target port identity base_path host_short remote_dir
  target="$(jq -r '.destinations.remote_rsync.target // empty' "$cfg")"
  port="$(jq -r '.destinations.remote_rsync.ssh_port // 22' "$cfg")"
  identity="$(jq -r '.destinations.remote_rsync.ssh_identity_file // ""' "$cfg")"
  base_path="$(jq -r '.destinations.remote_rsync.remote_base_path // empty' "$cfg")"
  host_short="$(hostname -s | tr -cd 'a-zA-Z0-9_-')"
  [ -n "$host_short" ] || host_short="host"
  remote_dir="${base_path%/}/${host_short}/${job_id}"

  local daily_days monthly_years
  daily_days="$(jq -r '.retention.daily_days // 0' "$cfg")"
  monthly_years="$(jq -r '.retention.monthly_years // 0' "$cfg")"

  if [ "${daily_days:-0}" -le 0 ] && [ "${monthly_years:-0}" -le 0 ]; then
    return 0
  fi

  local cutoff_daily cutoff_monthly
  cutoff_daily="00000000_000000"
  if [ "${daily_days:-0}" -gt 0 ]; then
    cutoff_daily="$(utc_cutoff_stamp_days_ago "$daily_days")"
  fi

  cutoff_monthly="00000000_000000"
  if [ "${monthly_years:-0}" -gt 0 ]; then
    cutoff_monthly="$(utc_cutoff_stamp_years_ago "$monthly_years")"
  fi

  local -a all=() dumps=()
  mapfile -t all < <(remote_ls "$target" "$port" "$identity" "$remote_dir")
  local f
  for f in "${all[@]}"; do
    f="$(trim "$f")"
    [ -n "$f" ] || continue
    if [[ "$f" =~ _[0-9]{8}_[0-9]{6}_full\.sql\.zst\.age$ ]]; then
      dumps+=("$f")
    fi
  done
  [ "${#dumps[@]}" -gt 0 ] || return 0
  IFS=$'\n' dumps=($(printf "%s\n" "${dumps[@]}" | sort)); IFS=$'\n\t'

  declare -A month_latest_stamp=()
  declare -A month_latest_dump=()

  local d stamp month
  for d in "${dumps[@]}"; do
    if [[ "$d" =~ _([0-9]{8}_[0-9]{6})_full\.sql\.zst\.age$ ]]; then
      stamp="${BASH_REMATCH[1]}"
      month="${stamp:0:6}"
      if [ -z "${month_latest_stamp[$month]+x}" ] || [[ "$stamp" > "${month_latest_stamp[$month]}" ]]; then
        month_latest_stamp["$month"]="$stamp"
        month_latest_dump["$month"]="$d"
      fi
    fi
  done

  local keep
  for d in "${dumps[@]}"; do
    keep="false"
    if [[ "$d" =~ _([0-9]{8}_[0-9]{6})_full\.sql\.zst\.age$ ]]; then
      stamp="${BASH_REMATCH[1]}"
      month="${stamp:0:6}"

      if [ "${daily_days:-0}" -gt 0 ] && ( [[ "$stamp" > "$cutoff_daily" ]] || [ "$stamp" = "$cutoff_daily" ] ); then
        keep="true"
      else
        if [ "${monthly_years:-0}" -gt 0 ] && ( [[ "$stamp" > "$cutoff_monthly" ]] || [ "$stamp" = "$cutoff_monthly" ] ); then
          if [ "${month_latest_dump[$month]:-}" = "$d" ]; then
            keep="true"
          fi
        fi
      fi
    fi

    if [ "$keep" != "true" ]; then
      info "Retention remote: suppression ${job_id}/${d}"
      remote_rm_set "$target" "$port" "$identity" "$remote_dir" "$d"
    fi
  done
}

###############################################
# Restore test (partiel, sans clé privée)
###############################################
restore_test_due() {
  # args: cfg st_path
  local cfg="$1" st="$2"

  local every_days
  every_days="$(jq -r '.restore_test.every_days // 0' "$cfg" 2>/dev/null || printf "0")"
  every_days="$(trim "$every_days")"
  if [[ ! "$every_days" =~ ^[0-9]+$ ]] || [ "$every_days" -le 0 ]; then
    printf "false"
    return 0
  fi

  local last_iso last_epoch now
  last_iso=""
  if [ -f "$st" ]; then
    last_iso="$(jq -r '.last_restore_test_at // empty' "$st" 2>/dev/null || true)"
  fi
  last_epoch="$(iso_to_epoch_utc "$last_iso")"
  now="$(date -u +%s)"

  if [ -z "${last_epoch:-}" ]; then
    printf "true"
    return 0
  fi

  if [ $(( now - last_epoch )) -ge $(( every_days * 86400 )) ]; then
    printf "true"
  else
    printf "false"
  fi
}

check_age_header_local() {
  local f="$1"
  head -c 32 "$f" 2>/dev/null | grep -a -q 'age-encryption.org/v1'
}

check_backup_set_local_partial() {
  # args: local_dir dump_file pub_fpr
  local local_dir="$1" dump_file="$2" pubfpr="$3"
  local dump_path sha_path meta_path base

  dump_path="${local_dir%/}/${dump_file}"
  sha_path="${local_dir%/}/${dump_file}.sha256"
  base="${dump_file%.sql.zst.age}"
  meta_path="${local_dir%/}/${base}.meta.json"

  [ -f "$dump_path" ] || { printf "%s" "local: dump introuvable (${dump_path})"; return 1; }
  [ -f "$sha_path" ]  || { printf "%s" "local: sha256 introuvable (${sha_path})"; return 1; }
  [ -f "$meta_path" ] || { printf "%s" "local: meta introuvable (${meta_path})"; return 1; }

  if ! check_age_header_local "$dump_path"; then
    printf "%s" "local: header age absent (fichier suspect)"
    return 1
  fi

  # checksum
  if ! ( cd "$local_dir" && sha256sum -c -- "$(basename "$sha_path")" >/dev/null ); then
    printf "%s" "local: sha256sum -c KO"
    return 1
  fi

  # meta cohérence: sha/size/pubkey_fingerprint
  local meta_sha meta_size meta_pub actual_size
  meta_sha="$(jq -r '.dump.sha256 // empty' "$meta_path" 2>/dev/null || true)"
  meta_size="$(jq -r '.dump.size_bytes // empty' "$meta_path" 2>/dev/null || true)"
  meta_pub="$(jq -r '.encryption.recipient_pubkey_fingerprint // empty' "$meta_path" 2>/dev/null || true)"
  actual_size="$(stat -c %s "$dump_path" 2>/dev/null || printf "0")"

  if [ -z "$meta_sha" ] || [ -z "$meta_size" ]; then
    printf "%s" "local: meta invalide (sha/size manquant)"
    return 1
  fi
  if [ "$meta_size" != "$actual_size" ]; then
    printf "%s" "local: size mismatch (meta=${meta_size} != actual=${actual_size})"
    return 1
  fi
  if [ -n "$meta_pub" ] && [ -n "$pubfpr" ] && [ "$meta_pub" != "$pubfpr" ]; then
    printf "%s" "local: pubkey fingerprint mismatch (meta=${meta_pub} != current=${pubfpr})"
    return 1
  fi

  printf "%s" "local: OK"
  return 0
}

check_backup_set_remote_partial() {
  # args: cfg job_id dump_file pub_fpr
  local cfg="$1" job_id="$2" dump_file="$3" pubfpr="$4"

  local target port identity base_path host_short remote_dir
  target="$(jq -r '.destinations.remote_rsync.target // empty' "$cfg")"
  port="$(jq -r '.destinations.remote_rsync.ssh_port // 22' "$cfg")"
  identity="$(jq -r '.destinations.remote_rsync.ssh_identity_file // ""' "$cfg")"
  base_path="$(jq -r '.destinations.remote_rsync.remote_base_path // empty' "$cfg")"

  host_short="$(hostname -s | tr -cd 'a-zA-Z0-9_-')"
  [ -n "$host_short" ] || host_short="host"
  remote_dir="${base_path%/}/${host_short}/${job_id}"

  if [ -z "$target" ] || [ -z "$base_path" ]; then
    printf "%s" "remote: target/base_path vide"
    return 1
  fi

  local base meta_file sha_file
  base="${dump_file%.sql.zst.age}"
  sha_file="${dump_file}.sha256"
  meta_file="${base}.meta.json"

  local -a ssh_cmd=()
  IFS=$'\0' read -r -d '' -a ssh_cmd < <(ssh_cmd_build "$port" "$identity" && printf '\0')

  # existence
  "${ssh_cmd[@]}" "$target" "test -f $(sh_q "${remote_dir}/${dump_file}") && test -f $(sh_q "${remote_dir}/${sha_file}") && test -f $(sh_q "${remote_dir}/${meta_file}")" >/dev/null 2>&1 || {
    printf "%s" "remote: fichiers manquants (${remote_dir})"
    return 1
  }

  # header age (best-effort)
  "${ssh_cmd[@]}" "$target" "head -c 32 -- $(sh_q "${remote_dir}/${dump_file}") | grep -a -q 'age-encryption.org/v1'" >/dev/null 2>&1 || {
    printf "%s" "remote: header age absent (fichier suspect)"
    return 1
  }

  # checksum
  "${ssh_cmd[@]}" "$target" "cd -- $(sh_q "$remote_dir") && sha256sum -c -- $(sh_q "$sha_file")" >/dev/null 2>&1 || {
    printf "%s" "remote: sha256sum -c KO"
    return 1
  }

  # meta cohérence pubkey_fingerprint (best-effort)
  if [ -n "$pubfpr" ]; then
    "${ssh_cmd[@]}" "$target" "cd -- $(sh_q "$remote_dir") && jq -r '.encryption.recipient_pubkey_fingerprint // empty' $(sh_q "$meta_file") | grep -qx $(sh_q "$pubfpr")" >/dev/null 2>&1 || {
      printf "%s" "remote: pubkey fingerprint mismatch (meta != current)"
      return 1
    }
  fi

  printf "%s" "remote: OK"
  return 0
}

restore_test_run_partial() {
  # stdout: message ; exit: 0 ok / 1 fail
  local cfg="$1"

  local job_id db_name
  job_id="$(jq -r '.job_id // empty' "$cfg")"
  db_name="$(jq -r '.db.name // empty' "$cfg")"

  local st dump_file
  st="$(safe_state_path "$job_id")"
  dump_file=""
  if [ -f "$st" ]; then
    dump_file="$(jq -r '.last_backup.filename // empty' "$st" 2>/dev/null || true)"
  fi
  dump_file="$(trim "$dump_file")"
  if [ -z "$dump_file" ]; then
    printf "%s" "Aucun backup précédent à tester (state vide). Faites un restore manuel quand un backup existe."
    return 1
  fi

  local pubfile pubfpr
  pubfile="$(jq -r '.encryption.recipient_pubkey_file // empty' "$cfg")"
  pubfpr=""
  if [ -n "$pubfile" ] && [ -f "$pubfile" ]; then
    pubfpr="$(pubkey_fingerprint "$pubfile")"
  fi

  local local_enabled local_dir rem_enabled
  local_enabled="$(jq -r '.destinations.local.enabled // false' "$cfg")"
  local_dir="$(jq -r '.destinations.local.path // empty' "$cfg")"
  rem_enabled="$(jq -r '.destinations.remote_rsync.enabled // false' "$cfg")"

  local msg_local msg_remote
  msg_local=""
  msg_remote=""

  if [ "$local_enabled" = "true" ]; then
    if [ -z "$local_dir" ] || [ ! -d "$local_dir" ]; then
      printf "%s" "local: path invalide (local_dir='${local_dir}')"
      return 1
    fi
    if ! msg_local="$(check_backup_set_local_partial "$local_dir" "$dump_file" "$pubfpr")"; then
      printf "%s" "${msg_local}"
      return 1
    fi
  else
    msg_local="local: off"
  fi

  if [ "$rem_enabled" = "true" ]; then
    if ! msg_remote="$(check_backup_set_remote_partial "$cfg" "$job_id" "$dump_file" "$pubfpr")"; then
      printf "%s" "${msg_remote}"
      return 1
    fi
  else
    msg_remote="remote: off"
  fi

  printf "%s" "${msg_local}; ${msg_remote}. Restore COMPLET manuel recommandé."
  return 0
}

restore_test_maybe() {
  # args: cfg dry_bool
  local cfg="$1" dry="$2"
  [ "$dry" = "true" ] && return 0

  local job_id db_name st
  job_id="$(jq -r '.job_id // empty' "$cfg")"
  db_name="$(jq -r '.db.name // empty' "$cfg")"
  st="$(safe_state_path "$job_id")"

  local due
  due="$(restore_test_due "$cfg" "$st")"
  [ "$due" = "true" ] || return 0

  local every_days
  every_days="$(jq -r '.restore_test.every_days // 0' "$cfg" 2>/dev/null || printf "0")"
  every_days="$(trim "$every_days")"
  if [[ ! "$every_days" =~ ^[0-9]+$ ]]; then
    every_days="0"
  fi

  info "${job_id}: restore_test partiel dû (every_days=${every_days})"

  local dump_file
  dump_file=""
  if [ -f "$st" ]; then
    dump_file="$(jq -r '.last_backup.filename // empty' "$st" 2>/dev/null || true)"
  fi
  dump_file="$(trim "$dump_file")"

  local msg
  if msg="$(restore_test_run_partial "$cfg")"; then
    webhook_restore_test "$cfg" "restore_test.reminder" "$job_id" "$db_name" "ok" "$msg" "$dump_file" "$every_days"
    update_restore_test_state "$job_id" "ok" "$msg" "$dump_file"
  else
    webhook_restore_test "$cfg" "restore_test.partial_failure" "$job_id" "$db_name" "fail" "$msg" "$dump_file" "$every_days"
    update_restore_test_state "$job_id" "fail" "$msg" "$dump_file"
  fi

  return 0
}

###############################################
# Backup job execution
###############################################
run_job() {
  # args: cfg_path force_bool dry_run_bool
  local cfg="$1" force="$2" dry="$3"

  local job_id db_name
  job_id="$(jq -r '.job_id' "$cfg")"
  db_name="$(jq -r '.db.name' "$cfg")"

  local st
  st="$(safe_state_path "$job_id")"

  local due
  due="$(is_due "$cfg" "$st" "$force")"
  if [ "$due" != "true" ]; then
    info "Skip (pas dû): ${job_id} (db=${db_name})"
    return 0
  fi

  if ! validate_cfg_or_fail "$cfg"; then
    webhook_event "$cfg" "backup.failure" "$job_id" "$db_name" "validate" 10 "Config invalide" 0 0 false false ""
    update_state "$job_id" "$(ts_utc)" "" 10 "Config invalide" "" 0 "" "" "" 0
    return 10
  fi

  local local_enabled local_dir rem_enabled
  local_enabled="$(jq -r '.destinations.local.enabled // false' "$cfg")"
  local_dir="$(jq -r '.destinations.local.path // empty' "$cfg")"
  rem_enabled="$(jq -r '.destinations.remote_rsync.enabled // false' "$cfg")"

  local fs_check_path
  if [ "$local_enabled" = "true" ] && [ -n "$local_dir" ]; then
    fs_check_path="$local_dir"
  else
    fs_check_path="$TMP_BASE"
  fi

  if ! check_min_free_space "$fs_check_path" "$MIN_FREE_GB_DEFAULT"; then
    err "Espace disque insuffisant sur ${fs_check_path} (min=${MIN_FREE_GB_DEFAULT}GB)"
    webhook_event "$cfg" "backup.failure" "$job_id" "$db_name" "disk" 11 "Espace disque insuffisant" 0 0 \
      $([ "$local_enabled" = "true" ] && echo true || echo false) \
      $([ "$rem_enabled" = "true" ] && echo true || echo false) \
      ""
    update_state "$job_id" "$(ts_utc)" "" 11 "Espace disque insuffisant" "" 0 "" "" "" 0
    return 11
  fi

  local stamp base dump_file sha_file meta_file
  stamp="$(utc_stamp_now)"
  base="${db_name}_${stamp}_full"
  dump_file="${base}.sql.zst.age"
  sha_file="${dump_file}.sha256"
  meta_file="${base}.meta.json"

  local tmpdir
  tmpdir="${TMP_BASE}/${job_id}/${stamp}"

  if [ "$dry" = "true" ]; then
    info "[DRY] Job dû: ${job_id} => ${dump_file}"
    return 0
  fi

  install -d -m 750 -o root -g root "$tmpdir" || {
    err "Impossible de créer tmpdir: $tmpdir"
    webhook_event "$cfg" "backup.failure" "$job_id" "$db_name" "tmpdir" 12 "Tmpdir KO" 0 0 \
      $([ "$local_enabled" = "true" ] && echo true || echo false) \
      $([ "$rem_enabled" = "true" ] && echo true || echo false) \
      ""
    update_state "$job_id" "$(ts_utc)" "" 12 "Tmpdir KO" "" 0 "" "" "" 0
    return 12
  }

  local started_epoch finished_epoch duration_ms
  started_epoch="$(date +%s%3N 2>/dev/null || printf "0")"

  local step exit_code error_msg
  step="dump"
  exit_code=0
  error_msg=""

  local pubfile pubfpr
  pubfile="$(jq -r '.encryption.recipient_pubkey_file' "$cfg")"
  pubfpr="$(pubkey_fingerprint "$pubfile")"

  # Dump options
  local single_tx routines triggers events zlevel
  single_tx="$(jq -r '.dump.single_transaction // true' "$cfg")"
  routines="$(jq -r '.dump.routines // true' "$cfg")"
  triggers="$(jq -r '.dump.triggers // true' "$cfg")"
  events="$(jq -r '.dump.events // true' "$cfg")"
  zlevel="$(jq -r '.compression.level // 6' "$cfg")"

  local -a dump_opts=()
  dump_opts+=(--user=root --protocol=socket)
  dump_opts+=(--default-character-set=utf8mb4)
  dump_opts+=(--quick)

  # IMPORTANT: on dump la DB en argument (pas --databases) => pas de CREATE DATABASE/USE dans le dump
  if [ "$single_tx" = "true" ]; then dump_opts+=(--single-transaction); fi
  if [ "$routines" = "true" ]; then dump_opts+=(--routines); fi
  if [ "$triggers" = "true" ]; then dump_opts+=(--triggers); fi
  if [ "$events"   = "true" ]; then dump_opts+=(--events); fi

  if dump_supports_column_statistics; then
    dump_opts+=(--column-statistics=0)
  fi

  local out_partial out_final
  out_partial="${tmpdir}/${dump_file}.partial"
  out_final="${tmpdir}/${dump_file}"

  if ( "$(dump_bin)" "${dump_opts[@]}" "$db_name" 2>>"${LOG_DIR}/${job_id}.log" \
        | zstd "-${zlevel}" --stdout 2>>"${LOG_DIR}/${job_id}.log" \
        | age -R "$pubfile" -o "$out_partial" 2>>"${LOG_DIR}/${job_id}.log" ); then
    :
  else
    exit_code=$?
    error_msg="Pipeline dump|zstd|age échoué (exit=$exit_code)"
    err "${job_id}: ${error_msg} — logs: /var/log/${APP_NAME}/${job_id}.log"
    rm -f "$out_partial" >/dev/null 2>&1 || true
    webhook_event "$cfg" "backup.failure" "$job_id" "$db_name" "$step" "$exit_code" "$error_msg" 0 0 \
      $([ "$local_enabled" = "true" ] && echo true || echo false) \
      $([ "$rem_enabled" = "true" ] && echo true || echo false) \
      "$dump_file"
    update_state "$job_id" "$(ts_utc)" "" "$exit_code" "$error_msg" "" 0 "" "" "" 0
    rm -rf "$tmpdir" >/dev/null 2>&1 || true
    return "$exit_code"
  fi

  step="rename"
  mv -f -- "$out_partial" "$out_final" || {
    exit_code=13
    error_msg="Rename .partial => final KO"
    err "${job_id}: ${error_msg}"
    webhook_event "$cfg" "backup.failure" "$job_id" "$db_name" "$step" "$exit_code" "$error_msg" 0 0 \
      $([ "$local_enabled" = "true" ] && echo true || echo false) \
      $([ "$rem_enabled" = "true" ] && echo true || echo false) \
      "$dump_file"
    update_state "$job_id" "$(ts_utc)" "" "$exit_code" "$error_msg" "" 0 "" "" "" 0
    rm -rf "$tmpdir" >/dev/null 2>&1 || true
    return "$exit_code"
  }

  step="checksum"
  local sha size_bytes
  sha="$(sha256sum "$out_final" | awk '{print $1}')"
  size_bytes="$(stat -c %s "$out_final" 2>/dev/null || printf "0")"
  printf "%s  %s\n" "$sha" "$dump_file" >"${tmpdir}/${sha_file}"

  step="metadata"
  write_metadata "${tmpdir}/${meta_file}" "$job_id" "$db_name" "$stamp" "$dump_file" "$sha" "$size_bytes" 0 "$zlevel" \
    $([ "$local_enabled" = "true" ] && echo true || echo false) \
    $([ "$rem_enabled" = "true" ] && echo true || echo false) \
    "$pubfpr" || true

  # Placement local
  step="local"
  local final_dir=""
  if [ "$local_enabled" = "true" ]; then
    if [ -z "$local_dir" ]; then
      exit_code=14
      error_msg="destinations.local.path vide"
    else
      install -d -m 750 -o root -g root "$local_dir" || {
        exit_code=14
        error_msg="mkdir local_dir KO: $local_dir"
      }
      if [ "$exit_code" -eq 0 ]; then
        mv -f -- "${tmpdir}/${dump_file}" "${local_dir}/${dump_file}" || { exit_code=14; error_msg="mv dump -> local KO"; }
        if [ "$exit_code" -eq 0 ]; then mv -f -- "${tmpdir}/${sha_file}"  "${local_dir}/${sha_file}"  || { exit_code=14; error_msg="mv sha -> local KO"; } fi
        if [ "$exit_code" -eq 0 ]; then mv -f -- "${tmpdir}/${meta_file}" "${local_dir}/${meta_file}" || { exit_code=14; error_msg="mv meta -> local KO"; } fi
        if [ "$exit_code" -eq 0 ]; then
          final_dir="$local_dir"
        fi
      fi
    fi
  else
    final_dir="$tmpdir"
  fi

  if [ "$exit_code" -ne 0 ]; then
    err "${job_id}: ${error_msg}"
    webhook_event "$cfg" "backup.failure" "$job_id" "$db_name" "$step" "$exit_code" "$error_msg" 0 "$size_bytes" \
      $([ "$local_enabled" = "true" ] && echo true || echo false) \
      $([ "$rem_enabled" = "true" ] && echo true || echo false) \
      "$dump_file"
    update_state "$job_id" "$(ts_utc)" "" "$exit_code" "$error_msg" "" 0 "" "" "" 0
    rm -rf "$tmpdir" >/dev/null 2>&1 || true
    return "$exit_code"
  fi

  # Remote rsync
  step="remote"
  local remote_path_full=""
  if [ "$rem_enabled" = "true" ]; then
    local target port identity base_path host_short remote_dir
    target="$(jq -r '.destinations.remote_rsync.target // empty' "$cfg")"
    port="$(jq -r '.destinations.remote_rsync.ssh_port // 22' "$cfg")"
    identity="$(jq -r '.destinations.remote_rsync.ssh_identity_file // ""' "$cfg")"
    base_path="$(jq -r '.destinations.remote_rsync.remote_base_path // empty' "$cfg")"

    host_short="$(hostname -s | tr -cd 'a-zA-Z0-9_-')"
    [ -n "$host_short" ] || host_short="host"
    remote_dir="${base_path%/}/${host_short}/${job_id}"

    if [ -z "$target" ] || [ -z "$base_path" ]; then
      exit_code=15
      error_msg="Remote target/base_path vide"
    else
      remote_prepare_dir "$target" "$port" "$identity" "$remote_dir" || {
        exit_code=15
        error_msg="Remote mkdir/chmod KO"
      }
    fi

    if [ "$exit_code" -eq 0 ]; then
      local src_dir="$final_dir"
      remote_upload_atomic "$target" "$port" "$identity" "$remote_dir" "$src_dir" "$dump_file" "$sha_file" "$meta_file" || {
        exit_code=16
        error_msg="Rsync upload KO"
      }
    fi

    if [ "$exit_code" -eq 0 ]; then
      remote_verify_sha256 "$target" "$port" "$identity" "$remote_dir" "$sha_file" || {
        exit_code=17
        error_msg="Remote sha256sum -c KO"
      }
    fi

    if [ "$exit_code" -ne 0 ]; then
      err "${job_id}: ${error_msg}"
      webhook_event "$cfg" "backup.failure" "$job_id" "$db_name" "$step" "$exit_code" "$error_msg" 0 "$size_bytes" \
        $([ "$local_enabled" = "true" ] && echo true || echo false) \
        $([ "$rem_enabled" = "true" ] && echo true || echo false) \
        "$dump_file"
      update_state "$job_id" "$(ts_utc)" "" "$exit_code" "$error_msg" "" 0 "" "" "" 0
      if [ "$local_enabled" != "true" ]; then
        rm -rf "$tmpdir" >/dev/null 2>&1 || true
      fi
      return "$exit_code"
    fi

    remote_path_full="${remote_dir}/${dump_file}"
  fi

  finished_epoch="$(date +%s%3N 2>/dev/null || printf "0")"
  if [[ "$started_epoch" =~ ^[0-9]+$ ]] && [[ "$finished_epoch" =~ ^[0-9]+$ ]] && [ "$started_epoch" -gt 0 ]; then
    duration_ms=$(( finished_epoch - started_epoch ))
  else
    duration_ms=0
  fi

  # Patch duration dans meta (best-effort)
  if [ "$local_enabled" = "true" ] && [ -n "$local_dir" ] && [ -f "${local_dir}/${meta_file}" ]; then
    jq --argjson d "$duration_ms" '.dump.duration_ms=$d' "${local_dir}/${meta_file}" >"${local_dir}/${meta_file}.tmp" 2>/dev/null \
      && mv -f "${local_dir}/${meta_file}.tmp" "${local_dir}/${meta_file}" || true
  elif [ -f "${tmpdir}/${meta_file}" ]; then
    jq --argjson d "$duration_ms" '.dump.duration_ms=$d' "${tmpdir}/${meta_file}" >"${tmpdir}/${meta_file}.tmp" 2>/dev/null \
      && mv -f "${tmpdir}/${meta_file}.tmp" "${tmpdir}/${meta_file}" || true
  fi

  local local_path_full=""
  if [ "$local_enabled" = "true" ]; then
    local_path_full="${local_dir}/${dump_file}"
  fi

  info "${job_id}: backup OK"
  if [ -n "$local_path_full" ]; then
    info "  - Local : ${local_path_full}"
  fi
  if [ -n "$remote_path_full" ]; then
    info "  - Remote: ${remote_path_full}"
  fi

  update_state "$job_id" "$(ts_utc)" "$(ts_utc)" 0 "" "$dump_file" "$size_bytes" "$sha" "$local_path_full" "$remote_path_full" "$duration_ms"

  local notify_success
  notify_success="$(jq -r '.webhook.notify.success // false' "$cfg")"
  if [ "$notify_success" = "true" ]; then
    webhook_event "$cfg" "backup.success" "$job_id" "$db_name" "done" 0 "" "$duration_ms" "$size_bytes" \
      $([ "$local_enabled" = "true" ] && echo true || echo false) \
      $([ "$rem_enabled" = "true" ] && echo true || echo false) \
      "$dump_file"
  fi

  retention_local "$cfg" || true
  retention_remote "$cfg" || true

  rm -rf "$tmpdir" >/dev/null 2>&1 || true
  return 0
}

###############################################
# Lock global
###############################################
acquire_lock_or_exit() {
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    info "Lock déjà pris => sortie (un runner tourne déjà)."
    exit 0
  fi
}

###############################################
# Wizard (manuel)
###############################################
is_tty() { [ -t 0 ] && [ -t 1 ]; }

bridge_restore() {
  if [ -f "$RESTORE_SH" ]; then
    info "Bascule vers: ${RESTORE_SH}"
    exec bash "$RESTORE_SH"
  fi
  warn "Introuvable: ${RESTORE_SH}"
}

count_local_dumps() {
  local dir="$1"
  [ -d "$dir" ] || { printf "0"; return 0; }
  find "$dir" -maxdepth 1 -type f -name '*_full.sql.zst.age' | wc -l | tr -d ' '
}

last_backup_from_state() {
  local job_id="$1" st
  st="$(safe_state_path "$job_id")"
  if [ -f "$st" ]; then
    jq -r '.last_success_at // empty' "$st" 2>/dev/null || true
  fi
}

cron_exists() {
  local self
  self="$(readlink -f "$0")"
  grep -R --line-number -F "$self" /etc/cron.d /etc/crontab /var/spool/cron/crontabs 2>/dev/null | grep -q .
}

install_cron() {
  local self
  self="$(readlink -f "$0")"
  local cron_file="/etc/cron.d/${APP_NAME}"
  local line="0 * * * * root ${self} --cron"
  printf "%s\n" "$line" >"$cron_file"
  chmod 0644 "$cron_file"
  chown root:root "$cron_file"
  info "Cron créé: ${cron_file}"
  info "  - ${line}"
}

open_shell_in_dir() {
  local dir="$1"
  local ans=""
  [ -d "$dir" ] || return 0
  printf "\n"
  read -r -p "Ouvrir un shell dans le dossier du dump ? (y/N) " ans
  ans="${ans:-N}"
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    info "Ouverture shell: cd ${dir}"
    cd "$dir" || exit 0
    exec bash --noprofile --norc
  fi
}

wizard_list_jobs() {
  local -a cfgs=()
  shopt -s nullglob
  cfgs=( "${CONFIG_DIR}"/*.json )
  shopt -u nullglob

  if [ "${#cfgs[@]}" -eq 0 ]; then
    warn "Aucun job trouvé dans ${CONFIG_DIR}"
    return 1
  fi

  printf "\nJobs disponibles:\n" >&2
  printf '%s\n' '---------------------------------------------------------------' >&2
  printf "%-3s %-20s %-10s %-6s %-22s %s\n" "#" "job_id" "db" "dumps" "last_success" "local_dir" >&2
  printf '%s\n' '---------------------------------------------------------------' >&2

  local i=1
  local cfg
  for cfg in "${cfgs[@]}"; do
    local job_id db local_enabled local_dir dumps last
    job_id="$(jq -r '.job_id // empty' "$cfg")"
    db="$(jq -r '.db.name // empty' "$cfg")"
    local_enabled="$(jq -r '.destinations.local.enabled // false' "$cfg")"
    local_dir="$(jq -r '.destinations.local.path // ""' "$cfg")"
    dumps="0"

    if [ "$local_enabled" = "true" ] && [ -n "$local_dir" ]; then
      dumps="$(count_local_dumps "$local_dir")"
    fi

    last="$(last_backup_from_state "$job_id")"
    if [ -z "$last" ]; then
      last="—"
    fi

    if [ "$local_enabled" != "true" ]; then
      local_dir="(local off)"
    fi

    printf "%-3s %-20s %-10s %-6s %-22s %s\n" "$i" "$job_id" "$db" "$dumps" "$last" "$local_dir" >&2
    i=$((i+1))
  done

  printf '%s\n' '---------------------------------------------------------------' >&2
  return 0
}

wizard_select_job_id() {
  local job_id=""
  read -r -p "Choisissez un job_id (ou vide pour annuler) : " job_id
  job_id="$(trim "${job_id:-}")"
  [ -n "$job_id" ] || return 1
  [ -f "$(job_cfg_path "$job_id")" ] || { err "Job introuvable: $job_id"; return 1; }
  printf "%s" "$job_id"
}

wizard_menu() {
  while true; do
    printf "\n=== %s runner (wizard) ===\n" "$APP_NAME" >&2
    printf "1) Lister les jobs\n" >&2
    printf "2) Lancer un job maintenant (FORCE)\n" >&2
    printf "3) Lancer TOUS les jobs dus (mode normal)\n" >&2
    printf "4) Vérifier/installer le cron hourly\n" >&2
    if [ -f "$RESTORE_SH" ]; then
      printf "5) Lancer le restore (db-backup-restore.sh)\n" >&2
    else
      printf "5) Lancer le restore (db-backup-restore.sh) (absent)\n" >&2
    fi
    printf "6) Quitter\n" >&2

    local c=""
    read -r -p "Choix: " c
    c="$(trim "${c:-}")"
    case "$c" in
      1)
        wizard_list_jobs || true
        ;;
      2)
        wizard_list_jobs || true
        local jid=""
        if jid="$(wizard_select_job_id)"; then
          info "Run NOW (force) : $jid"
          run_job "$(job_cfg_path "$jid")" "true" "false" || true

          local local_enabled local_dir st dumpfile
          local_enabled="$(jq -r '.destinations.local.enabled // false' "$(job_cfg_path "$jid")")"
          local_dir="$(jq -r '.destinations.local.path // ""' "$(job_cfg_path "$jid")")"
          st="$(safe_state_path "$jid")"
          dumpfile=""
          if [ -f "$st" ]; then
            dumpfile="$(jq -r '.last_backup.filename // empty' "$st" 2>/dev/null || true)"
          fi
          if [ "$local_enabled" = "true" ] && [ -n "$local_dir" ] && [ -n "$dumpfile" ]; then
            info "Dernier dump local: ${local_dir}/${dumpfile}"
            open_shell_in_dir "$local_dir"
          fi
        fi
        ;;
      3)
        info "Run jobs dus (mode normal)"
        return 0
        ;;
      4)
        if cron_exists; then
          info "Cron: OK (une entrée pointe déjà vers ce runner)"
        else
          warn "Cron: introuvable (aucune entrée ne lance ce runner)."
          local ans=""
          read -r -p "Créer /etc/cron.d/${APP_NAME} (hourly) ? (y/N) " ans
          ans="${ans:-N}"
          if [[ "$ans" =~ ^[Yy]$ ]]; then
            install_cron
          fi
        fi
        ;;
      5)
        bridge_restore
        ;;
      6)
        exit 0
        ;;
      *)
        warn "Choix invalide."
        ;;
    esac
  done
}

###############################################
# Mode normal (cron ou manuel args)
###############################################
run_all_jobs() {
  local force="$1" dry="$2" job_filter="$3"

  acquire_lock_or_exit
  info "Runner start (force=${force}, dry=${dry})"

  shopt -s nullglob
  local -a cfgs=( "${CONFIG_DIR}"/*.json )
  shopt -u nullglob

  if [ "${#cfgs[@]}" -eq 0 ]; then
    warn "Aucun job trouvé dans ${CONFIG_DIR}"
    return 0
  fi

  local any_fail=0
  local cfg job_id rc
  for cfg in "${cfgs[@]}"; do
    [ -f "$cfg" ] || continue
    job_id="$(jq -r '.job_id // empty' "$cfg" 2>/dev/null || true)"
    if [ -z "$job_id" ]; then
      err "Config JSON illisible: $cfg"
      any_fail=1
      continue
    fi
    if [ -n "$job_filter" ] && [ "$job_filter" != "$job_id" ]; then
      continue
    fi

    rc=0
    run_job "$cfg" "$force" "$dry" || rc=$?
    if [ "$rc" -ne 0 ]; then
      any_fail=1
    fi

    # Restore test partiel (indépendant du fait que le backup ait tourné ou non)
    restore_test_maybe "$cfg" "$dry" || true
  done

  if [ "$any_fail" -ne 0 ]; then
    err "Runner end: au moins un job en échec."
    return 1
  fi

  info "Runner end: OK"
  return 0
}

###############################################
# CLI
###############################################
JOB_FILTER=""
FORCE="false"
DRY="false"
MODE="auto"  # auto|cron

while [ "$#" -gt 0 ]; do
  case "$1" in
    --job) JOB_FILTER="${2:-}"; shift 2 ;;
    --force) FORCE="true"; shift 1 ;;
    --dry-run) DRY="true"; shift 1 ;;
    --cron) MODE="cron"; shift 1 ;;
    -h|--help)
      cat <<EOF
db-backup-runner.sh V${SCRIPT_VERSION}

Options:
  --cron            Force mode non-interactif (pour cron)
  --job <job_id>    Exécuter un seul job
  --force           Exécuter même si "pas dû"
  --dry-run         N'exécute pas mysqldump/rsync (affiche juste)
EOF
      exit 0
      ;;
    *) err "Option inconnue: $1"; exit 1 ;;
  esac
done

###############################################
# Main
###############################################
require_root
ensure_dirs
ensure_deps

if [ "$MODE" != "cron" ] && [ "$FORCE" = "false" ] && [ "$DRY" = "false" ] && [ -z "$JOB_FILTER" ] && is_tty; then
  print_intro_runner
  wizard_menu
fi

run_all_jobs "$FORCE" "$DRY" "$JOB_FILTER"
exit $?
