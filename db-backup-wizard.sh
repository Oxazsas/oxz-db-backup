#!/usr/bin/env bash
# db-backup-wizard.sh — V3.2 (Ubuntu)
# Script 1/3: Wizard CRUD jobs (JSON) + clés age + tests (DB/rsync/webhook)
# + Ponts vers runner/restore si présents dans le même dossier
# + MODIFIER un job existant
# + Paramètre "restore_test_every_days" (0 = désactivé) préparé pour script futur

set -u -o pipefail
IFS=$'\n\t'
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

###############################################
# Constantes / chemins
###############################################
readonly APP_NAME="oxz-db-backup"
readonly SCRIPT_VERSION="3.2"
readonly VERSION_JSON=1

readonly CONFIG_DIR="/etc/${APP_NAME}/jobs"
readonly KEYS_DIR="/etc/${APP_NAME}/keys"
readonly SECRETS_DIR="/etc/${APP_NAME}/secrets"
readonly STATE_DIR="/var/lib/${APP_NAME}/state"
readonly LOG_DIR="/var/log/${APP_NAME}"

readonly DEFAULT_LOCAL_BASE="/var/backups/${APP_NAME}"
readonly TMP_BASE="${DEFAULT_LOCAL_BASE}/.tmp"

readonly TZ_DEFAULT="Europe/Paris"

# Scripts frères (pont)
readonly SELF_PATH="$(readlink -f "$0" 2>/dev/null || printf "%s" "$0")"
readonly SELF_DIR="$(cd "$(dirname "$SELF_PATH")" >/dev/null 2>&1 && pwd -P || printf "%s" ".")"
readonly RUNNER_SH="${SELF_DIR}/db-backup-runner.sh"
readonly RESTORE_SH="${SELF_DIR}/db-backup-restore.sh"

INTRO_SHOWN="false"

###############################################
# UI / logs
###############################################
info() { printf "\033[1;32m[INFO]\033[0m %s\n" "$*" >&2; }
warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*" >&2; }
err()  { printf "\033[1;31m[ERR ]\033[0m %s\n" "$*" >&2; }

pause() { read -r -p "Appuyez sur Entrée pour continuer..." _; }

tty_out() {
  if [ -c /dev/tty ]; then
    printf "%s" "/dev/tty"
  else
    printf "%s" "/dev/stderr"
  fi
}

###############################################
# Sécurité / helpers
###############################################
require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "Lancez ce script en root (ex: sudo $0)"
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

trim() {
  local s="${1:-}"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf "%s" "$s"
}

validate_job_id() { [[ "${1:-}" =~ ^[a-zA-Z0-9_-]{3,64}$ ]]; }

safe_write_file() {
  local path="$1" mode="$2" owner="$3" group="$4" content="$5"
  local tmp
  tmp="$(mktemp)" || return 1
  umask 077
  printf "%s" "$content" >"$tmp" || { rm -f "$tmp"; return 1; }
  install -m "$mode" -o "$owner" -g "$group" "$tmp" "$path" || { rm -f "$tmp"; return 1; }
  rm -f "$tmp"
}

secure_delete_file() {
  local f="$1"
  [ -f "$f" ] || return 0
  if have_cmd shred; then
    shred -u "$f" >/dev/null 2>&1 || rm -f "$f"
  else
    rm -f "$f"
  fi
}

ensure_dirs() {
  install -d -m 700 -o root -g root "${CONFIG_DIR}" "${SECRETS_DIR}" "${STATE_DIR}"
  install -d -m 755 -o root -g root "${KEYS_DIR}"
  install -d -m 750 -o root -g root "${LOG_DIR}" "${DEFAULT_LOCAL_BASE}" "${TMP_BASE}"
}

###############################################
# Dépendances (Ubuntu)
###############################################
apt_install() {
  local pkgs=("$@")
  info "Installation: ${pkgs[*]}"
  apt-get update -y >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
}

ensure_deps() {
  local missing=()

  for c in jq age age-keygen zstd rsync ssh curl sed awk grep; do
    have_cmd "$c" || missing+=("$c")
  done
  if ! have_cmd mysql && ! have_cmd mariadb; then
    missing+=("mariadb-client")
  fi

  if [ "${#missing[@]}" -eq 0 ]; then
    return 0
  fi

  warn "Dépendances manquantes: ${missing[*]}"
  read -r -p "Installer maintenant via apt ? [Y/n] " ans
  ans="${ans:-Y}"
  if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    err "Installez les dépendances puis relancez."
    return 1
  fi

  local pkgs=()
  local c
  for c in "${missing[@]}"; do
    case "$c" in
      mariadb-client) pkgs+=("mariadb-client") ;;
      *) pkgs+=("$c") ;;
    esac
  done
  mapfile -t pkgs < <(printf "%s\n" "${pkgs[@]}" | awk '!seen[$0]++')
  apt_install "${pkgs[@]}"
}


###############################################
# Intro (néophyte-friendly)
###############################################
print_intro_wizard() {
  # Affiche UNE SEULE FOIS par exécution (pas à chaque redraw du menu)
  if [ "${INTRO_SHOWN:-false}" = "true" ]; then
    return 0
  fi
  INTRO_SHOWN="true"

  local out
  out="$(tty_out)"

  {
    printf "\n"
    printf "============================================================\n"
    printf "%s — Wizard (script 1/3) — V%s\n" "${APP_NAME}" "${SCRIPT_VERSION}"
    printf "============================================================\n\n"

    printf "Ce wizard sert à :\n"
    printf " - Créer / modifier / tester / supprimer des jobs de backup (JSON)\n"
    printf " - Générer (ou saisir) une clé publique age par job (la clé PRIVÉE reste chez vous)\n"
    printf " - Tester l'accès DB, rsync remote, webhook\n"
    printf " - Lancer les scripts frères runner/restore si présents\n\n"

    printf "Chemins :\n"
    printf " - Jobs JSON      : %s\n" "${CONFIG_DIR}"
    printf " - Clés publiques : %s\n" "${KEYS_DIR}"
    printf " - Secrets        : %s\n" "${SECRETS_DIR}"
    printf " - State          : %s\n" "${STATE_DIR}"
    printf " - Logs           : %s\n" "${LOG_DIR}"
    printf " - Backups locaux : %s\n\n" "${DEFAULT_LOCAL_BASE}"

    printf "Sécurité :\n"
    printf " - Les backups sont chiffrés avec age (clé publique sur le serveur)\n"
    printf " - La clé PRIVÉE n'est jamais stockée ici : gardez-la (1Password, etc.)\n"
    printf " - Sans clé privée => restauration impossible\n\n"

    printf "Ponts :\n"
    if [ -f "$RUNNER_SH" ]; then
      printf " - Runner  : %s (présent)\n" "$RUNNER_SH"
    else
      printf " - Runner  : %s (absent)\n" "$RUNNER_SH"
    fi
    if [ -f "$RESTORE_SH" ]; then
      printf " - Restore : %s (présent)\n" "$RESTORE_SH"
    else
      printf " - Restore : %s (absent)\n" "$RESTORE_SH"
    fi

    printf "\n"
  } >"$out"

  # pause "une touche" (pas Entrée)
  if [ -c /dev/tty ]; then
    read -r -n 1 -s -p "Appuyez sur une touche pour continuer..." _ </dev/tty
    printf "\n" >&2
  else
    read -r -p "Appuyez sur Entrée pour continuer..." _ || true
  fi
}
###############################################
# Input helpers
###############################################
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
      if [[ "$ans" =~ ^[Yy]$ ]]; then return 0; else return 1; fi
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

ask_time_hhmm() {
  local prompt="$1" default="${2:-04:00}" ans=""
  while true; do
    ans="$(ask_input "$prompt" "$default")"
    ans="$(trim "$ans")"
    if [[ "$ans" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]; then
      printf "%s" "$ans"
      return 0
    fi
    warn "Format attendu HH:MM (00:00 → 23:59)."
  done
}

###############################################
# MySQL/MariaDB helpers
###############################################
mysql_bin() { if have_cmd mysql; then printf "mysql"; else printf "mariadb"; fi; }

mysql_exec() {
  local sql="$1"
  "$(mysql_bin)" --batch --skip-column-names -e "$sql"
}

db_exists() {
  local db="$1"
  mysql_exec "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='$(printf "%s" "$db" | sed "s/'/''/g")';" 2>/dev/null | grep -qx "$db"
}

is_system_db() {
  case "$1" in
    information_schema|performance_schema|mysql|sys) return 0 ;;
    *) return 1 ;;
  esac
}

select_database() {
  local -a all=()
  if ! mapfile -t all < <(mysql_exec "SHOW DATABASES;" 2>/dev/null); then
    err "Impossible de lister les bases (MariaDB/MySQL down ? droits root/socket ?)."
    return 1
  fi
  if [ "${#all[@]}" -eq 0 ]; then
    err "Aucune base trouvée."
    return 1
  fi

  info "Bases disponibles :"
  printf "  [0] Saisir manuellement le nom de la DB\n" >&2

  local -a menu_dbs=()
  local i=1 d
  for d in "${all[@]}"; do
    local label="$d"
    if is_system_db "$d"; then
      label="${d} (system)"
    fi
    printf "  [%d] %s\n" "$i" "$label" >&2
    menu_dbs+=("$d")
    i=$((i+1))
  done

  local choice
  choice="$(ask_int "Choisissez une base (numéro)" "1" 0 "${#menu_dbs[@]}")"

  if [ "$choice" -eq 0 ]; then
    local manual
    while true; do
      manual="$(ask_input "Nom de la DB" "")"
      manual="$(trim "$manual")"
      if [ -z "$manual" ]; then
        warn "Nom vide."
        continue
      fi
      if db_exists "$manual"; then
        printf "%s" "$manual"
        return 0
      fi
      warn "La DB '$manual' n'existe pas."
      ask_yes_no "Réessayer ?" "Y" || return 1
    done
  fi

  printf "%s" "${menu_dbs[$((choice-1))]}"
  return 0
}

###############################################
# AGE keygen
###############################################
generate_age_keypair() {
  local idpath priv pub
  idpath="$(mktemp)" || return 1
  rm -f "$idpath" || { rm -f "$idpath"; return 1; }

  if ! age-keygen -o "$idpath" >/dev/null 2>&1; then
    rm -f "$idpath" || true
    return 1
  fi

  priv="$(grep -E '^AGE-SECRET-KEY-' "$idpath" | head -n 1 || true)"
  priv="$(trim "$priv")"

  pub="$(age-keygen -y "$idpath" 2>/dev/null | head -n 1 || true)"
  pub="$(trim "$pub")"

  secure_delete_file "$idpath"

  if [[ ! "$priv" =~ ^AGE-SECRET-KEY- ]]; then
    return 1
  fi
  if [[ ! "$pub" =~ ^age1[0-9a-z]+$ ]]; then
    return 1
  fi

  printf "%s\n%s\n" "$priv" "$pub"
  return 0
}

confirm_keys_pasteback() {
  local priv="$1" pub="$2"
  local OUT
  OUT="$(tty_out)"

  if [[ ! "$pub" =~ ^age1[0-9a-z]+$ ]]; then
    err "Clé publique vide/invalide => arrêt (on évite un .age.pub vide)."
    return 1
  fi

  info "Clés age à sauvegarder dans 1Password :"
  {
    printf "\n================= AGE PRIVATE KEY =================\n%s\n===================================================\n\n" "$priv"
    printf "================== AGE PUBLIC KEY =================\n%s\n===================================================\n\n" "$pub"
    printf "[ATTENTION] La clé PRIVÉE ne sera PAS stockée sur le serveur.\n"
    printf "           Pour restaurer un backup, on vous demandera de COLLER la clé privée.\n\n"
  } >"$OUT"

  local pasted
  while true; do
    pasted="$(ask_input "Pour vérifier: recolle la clé privée (AGE-SECRET-KEY-...)" "")"
    pasted="$(trim "$pasted")"
    if [ "$pasted" = "$priv" ]; then
      info "Vérification OK."
      return 0
    fi
    warn "Clé différente."
    ask_yes_no "Réessayer ?" "Y" || return 1
  done
}

ask_or_create_recipient_pubkey_file() {
  local job_id="$1"
  local pubfile="${KEYS_DIR}/${job_id}.age.pub"
  local pubkey=""

  info "Chiffrement: age (clé publique/privée)."

  if ask_yes_no "Générer une nouvelle paire de clés age pour ce job ?" "Y"; then
    local priv pub
    {
      IFS= read -r priv
      IFS= read -r pub
    } < <(generate_age_keypair) || {
      err "age-keygen a échoué (génération clé)."
      return 1
    }

    priv="$(trim "$priv")"
    pub="$(trim "$pub")"

    confirm_keys_pasteback "$priv" "$pub" || return 1

    pubkey="$pub"
    safe_write_file "$pubfile" 644 root root "${pubkey}"$'\n' || {
      err "Impossible d'écrire la clé publique: $pubfile"
      return 1
    }

    if ! grep -Eq '^age1[0-9a-z]+$' "$pubfile"; then
      rm -f "$pubfile" || true
      err "Fichier de pubkey invalide/vidé: $pubfile"
      return 1
    fi

    info "Clé publique enregistrée: $pubfile"
    printf "%s" "$pubfile"
    return 0
  fi

  while true; do
    pubkey="$(ask_input "Collez la clé publique age (commence par age1...)" "")"
    pubkey="$(trim "$pubkey")"
    if [[ "$pubkey" =~ ^age1[0-9a-z]+$ ]]; then
      break
    fi
    warn "Clé publique invalide."
  done

  safe_write_file "$pubfile" 644 root root "${pubkey}"$'\n' || {
    err "Écriture pubkey KO."
    return 1
  }
  grep -Eq '^age1[0-9a-z]+$' "$pubfile" || {
    rm -f "$pubfile" || true
    err "Pubkey invalide."
    return 1
  }

  info "Clé publique enregistrée: $pubfile"
  printf "%s" "$pubfile"
}

###############################################
# Remote rsync test (durci: timeouts)
###############################################
ssh_base_opts() {
  printf "%s" "-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=1"
}

test_remote_rsync() {
  local target="$1" port="$2" identity="${3:-}" remote_base="$4" job_id="$5"

  local host_short ts remote_dir remote_file
  host_short="$(hostname -s | tr -cd 'a-zA-Z0-9_-')"
  [ -n "$host_short" ] || host_short="host"

  ts="$(date -u +%Y%m%d_%H%M%S)"
  remote_dir="${remote_base%/}/${host_short}/${job_id}/.wizard_test_${ts}"
  remote_file="${remote_dir}/__rsync_test__.txt"

  local tmpdir tmpfile
  tmpdir="$(mktemp -d)" || return 1
  tmpfile="${tmpdir}/test.txt"
  printf "db-backup wizard test %s\n" "$ts" >"$tmpfile" || { rm -rf "$tmpdir"; return 1; }

  local -a ssh_cmd=(ssh -p "$port")
  # shellcheck disable=SC2206
  ssh_cmd+=($(ssh_base_opts))
  if [ -n "$identity" ]; then
    ssh_cmd+=(-i "$identity")
  fi

  info "Test remote: mkdir ${target}:${remote_dir}"
  "${ssh_cmd[@]}" "$target" "mkdir -p -- '$remote_dir'" || { rm -rf "$tmpdir"; return 1; }

  info "Test remote: rsync upload"
  local ssh_e="ssh -p ${port} $(ssh_base_opts)"
  if [ -n "$identity" ]; then
    ssh_e+=" -i ${identity}"
  fi
  rsync -a -e "$ssh_e" "$tmpfile" "${target}:${remote_file}" || { rm -rf "$tmpdir"; return 1; }

  info "Test remote: présence fichier"
  "${ssh_cmd[@]}" "$target" "test -f '$remote_file'" || { rm -rf "$tmpdir"; return 1; }

  info "Test remote: nettoyage"
  "${ssh_cmd[@]}" "$target" "rm -rf -- '$remote_dir'" >/dev/null 2>&1 || true

  rm -rf "$tmpdir"
  info "Remote rsync: OK"
  return 0
}

###############################################
# Webhook
###############################################
test_webhook() {
  local url="$1" headers_file="${2:-}"

  local payload
  payload="$(jq -c -n \
    --arg event "wizard.test" \
    --arg hostname "$(hostname -s)" \
    --arg at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    '{event:$event, hostname:$hostname, at:$at}')"

  local -a cmd=(curl -fsS -X POST -H "Content-Type: application/json" --data "$payload")
  if [ -n "$headers_file" ] && [ -f "$headers_file" ]; then
    while IFS= read -r line; do
      line="$(trim "$line")"
      [ -z "$line" ] && continue
      cmd+=(-H "$line")
    done <"$headers_file"
  fi

  info "Test webhook: POST $url"
  cmd+=("$url")
  "${cmd[@]}" >/dev/null
  info "Webhook: OK"
}

###############################################
# JSON config
###############################################
job_config_path() { printf "%s/%s.json" "$CONFIG_DIR" "$1"; }

read_bool() {
  local v="${1:-false}"
  v="$(trim "$v")"
  if [ "$v" = "true" ] || [ "$v" = "false" ]; then
    printf "%s" "$v"
  else
    printf "%s" "false"
  fi
}

write_job_config_json() {
  local job_id="$1" db_name="$2" schedule_type="$3" every_hours="$4" daily_time="$5" timezone="$6"
  local retention_daily_days="$7" retention_monthly_years="$8" compression_level="$9" recipient_pubkey_file="${10}"
  local local_enabled="${11}" local_path="${12}"
  local remote_enabled="${13}" remote_target="${14}" remote_ssh_port="${15}" remote_identity_file="${16}" remote_base_path="${17}"
  local webhook_enabled="${18}" webhook_url="${19}" webhook_notify_success="${20}" webhook_notify_failure="${21}" webhook_headers_secret_file="${22}"
  local restore_test_every_days="${23}"

  local tmp outpath
  tmp="$(mktemp)" || return 1
  umask 077

  jq -n \
    --argjson version "$VERSION_JSON" \
    --arg job_id "$job_id" \
    --argjson enabled true \
    --arg db_name "$db_name" \
    --arg schedule_type "$schedule_type" \
    --argjson every_hours "$every_hours" \
    --arg daily_time "$daily_time" \
    --arg timezone "$timezone" \
    --argjson retention_daily_days "$retention_daily_days" \
    --argjson retention_monthly_years "$retention_monthly_years" \
    --arg retention_monthly_rule "last_of_month" \
    --argjson single_transaction true \
    --argjson routines true \
    --argjson triggers true \
    --argjson events true \
    --arg compression_type "zstd" \
    --argjson compression_level "$compression_level" \
    --arg encryption_type "age" \
    --arg recipient_pubkey_file "$recipient_pubkey_file" \
    --argjson local_enabled "$local_enabled" \
    --arg local_path "$local_path" \
    --argjson remote_enabled "$remote_enabled" \
    --arg remote_target "$remote_target" \
    --argjson remote_ssh_port "$remote_ssh_port" \
    --arg remote_identity_file "$remote_identity_file" \
    --arg remote_base_path "$remote_base_path" \
    --argjson webhook_enabled "$webhook_enabled" \
    --arg webhook_url "$webhook_url" \
    --argjson webhook_notify_success "$webhook_notify_success" \
    --argjson webhook_notify_failure "$webhook_notify_failure" \
    --arg webhook_headers_secret_file "$webhook_headers_secret_file" \
    --argjson restore_test_every_days "$restore_test_every_days" \
    '
    {
      version: $version,
      job_id: $job_id,
      enabled: $enabled,
      db: { name: $db_name },
      schedule: (
        if $schedule_type == "hourly" then
          { type:"hourly", every_hours:$every_hours, daily_time:null, timezone:$timezone }
        else
          { type:"daily", every_hours:null, daily_time:$daily_time, timezone:$timezone }
        end
      ),
      retention: { daily_days:$retention_daily_days, monthly_years:$retention_monthly_years, monthly_rule:$retention_monthly_rule },
      dump: { single_transaction:$single_transaction, routines:$routines, triggers:$triggers, events:$events },
      compression: { type:$compression_type, level:$compression_level },
      encryption: { type:$encryption_type, recipient_pubkey_file:$recipient_pubkey_file },
      destinations: {
        local: { enabled:$local_enabled, path:(if $local_enabled then $local_path else null end) },
        remote_rsync: (
          if $remote_enabled then
            { enabled:true, target:$remote_target, ssh_port:$remote_ssh_port,
              ssh_identity_file:(if ($remote_identity_file|length)>0 then $remote_identity_file else null end),
              remote_base_path:$remote_base_path
            }
          else
            { enabled:false, target:null, ssh_port:null, ssh_identity_file:null, remote_base_path:null }
          end
        )
      },
      webhook: (
        if $webhook_enabled then
          { enabled:true, url:$webhook_url,
            notify:{success:$webhook_notify_success, failure:$webhook_notify_failure},
            headers_secret_file:(if ($webhook_headers_secret_file|length)>0 then $webhook_headers_secret_file else null end)
          }
        else
          { enabled:false, url:null, notify:{success:false, failure:false}, headers_secret_file:null }
        end
      ),
      restore_test: {
        every_days: $restore_test_every_days
      }
    }' >"$tmp" || { rm -f "$tmp"; return 1; }

  outpath="$(job_config_path "$job_id")"
  install -m 600 -o root -g root "$tmp" "$outpath" || { rm -f "$tmp"; return 1; }
  rm -f "$tmp"
  info "Config écrite: $outpath"
}

###############################################
# Jobs: list/select/summary
###############################################
list_jobs() { ls -1 "${CONFIG_DIR}"/*.json 2>/dev/null | sed "s|^${CONFIG_DIR}/||; s|\.json$||" || true; }

select_job() {
  local -a jobs=()
  mapfile -t jobs < <(list_jobs)
  if [ "${#jobs[@]}" -eq 0 ]; then
    warn "Aucun job trouvé dans ${CONFIG_DIR}"
    return 1
  fi
  info "Jobs disponibles :"
  local i=1 j
  for j in "${jobs[@]}"; do
    printf "  [%d] %s\n" "$i" "$j" >&2
    i=$((i+1))
  done
  local choice
  choice="$(ask_int "Choisissez un job (numéro)" "1" 1 "${#jobs[@]}")"
  printf "%s" "${jobs[$((choice-1))]}"
}

show_job_summary() {
  local job_id="$1" cfg
  cfg="$(job_config_path "$job_id")"
  [ -f "$cfg" ] || { err "Config introuvable: $cfg"; return 1; }

  info "Résumé job: $job_id"
  jq -r '
    "DB: \(.db.name)\n" +
    "Enabled: \(.enabled)\n" +
    "Schedule: \(.schedule.type) " +
      (if .schedule.type=="hourly" then "(every \(.schedule.every_hours)h)" else "(at \(.schedule.daily_time))" end) + " TZ=\(.schedule.timezone)\n" +
    "Retention: daily \(.retention.daily_days)d, monthly \(.retention.monthly_years)y (\(.retention.monthly_rule))\n" +
    "Restore test: every_days=\(.restore_test.every_days // 0)\n" +
    "Local: \(.destinations.local.enabled) \(.destinations.local.path // "")\n" +
    "Remote: \(.destinations.remote_rsync.enabled) \(.destinations.remote_rsync.target // "")\n" +
    "Encrypt: \(.encryption.type) pub=\(.encryption.recipient_pubkey_file)\n" +
    "Webhook: \(.webhook.enabled) \(.webhook.url // "")"
  ' "$cfg" | sed 's/^/  /'
}

###############################################
# Create job (complet)
###############################################
create_job() {
  info "=== Création d'un job de backup ==="

  local db_name
  if ! db_name="$(select_database)"; then
    warn "Sélection DB annulée."
    pause
    return 0
  fi
  info "Base sélectionnée: $db_name"

  local job_id_default job_id
  job_id_default="$(printf "%s-prod" "$db_name" | tr -cd 'a-zA-Z0-9_-')"
  while true; do
    job_id="$(ask_input "Job ID (a-zA-Z0-9_-)" "$job_id_default")"
    job_id="$(trim "$job_id")"
    if ! validate_job_id "$job_id"; then
      warn "Job ID invalide (3-64 chars, a-zA-Z0-9_-)."
      continue
    fi
    if [ -f "$(job_config_path "$job_id")" ]; then
      warn "Ce job existe déjà: $(job_config_path "$job_id")"
      ask_yes_no "Choisir un autre job_id ?" "Y" || { warn "Annulé."; pause; return 0; }
      continue
    fi
    break
  done

  local timezone
  timezone="$(ask_input "Timezone" "$TZ_DEFAULT")"
  timezone="$(trim "$timezone")"
  [ -n "$timezone" ] || timezone="$TZ_DEFAULT"

  info "Planification:"
  printf "  [1] Toutes les X heures\n" >&2
  printf "  [2] Chaque jour à HH:MM\n" >&2
  local sched_choice
  sched_choice="$(ask_int "Choix" "1" 1 2)"

  local schedule_type="hourly" every_hours=6 daily_time="04:00"
  if [ "$sched_choice" -eq 1 ]; then
    schedule_type="hourly"
    every_hours="$(ask_int "Toutes les combien d'heures ?" "6" 1 999999999)"
  else
    schedule_type="daily"
    daily_time="$(ask_time_hhmm "Chaque jour à" "04:00")"
  fi

  local retention_daily_days retention_monthly_years
  retention_daily_days="$(ask_int "Rétention: conserver les backups quotidiens (jours)" "14" 1 365000)"
  retention_monthly_years="$(ask_int "Rétention: conserver 1 backup mensuel (années, 0=off)" "3" 0 200)"
  info "Règle mensuelle: dernier backup du mois (last_of_month)"

  local compression_level
  compression_level="$(ask_int "Compression zstd: niveau (1=rapide, 19=fort)" "6" 1 19)"

  local recipient_pubkey_file
  while true; do
    if recipient_pubkey_file="$(ask_or_create_recipient_pubkey_file "$job_id")"; then
      break
    fi
    err "Génération / saisie de clé age échouée."
    ask_yes_no "Réessayer ?" "Y" || { warn "Annulé."; pause; return 0; }
  done

  # Restore test frequency (pre-config)
  local restore_test_every_days
  restore_test_every_days="$(ask_int "Test de restauration (jours, 0 = désactivé)" "0" 0 365000)"

  # Destinations
  local local_enabled=true local_path=""
  if ask_yes_no "Activer une sauvegarde locale ?" "Y"; then
    local_path="$(ask_input "Chemin local de sauvegarde" "${DEFAULT_LOCAL_BASE}/${job_id}")"
    local_path="$(trim "$local_path")"
    if [ -z "$local_path" ]; then
      err "Chemin local invalide."
      pause
      return 0
    fi
    install -d -m 750 -o root -g root "$local_path" || { err "Impossible de créer: $local_path"; pause; return 0; }
    info "Dossier local prêt: $local_path"
    local_enabled=true
  else
    local_enabled=false
    local_path=""
  fi

  local remote_enabled=false remote_target="" remote_ssh_port=22 remote_identity_file="" remote_base_path=""
  if ask_yes_no "Activer une sauvegarde distante (rsync/ssh) ?" "N"; then
    remote_target="$(ask_input "Cible rsync (user@host)" "")"
    remote_target="$(trim "$remote_target")"
    if [ -z "$remote_target" ]; then
      err "Cible distante invalide."
      pause
      return 0
    fi
    remote_ssh_port="$(ask_int "Port SSH" "22" 1 65535)"
    remote_identity_file="$(ask_input "Fichier clé SSH (optionnel)" "")"
    remote_identity_file="$(trim "$remote_identity_file")"
    if [ -n "$remote_identity_file" ] && [ ! -f "$remote_identity_file" ]; then
      err "Fichier clé SSH introuvable: $remote_identity_file"
      pause
      return 0
    fi
    remote_base_path="$(ask_input "Chemin remote de base" "/srv/backups/${APP_NAME}")"
    remote_base_path="$(trim "$remote_base_path")"
    if [ -z "$remote_base_path" ]; then
      err "Chemin remote invalide."
      pause
      return 0
    fi

    info "Test de connexion rsync/ssh..."
    if ! test_remote_rsync "$remote_target" "$remote_ssh_port" "$remote_identity_file" "$remote_base_path" "$job_id"; then
      err "Test rsync/ssh KO."
      ask_yes_no "Désactiver le remote et continuer quand même ?" "Y" || { warn "Annulé."; pause; return 0; }
      remote_enabled=false
    else
      remote_enabled=true
    fi
  fi

  local webhook_enabled=false webhook_url="" webhook_notify_success=false webhook_notify_failure=true webhook_headers_secret_file=""
  if ask_yes_no "Activer un webhook de notification ?" "N"; then
    webhook_url="$(ask_input "URL webhook (https://...)" "")"
    webhook_url="$(trim "$webhook_url")"
    if [[ ! "$webhook_url" =~ ^https?:// ]]; then
      err "URL webhook invalide."
      pause
      return 0
    fi

    if ask_yes_no "Notifier aussi les succès ?" "N"; then
      webhook_notify_success=true
    else
      webhook_notify_success=false
    fi
    webhook_notify_failure=true

    if ask_yes_no "Ajouter des headers secrets (token) ?" "N"; then
      local hfile="${SECRETS_DIR}/${job_id}.webhook.headers"
      info "Entrez les headers (1 par ligne, ex: Authorization: Bearer XXX). Ligne vide pour terminer."
      umask 077
      : >"$hfile" || { err "Impossible d'écrire: $hfile"; pause; return 0; }
      chmod 600 "$hfile"
      chown root:root "$hfile"
      while true; do
        local line
        read -r -p "> " line
        line="$(trim "$line")"
        [ -z "$line" ] && break
        printf "%s\n" "$line" >>"$hfile"
      done
      webhook_headers_secret_file="$hfile"
      info "Headers enregistrés: $hfile"
    fi

    info "Test webhook..."
    if ! test_webhook "$webhook_url" "$webhook_headers_secret_file"; then
      err "Test webhook KO."
      ask_yes_no "Désactiver le webhook et continuer ?" "Y" || { warn "Annulé."; pause; return 0; }
      webhook_enabled=false
    else
      webhook_enabled=true
    fi
  fi

  if ! write_job_config_json \
    "$job_id" "$db_name" \
    "$schedule_type" "$every_hours" "$daily_time" "$timezone" \
    "$retention_daily_days" "$retention_monthly_years" \
    "$compression_level" "$recipient_pubkey_file" \
    "$local_enabled" "$local_path" \
    "$remote_enabled" "$remote_target" "$remote_ssh_port" "$remote_identity_file" "$remote_base_path" \
    "$webhook_enabled" "$webhook_url" "$webhook_notify_success" "$webhook_notify_failure" "$webhook_headers_secret_file" \
    "$restore_test_every_days"
  then
    err "Écriture JSON impossible."
    pause
    return 0
  fi

  local cfg_path
  cfg_path="$(job_config_path "$job_id")"

  info "=== Récapitulatif ==="
  cat >&2 <<EOF
Job ID        : ${job_id}
DB            : ${db_name}
Schedule      : ${schedule_type} $( [ "$schedule_type" = "hourly" ] && printf "(toutes les %sh)" "$every_hours" || printf "(tous les jours à %s)" "$daily_time" )
Timezone      : ${timezone}
Rétention     : daily=${retention_daily_days} jours, monthly=${retention_monthly_years} années (dernier backup du mois)
Restore test  : every_days=${restore_test_every_days} (0=off)
Compression   : zstd level=${compression_level}
Chiffrement   : age (clé publique sur le serveur)
  - PubKey    : ${recipient_pubkey_file}
Destinations  :
  - Local     : ${local_enabled} $( [ "$local_enabled" = "true" ] && printf "%s" "$local_path" || printf "" )
  - Remote    : ${remote_enabled} $( [ "$remote_enabled" = "true" ] && printf "%s:%s (port %s)" "$remote_target" "$remote_base_path" "$remote_ssh_port" || printf "" )
Webhook       : ${webhook_enabled} $( [ "$webhook_enabled" = "true" ] && printf "%s" "$webhook_url" || printf "" )
Config JSON   : ${cfg_path}

IMPORTANT
- Sauvegardez la clé PRIVÉE age affichée pendant le wizard (sinon impossible de restaurer)
EOF

  pause
}

###############################################
# Modifier un job (CRUD: UPDATE)
###############################################
modify_job() {
  info "=== Modifier un job ==="
  local job_id
  if ! job_id="$(select_job)"; then
    pause
    return 0
  fi

  local cfg
  cfg="$(job_config_path "$job_id")"
  [ -f "$cfg" ] || { err "Config introuvable: $cfg"; pause; return 0; }

  show_job_summary "$job_id" || { pause; return 0; }

  if ! ask_yes_no "Modifier ce job ?" "Y"; then
    return 0
  fi

  # Charger valeurs actuelles (defaults solides)
  local db_name timezone schedule_type every_hours daily_time
  local retention_daily_days retention_monthly_years compression_level
  local recipient_pubkey_file
  local local_enabled local_path
  local remote_enabled remote_target remote_ssh_port remote_identity_file remote_base_path
  local webhook_enabled webhook_url webhook_notify_success webhook_notify_failure webhook_headers_secret_file
  local restore_test_every_days

  db_name="$(jq -r '.db.name // empty' "$cfg")"
  timezone="$(jq -r '.schedule.timezone // "'"$TZ_DEFAULT"'"' "$cfg")"
  schedule_type="$(jq -r '.schedule.type // "hourly"' "$cfg")"
  every_hours="$(jq -r '.schedule.every_hours // 6' "$cfg")"
  daily_time="$(jq -r '.schedule.daily_time // "04:00"' "$cfg")"

  retention_daily_days="$(jq -r '.retention.daily_days // 14' "$cfg")"
  retention_monthly_years="$(jq -r '.retention.monthly_years // 3' "$cfg")"
  compression_level="$(jq -r '.compression.level // 6' "$cfg")"
  recipient_pubkey_file="$(jq -r '.encryption.recipient_pubkey_file // ""' "$cfg")"

  local_enabled="$(jq -r '.destinations.local.enabled // false' "$cfg")"
  local_path="$(jq -r '.destinations.local.path // ""' "$cfg")"

  remote_enabled="$(jq -r '.destinations.remote_rsync.enabled // false' "$cfg")"
  remote_target="$(jq -r '.destinations.remote_rsync.target // ""' "$cfg")"
  remote_ssh_port="$(jq -r '.destinations.remote_rsync.ssh_port // 22' "$cfg")"
  remote_identity_file="$(jq -r '.destinations.remote_rsync.ssh_identity_file // ""' "$cfg")"
  remote_base_path="$(jq -r '.destinations.remote_rsync.remote_base_path // ""' "$cfg")"

  webhook_enabled="$(jq -r '.webhook.enabled // false' "$cfg")"
  webhook_url="$(jq -r '.webhook.url // ""' "$cfg")"
  webhook_notify_success="$(jq -r '.webhook.notify.success // false' "$cfg")"
  webhook_notify_failure="$(jq -r '.webhook.notify.failure // true' "$cfg")"
  webhook_headers_secret_file="$(jq -r '.webhook.headers_secret_file // ""' "$cfg")"

  restore_test_every_days="$(jq -r '.restore_test.every_days // 0' "$cfg")"

  # DB (optionnel)
  if ask_yes_no "Changer la base de données ?" "N"; then
    local newdb
    if newdb="$(select_database)"; then
      db_name="$(trim "$newdb")"
    else
      warn "Changement DB annulé."
    fi
  fi

  # Timezone
  timezone="$(ask_input "Timezone" "$timezone")"
  timezone="$(trim "$timezone")"
  [ -n "$timezone" ] || timezone="$TZ_DEFAULT"

  # Schedule
  info "Planification actuelle: ${schedule_type}"
  printf "  [1] Toutes les X heures\n" >&2
  printf "  [2] Chaque jour à HH:MM\n" >&2
  local sched_choice_default="1"
  if [ "$schedule_type" = "daily" ]; then
    sched_choice_default="2"
  fi
  local sched_choice
  sched_choice="$(ask_int "Choix" "$sched_choice_default" 1 2)"
  if [ "$sched_choice" -eq 1 ]; then
    schedule_type="hourly"
    every_hours="$(ask_int "Toutes les combien d'heures ?" "$every_hours" 1 999999999)"
    daily_time="04:00"
  else
    schedule_type="daily"
    daily_time="$(ask_time_hhmm "Chaque jour à" "$daily_time")"
    every_hours=6
  fi

  retention_daily_days="$(ask_int "Rétention: backups quotidiens (jours)" "$retention_daily_days" 1 365000)"
  retention_monthly_years="$(ask_int "Rétention: 1 backup mensuel (années, 0=off)" "$retention_monthly_years" 0 200)"
  compression_level="$(ask_int "Compression zstd: niveau (1-19)" "$compression_level" 1 19)"

  # Restore test frequency
  restore_test_every_days="$(ask_int "Test de restauration (jours, 0=off)" "$restore_test_every_days" 0 365000)"

  # Pubkey (optionnel)
  if ask_yes_no "Changer la clé publique age (recipient) ?" "N"; then
    local new_pub
    if new_pub="$(ask_or_create_recipient_pubkey_file "$job_id")"; then
      recipient_pubkey_file="$new_pub"
    else
      warn "Changement de pubkey annulé."
    fi
  else
    # Valider l'existante (best-effort)
    if [ -z "$recipient_pubkey_file" ] || [ ! -f "$recipient_pubkey_file" ] || ! grep -Eq '^age1[0-9a-z]+$' "$recipient_pubkey_file"; then
      warn "Pubkey actuelle invalide/introuvable -> il faut en définir une."
      local new_pub2
      new_pub2="$(ask_or_create_recipient_pubkey_file "$job_id")" || { err "Pubkey requise."; pause; return 0; }
      recipient_pubkey_file="$new_pub2"
    fi
  fi

  # Local destination
  local local_default="N"
  if [ "$local_enabled" = "true" ]; then local_default="Y"; fi
  if ask_yes_no "Activer la sauvegarde locale ?" "$local_default"; then
    local_enabled=true
    local_path="$(ask_input "Chemin local de sauvegarde" "${local_path:-${DEFAULT_LOCAL_BASE}/${job_id}}")"
    local_path="$(trim "$local_path")"
    if [ -z "$local_path" ]; then
      err "Chemin local invalide."
      pause
      return 0
    fi
    install -d -m 750 -o root -g root "$local_path" || { err "Impossible de créer: $local_path"; pause; return 0; }
  else
    local_enabled=false
    local_path=""
  fi

  # Remote destination
  local remote_default="N"
  if [ "$remote_enabled" = "true" ]; then remote_default="Y"; fi
  if ask_yes_no "Activer la sauvegarde distante (rsync/ssh) ?" "$remote_default"; then
    remote_enabled=true
    remote_target="$(ask_input "Cible rsync (user@host)" "$remote_target")"
    remote_target="$(trim "$remote_target")"
    if [ -z "$remote_target" ]; then
      err "Cible distante invalide."
      pause
      return 0
    fi
    remote_ssh_port="$(ask_int "Port SSH" "$remote_ssh_port" 1 65535)"
    remote_identity_file="$(ask_input "Fichier clé SSH (optionnel)" "$remote_identity_file")"
    remote_identity_file="$(trim "$remote_identity_file")"
    if [ -n "$remote_identity_file" ] && [ ! -f "$remote_identity_file" ]; then
      err "Fichier clé SSH introuvable: $remote_identity_file"
      pause
      return 0
    fi
    remote_base_path="$(ask_input "Chemin remote de base" "${remote_base_path:-/srv/backups/${APP_NAME}}")"
    remote_base_path="$(trim "$remote_base_path")"
    if [ -z "$remote_base_path" ]; then
      err "Chemin remote invalide."
      pause
      return 0
    fi

    info "Test de connexion rsync/ssh..."
    if ! test_remote_rsync "$remote_target" "$remote_ssh_port" "$remote_identity_file" "$remote_base_path" "$job_id"; then
      err "Test rsync/ssh KO."
      ask_yes_no "Désactiver le remote et continuer quand même ?" "Y" || { warn "Annulé."; pause; return 0; }
      remote_enabled=false
      remote_target=""
      remote_base_path=""
      remote_identity_file=""
      remote_ssh_port=22
    fi
  else
    remote_enabled=false
    remote_target=""
    remote_base_path=""
    remote_identity_file=""
    remote_ssh_port=22
  fi

  # Webhook
  local wh_default="N"
  if [ "$webhook_enabled" = "true" ]; then wh_default="Y"; fi
  if ask_yes_no "Activer un webhook de notification ?" "$wh_default"; then
    webhook_enabled=true
    webhook_url="$(ask_input "URL webhook (https://...)" "$webhook_url")"
    webhook_url="$(trim "$webhook_url")"
    if [[ ! "$webhook_url" =~ ^https?:// ]]; then
      err "URL webhook invalide."
      pause
      return 0
    fi

    if ask_yes_no "Notifier aussi les succès ?" "$( [ "$webhook_notify_success" = "true" ] && printf "Y" || printf "N" )"; then
      webhook_notify_success=true
    else
      webhook_notify_success=false
    fi
    webhook_notify_failure=true

    if ask_yes_no "Modifier/ajouter des headers secrets (token) ?" "N"; then
      local hfile="${SECRETS_DIR}/${job_id}.webhook.headers"
      info "Entrez les headers (1 par ligne, ex: Authorization: Bearer XXX). Ligne vide pour terminer."
      umask 077
      : >"$hfile" || { err "Impossible d'écrire: $hfile"; pause; return 0; }
      chmod 600 "$hfile"
      chown root:root "$hfile"
      while true; do
        local line
        read -r -p "> " line
        line="$(trim "$line")"
        [ -z "$line" ] && break
        printf "%s\n" "$line" >>"$hfile"
      done
      webhook_headers_secret_file="$hfile"
      info "Headers enregistrés: $hfile"
    fi

    info "Test webhook..."
    if ! test_webhook "$webhook_url" "$webhook_headers_secret_file"; then
      err "Test webhook KO."
      ask_yes_no "Désactiver le webhook et continuer ?" "Y" || { warn "Annulé."; pause; return 0; }
      webhook_enabled=false
      webhook_url=""
      webhook_headers_secret_file=""
      webhook_notify_success=false
      webhook_notify_failure=false
    fi
  else
    webhook_enabled=false
    webhook_url=""
    webhook_headers_secret_file=""
    webhook_notify_success=false
    webhook_notify_failure=false
  fi

  # Ecriture (on conserve job_id, enabled=true)
  if ! write_job_config_json \
    "$job_id" "$db_name" \
    "$schedule_type" "$every_hours" "$daily_time" "$timezone" \
    "$retention_daily_days" "$retention_monthly_years" \
    "$compression_level" "$recipient_pubkey_file" \
    "$local_enabled" "$local_path" \
    "$remote_enabled" "$remote_target" "$remote_ssh_port" "$remote_identity_file" "$remote_base_path" \
    "$webhook_enabled" "$webhook_url" "$webhook_notify_success" "$webhook_notify_failure" "$webhook_headers_secret_file" \
    "$restore_test_every_days"
  then
    err "Écriture JSON impossible."
    pause
    return 0
  fi

  info "Job modifié: ${job_id}"
  show_job_summary "$job_id" || true
  pause
}

###############################################
# Tester un job
###############################################
test_job() {
  info "=== Tester un job ==="
  local job_id
  if ! job_id="$(select_job)"; then
    pause
    return 0
  fi

  local cfg
  cfg="$(job_config_path "$job_id")"
  show_job_summary "$job_id" || { pause; return 0; }

  local db
  db="$(jq -r '.db.name' "$cfg")"
  info "Test DB access (socket root): DB=${db}"

  if ! db_exists "$db"; then
    err "La base n'existe pas: $db"
    pause
    return 0
  fi
  if ! mysql_exec "SELECT 1;" >/dev/null 2>&1; then
    err "Accès MySQL/MariaDB KO (SELECT 1)."
    pause
    return 0
  fi
  mysql_exec "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='$(printf "%s" "$db" | sed "s/'/''/g")' LIMIT 1;" >/dev/null 2>&1 || {
    err "Accès DB KO (information_schema.TABLES)."
    pause
    return 0
  }
  info "DB: OK"

  local pubfile
  pubfile="$(jq -r '.encryption.recipient_pubkey_file' "$cfg")"
  if [ ! -f "$pubfile" ]; then
    err "Clé publique introuvable: $pubfile"
    pause
    return 0
  fi
  if ! grep -Eq '^age1[0-9a-z]+$' "$pubfile"; then
    err "Clé publique invalide dans: $pubfile"
    pause
    return 0
  fi
  info "PubKey: OK"

  local rem_enabled
  rem_enabled="$(jq -r '.destinations.remote_rsync.enabled' "$cfg")"
  if [ "$rem_enabled" = "true" ]; then
    local rt rp ri rb
    rt="$(jq -r '.destinations.remote_rsync.target' "$cfg")"
    rp="$(jq -r '.destinations.remote_rsync.ssh_port' "$cfg")"
    ri="$(jq -r '.destinations.remote_rsync.ssh_identity_file // ""' "$cfg")"
    rb="$(jq -r '.destinations.remote_rsync.remote_base_path' "$cfg")"
    info "Test remote rsync..."
    if ! test_remote_rsync "$rt" "$rp" "$ri" "$rb" "$job_id"; then
      err "Remote rsync: KO"
      pause
      return 0
    fi
  else
    info "Remote rsync désactivé: skip"
  fi

  local wh_enabled
  wh_enabled="$(jq -r '.webhook.enabled' "$cfg")"
  if [ "$wh_enabled" = "true" ]; then
    local url hf
    url="$(jq -r '.webhook.url' "$cfg")"
    hf="$(jq -r '.webhook.headers_secret_file // ""' "$cfg")"
    info "Test webhook..."
    if ! test_webhook "$url" "$hf"; then
      err "Webhook: KO"
      pause
      return 0
    fi
  else
    info "Webhook désactivé: skip"
  fi

  info "Tests OK."
  pause
}

###############################################
# Supprimer un job
###############################################
delete_job() {
  info "=== Supprimer un job ==="
  local job_id
  if ! job_id="$(select_job)"; then
    pause
    return 0
  fi

  local cfg
  cfg="$(job_config_path "$job_id")"
  show_job_summary "$job_id" || { pause; return 0; }

  if ! ask_yes_no "Confirmer suppression du job (config JSON) ?" "N"; then
    return 0
  fi

  local pubfile headers_file local_enabled local_path
  pubfile="$(jq -r '.encryption.recipient_pubkey_file // ""' "$cfg")"
  headers_file="$(jq -r '.webhook.headers_secret_file // ""' "$cfg")"
  local_enabled="$(jq -r '.destinations.local.enabled' "$cfg")"
  local_path="$(jq -r '.destinations.local.path // ""' "$cfg")"

  rm -f "$cfg" || true
  info "Config supprimée: $cfg"

  if [ -n "$pubfile" ] && [ -f "$pubfile" ]; then
    ask_yes_no "Supprimer la clé publique (pub) ${pubfile} ?" "N" && rm -f "$pubfile" || true
  fi
  if [ -n "$headers_file" ] && [ -f "$headers_file" ]; then
    ask_yes_no "Supprimer le fichier headers secrets ${headers_file} ?" "N" && rm -f "$headers_file" || true
  fi

  if [ "$local_enabled" = "true" ] && [ -n "$local_path" ] && [ -d "$local_path" ]; then
    if ask_yes_no "Supprimer le dossier de backups local ${local_path} ?" "N"; then
      rm -rf "$local_path" || true
      info "Dossier supprimé: $local_path"
    fi
  fi

  warn "NB: la suppression remote n'est pas gérée ici (trop risqué)."
  pause
}

###############################################
# Ponts vers runner/restore
###############################################
bridge_runner() {
  if [ -f "$RUNNER_SH" ]; then
    info "Bascule vers: ${RUNNER_SH}"
    exec bash "$RUNNER_SH"
  fi
  warn "Introuvable: ${RUNNER_SH}"
  pause
}

bridge_restore() {
  if [ -f "$RESTORE_SH" ]; then
    info "Bascule vers: ${RESTORE_SH}"
    exec bash "$RESTORE_SH"
  fi
  warn "Introuvable: ${RESTORE_SH}"
  pause
}

###############################################
# Menu principal
###############################################
main_menu() {
  while true; do
    clear 2>/dev/null || true
    printf "========================================\n"
    printf " %s - Wizard (script 1) — V%s\n" "${APP_NAME}" "${SCRIPT_VERSION}"
    printf "========================================\n\n"
    printf "  [1] Créer un job\n"
    printf "  [2] Modifier un job\n"
    printf "  [3] Tester un job\n"
    printf "  [4] Supprimer un job\n"
    printf "  [5] Lister les jobs\n"

    local idx=6
    local runner_idx=0
    local restore_idx=0

    if [ -f "$RUNNER_SH" ]; then
      printf "  [%d] Lancer le runner (db-backup-runner.sh)\n" "$idx"
      runner_idx="$idx"
      idx=$((idx+1))
    else
      printf "  [%d] Lancer le runner (db-backup-runner.sh) (absent)\n" "$idx"
      idx=$((idx+1))
    fi

    if [ -f "$RESTORE_SH" ]; then
      printf "  [%d] Lancer le restore (db-backup-restore.sh)\n" "$idx"
      restore_idx="$idx"
      idx=$((idx+1))
    else
      printf "  [%d] Lancer le restore (db-backup-restore.sh) (absent)\n" "$idx"
      idx=$((idx+1))
    fi

    printf "  [%d] Quitter\n\n" "$idx"

    local choice
    choice="$(ask_int "Choix" "$idx" 1 "$idx")"

    case "$choice" in
      1) create_job ;;
      2) modify_job ;;
      3) test_job ;;
      4) delete_job ;;
      5)
        info "Jobs:"
        if ! list_jobs | sed 's/^/  - /' >&2; then
          warn "Aucun job."
        fi
        pause
        ;;
      *)
        if [ "$runner_idx" -ne 0 ] && [ "$choice" -eq "$runner_idx" ]; then
          bridge_runner
        elif [ "$restore_idx" -ne 0 ] && [ "$choice" -eq "$restore_idx" ]; then
          bridge_restore
        else
          exit 0
        fi
        ;;
    esac
  done
}

###############################################
# Entrée
###############################################
require_root
ensure_dirs
ensure_deps || exit 1
print_intro_wizard
main_menu
