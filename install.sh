#!/usr/bin/env bash
#
# FluxGate one-click deploy (systemd) — multilingual (en / zh / ja)
# FluxGate 一键部署脚本(systemd)— 多语言(英/中/日)
# FluxGate ワンクリック導入(systemd)— 多言語(英/中/日)
#
#   - On launch: choose language (en / zh / ja) first
#   - If already installed: menu → 1) stop  2) restart  3) update
#   - Fresh install: prompt account (default admin) + password (blank = auto)
#       admin console on a RANDOM high port (0.0.0.0); proxy on 80/443
#   - Every install / update re-downloads the latest binary AND refreshes GeoIP
#   - Update flow = stop → download latest → refresh GeoIP → start
#
# Usage:
#   sudo bash install.sh                       # install, or manage if installed
#   sudo bash install.sh --uninstall           # uninstall (keeps /var/lib/fluxgate)
#   sudo bash install.sh --lang en|zh|ja       # force language (skip the menu)
#   curl -fsSL https://.../install.sh | sudo bash
#
# Non-interactive overrides (env): FLUXGATE_LANG, FLUXGATE_ADMIN_USER, FLUXGATE_ADMIN_PASSWORD
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DOWNLOAD_URL="https://github.com/dollarkillerx/FluxGate/releases/download/v0.1.0/fluxgate-admin-0.1.0-x86_64-linux-musl.tar.gz"
GEO_URL="https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb"
INSTALL_BIN="/usr/local/bin/fluxgate-admin"
DATA_DIR="/var/lib/fluxgate"
GEO_FILE="${DATA_DIR}/geoip/GeoLite2-Country.mmdb"
ETC_DIR="/etc/fluxgate"
ENV_FILE="${ETC_DIR}/fluxgate.env"
SVC_NAME="fluxgate-admin"
SVC_FILE="/etc/systemd/system/${SVC_NAME}.service"
SVC_USER="fluxgate"
PROXY_HTTP="0.0.0.0:80"
PROXY_HTTPS="0.0.0.0:443"

# Read interactive input from the controlling terminal, so prompts work even
# when the script is piped (curl ... | sudo bash). Empty if no tty available.
TTY="/dev/tty"; [ -e "$TTY" ] && [ -r "$TTY" ] || TTY=""

b()   { printf '\033[1m%s\033[0m' "$1"; }
ok()  { printf '\033[32m%s\033[0m\n' "$1"; }
warn(){ printf '\033[33m%s\033[0m\n' "$1"; }
err() { printf '\033[31m%s\033[0m\n' "$1" >&2; }

# ---------------------------------------------------------------------------
# i18n — translations grouped per language. `t KEY` echoes the localized text
# (some entries are printf format strings with %s placeholders).
# ---------------------------------------------------------------------------
LC="en"

t_en(){ case "$1" in
  need_root)     echo "Please run as root: sudo bash install.sh";;
  need_curl)     echo "curl is required. Install it first (apt install curl / yum install curl).";;
  need_systemd)  echo "This system does not use systemd; the script does not apply.";;
  lang_prompt)   echo "Select language  1) English  2) 中文  3) 日本語  [%s]: ";;
  title)         echo "==== FluxGate deployment ====";;
  menu_title)    echo "FluxGate is already installed. Choose an action:";;
  menu_stop)     echo "  1) Stop the service";;
  menu_restart)  echo "  2) Restart the service";;
  menu_update)   echo "  3) Update to the latest version";;
  menu_prompt)   echo "Enter an option [1-3]: ";;
  menu_invalid)  echo "Invalid option.";;
  ask_user)      echo "Admin username [admin]: ";;
  ask_pass)      echo "Admin password (blank = auto-generate a strong one): ";;
  pass_gen)      echo "A random password has been generated.";;
  ask_pass2)     echo "Re-enter to confirm: ";;
  pass_mismatch) echo "Passwords do not match, please retry.";;
  downloading)   echo "Downloading the latest binary ...";;
  no_bin)        echo "fluxgate-admin not found inside the archive.";;
  bad_archive)   echo "Downloaded archive is corrupt — aborting (service untouched).";;
  bad_binary)    echo "Downloaded file is not a valid executable — aborting (service untouched).";;
  rollback)      echo "New version failed to start — rolling back to the previous binary ...";;
  rolled_back)   echo "Rolled back to the previous version.";;
  menu_noninteractive) echo "Already installed. In non-interactive mode use --stop / --restart / --update.";;
  installed)     echo "Installed binary: %s";;
  geo_dl)        echo "Refreshing GeoIP database ...";;
  geo_done)      echo "GeoIP database updated.";;
  geo_fail)      echo "GeoIP download failed (the service will retry on start).";;
  act_stopping)  echo "Stopping the service ...";;
  act_stopped)   echo "Service stopped.";;
  act_restarting)echo "Restarting the service ...";;
  act_restarted) echo "Service restarted.";;
  act_updating)  echo "Updating: stop → download latest → refresh GeoIP → start ...";;
  update_done)   echo "Update complete.";;
  waiting)       echo "Waiting for the service to become ready ";;
  not_ready)     echo "Service did not become ready in time. Recent logs:";;
  troubleshoot)  echo "Troubleshoot with: systemctl status %s";;
  done_banner)   echo " Installation complete ";;
  l_console)     echo "Console URL";;
  l_account)     echo "Account    ";;
  l_password)    echo "Password   ";;
  pass_unchanged)echo "(unchanged — kept from existing config)";;
  l_proxy)       echo "Proxy      ";;
  tips)          echo "Notes:";;
  tip_tls)       echo "  • The console uses a self-signed HTTPS cert; trust it in the browser on first visit.";;
  tip_fw)        echo "  • The admin port is random — open TCP %s (and 80/443 for the proxy) in your firewall/security group.";;
  tip_env)       echo "  • Credentials & config live in: %s (chmod 600).";;
  cmds)          echo "Common commands:";;
  c_status)      echo "  systemctl status %s        # status";;
  c_logs)        echo "  journalctl -u %s -f        # live logs";;
  c_manage)      echo "  sudo bash install.sh       # stop / restart / update menu";;
  c_uninstall)   echo "  sudo bash install.sh --uninstall   # uninstall";;
  uni_done)      echo "Service stopped and removed.";;
  uni_keep)      echo "Data dir %s and config %s were kept (rm -rf manually to purge).";;
esac; }

t_zh(){ case "$1" in
  need_root)     echo "请用 root 运行:sudo bash install.sh";;
  need_curl)     echo "需要 curl,请先安装:apt install curl / yum install curl";;
  need_systemd)  echo "本系统未使用 systemd,脚本不适用。";;
  lang_prompt)   echo "选择语言 / Select language  1) English  2) 中文  3) 日本語  [%s]: ";;
  title)         echo "==== FluxGate 部署 ====";;
  menu_title)    echo "检测到已安装 FluxGate,请选择操作:";;
  menu_stop)     echo "  1) 停止服务";;
  menu_restart)  echo "  2) 重启服务";;
  menu_update)   echo "  3) 更新到最新版本";;
  menu_prompt)   echo "请输入选项 [1-3]: ";;
  menu_invalid)  echo "无效选项。";;
  ask_user)      echo "管理员用户名 [admin]: ";;
  ask_pass)      echo "管理员密码(留空=自动生成强密码): ";;
  pass_gen)      echo "已自动生成随机密码。";;
  ask_pass2)     echo "再次输入确认: ";;
  pass_mismatch) echo "两次输入不一致,请重试。";;
  downloading)   echo "下载最新二进制 ...";;
  no_bin)        echo "压缩包内未找到 fluxgate-admin。";;
  bad_archive)   echo "下载的压缩包损坏 —— 已中止(服务未受影响)。";;
  bad_binary)    echo "下载的文件不是有效的可执行程序 —— 已中止(服务未受影响)。";;
  rollback)      echo "新版本启动失败 —— 正在回滚到上一个二进制 ...";;
  rolled_back)   echo "已回滚到上一个版本。";;
  menu_noninteractive) echo "已安装。非交互模式请使用 --stop / --restart / --update。";;
  installed)     echo "已安装二进制:%s";;
  geo_dl)        echo "更新 GeoIP 数据库 ...";;
  geo_done)      echo "GeoIP 数据库已更新。";;
  geo_fail)      echo "GeoIP 下载失败(服务启动时会重试)。";;
  act_stopping)  echo "正在停止服务 ...";;
  act_stopped)   echo "服务已停止。";;
  act_restarting)echo "正在重启服务 ...";;
  act_restarted) echo "服务已重启。";;
  act_updating)  echo "更新中:停止 → 下载最新 → 更新 GeoIP → 启动 ...";;
  update_done)   echo "更新完成。";;
  waiting)       echo "等待服务就绪 ";;
  not_ready)     echo "服务未在预期时间内就绪,最近日志:";;
  troubleshoot)  echo "可手动排查:systemctl status %s";;
  done_banner)   echo " 安装完成 ";;
  l_console)     echo "控制台地址";;
  l_account)     echo "账户      ";;
  l_password)    echo "密码      ";;
  pass_unchanged)echo "(未更改,沿用现有配置)";;
  l_proxy)       echo "反向代理  ";;
  tips)          echo "提示:";;
  tip_tls)       echo "  • 控制台为自签 HTTPS,浏览器首次访问需手动信任证书。";;
  tip_fw)        echo "  • 管理端口为随机高端口,请在防火墙/安全组放行 TCP %s(以及代理用的 80/443)。";;
  tip_env)       echo "  • 凭据与配置在:%s (chmod 600)。";;
  cmds)          echo "常用命令:";;
  c_status)      echo "  systemctl status %s        # 查看状态";;
  c_logs)        echo "  journalctl -u %s -f        # 实时日志";;
  c_manage)      echo "  sudo bash install.sh       # 停止 / 重启 / 更新 菜单";;
  c_uninstall)   echo "  sudo bash install.sh --uninstall   # 卸载";;
  uni_done)      echo "已停止并移除服务与二进制。";;
  uni_keep)      echo "数据目录 %s 与配置 %s 已保留(如需彻底清除请手动 rm -rf)。";;
esac; }

t_ja(){ case "$1" in
  need_root)     echo "root 権限で実行してください: sudo bash install.sh";;
  need_curl)     echo "curl が必要です。先にインストールしてください(apt install curl / yum install curl)。";;
  need_systemd)  echo "このシステムは systemd を使用していないため、本スクリプトは利用できません。";;
  lang_prompt)   echo "言語を選択 / Select language  1) English  2) 中文  3) 日本語  [%s]: ";;
  title)         echo "==== FluxGate デプロイ ====";;
  menu_title)    echo "FluxGate は既にインストール済みです。操作を選択してください:";;
  menu_stop)     echo "  1) サービスを停止";;
  menu_restart)  echo "  2) サービスを再起動";;
  menu_update)   echo "  3) 最新バージョンへ更新";;
  menu_prompt)   echo "番号を入力 [1-3]: ";;
  menu_invalid)  echo "無効な選択です。";;
  ask_user)      echo "管理者ユーザー名 [admin]: ";;
  ask_pass)      echo "管理者パスワード(空欄=強力なパスワードを自動生成): ";;
  pass_gen)      echo "ランダムなパスワードを生成しました。";;
  ask_pass2)     echo "確認のため再入力: ";;
  pass_mismatch) echo "パスワードが一致しません。もう一度お試しください。";;
  downloading)   echo "最新バイナリをダウンロード中 ...";;
  no_bin)        echo "アーカイブ内に fluxgate-admin が見つかりません。";;
  bad_archive)   echo "ダウンロードしたアーカイブが破損しています — 中止します(サービスは影響なし)。";;
  bad_binary)    echo "ダウンロードしたファイルは有効な実行ファイルではありません — 中止します(サービスは影響なし)。";;
  rollback)      echo "新バージョンの起動に失敗 — 以前のバイナリにロールバック中 ...";;
  rolled_back)   echo "以前のバージョンにロールバックしました。";;
  menu_noninteractive) echo "インストール済みです。非対話モードでは --stop / --restart / --update を使用してください。";;
  installed)     echo "バイナリをインストールしました: %s";;
  geo_dl)        echo "GeoIP データベースを更新中 ...";;
  geo_done)      echo "GeoIP データベースを更新しました。";;
  geo_fail)      echo "GeoIP のダウンロードに失敗しました(起動時に再試行します)。";;
  act_stopping)  echo "サービスを停止中 ...";;
  act_stopped)   echo "サービスを停止しました。";;
  act_restarting)echo "サービスを再起動中 ...";;
  act_restarted) echo "サービスを再起動しました。";;
  act_updating)  echo "更新中: 停止 → 最新版をダウンロード → GeoIP 更新 → 起動 ...";;
  update_done)   echo "更新が完了しました。";;
  waiting)       echo "サービスの起動を待機中 ";;
  not_ready)     echo "サービスが時間内に起動しませんでした。最近のログ:";;
  troubleshoot)  echo "確認方法: systemctl status %s";;
  done_banner)   echo " インストール完了 ";;
  l_console)     echo "コンソール URL";;
  l_account)     echo "アカウント   ";;
  l_password)    echo "パスワード   ";;
  pass_unchanged)echo "(変更なし — 既存設定を維持)";;
  l_proxy)       echo "リバースプロキシ";;
  tips)          echo "注意:";;
  tip_tls)       echo "  • コンソールは自己署名 HTTPS です。初回アクセス時にブラウザで証明書を信頼してください。";;
  tip_fw)        echo "  • 管理ポートはランダムです。ファイアウォール/セキュリティグループで TCP %s(およびプロキシ用 80/443)を開放してください。";;
  tip_env)       echo "  • 認証情報と設定は %s (chmod 600) にあります。";;
  cmds)          echo "よく使うコマンド:";;
  c_status)      echo "  systemctl status %s        # 状態確認";;
  c_logs)        echo "  journalctl -u %s -f        # ログ追跡";;
  c_manage)      echo "  sudo bash install.sh       # 停止 / 再起動 / 更新 メニュー";;
  c_uninstall)   echo "  sudo bash install.sh --uninstall   # アンインストール";;
  uni_done)      echo "サービスを停止・削除しました。";;
  uni_keep)      echo "データ %s と設定 %s は保持しました(完全削除は手動で rm -rf)。";;
esac; }

t(){ case "$LC" in zh) t_zh "$1";; ja) t_ja "$1";; *) t_en "$1";; esac; }
tp(){ local k="$1"; shift; printf "$(t "$k")\n" "$@"; }

# ---------------------------------------------------------------------------
# Args + language selection (prompted FIRST)
# ---------------------------------------------------------------------------
norm_lang(){ case "$1" in zh*|*zh*|2|cn|CN) echo zh;; ja*|*ja*|3|jp|JP) echo ja;; en*|*en*|1) echo en;; *) echo "";; esac; }

ARG_LANG=""; DO_UNINSTALL=0; ACTION=""
for a in "$@"; do
  case "$a" in
    --lang=*) ARG_LANG="${a#--lang=}";;
    --lang)   ARG_LANG="next";;
    --uninstall) DO_UNINSTALL=1;;
    --stop)    ACTION="stop";;
    --restart) ACTION="restart";;
    --update)  ACTION="update";;
    *) [ "$ARG_LANG" = "next" ] && ARG_LANG="$a";;
  esac
done

select_language(){
  LC="$(norm_lang "${ARG_LANG:-}")"
  [ -z "$LC" ] && LC="$(norm_lang "${FLUXGATE_LANG:-}")"
  local detected; detected="$(norm_lang "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}")"; [ -z "$detected" ] && detected="en"
  [ -n "$LC" ] && return 0
  if [ -n "$TTY" ]; then
    printf "$(t lang_prompt)" "$detected" > "$TTY"
    local choice=""; read -r choice < "$TTY" || choice=""
    LC="$(norm_lang "${choice:-$detected}")"; [ -z "$LC" ] && LC="$detected"
  else
    LC="$detected"
  fi
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
require_root(){ [ "$(id -u)" -eq 0 ] || { err "$(t need_root)"; exit 1; }; }
get_env(){ grep -E "^$1=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2-; }
is_installed(){ [ -f "$SVC_FILE" ] || [ -x "$INSTALL_BIN" ]; }

gen_password(){
  if command -v openssl >/dev/null 2>&1; then openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 20
  else tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20; fi
}
gen_token(){
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 32
  else tr -dc 'a-f0-9' </dev/urandom | head -c 64; fi
}
port_in_use(){
  local p="$1"
  if command -v ss >/dev/null 2>&1; then ss -Hltn "sport = :$p" 2>/dev/null | grep -q ":$p"
  elif command -v netstat >/dev/null 2>&1; then netstat -ltn 2>/dev/null | grep -q ":$p "
  else (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && { exec 3>&- 3<&-; return 0; } || return 1; fi
}
pick_free_port(){
  local p
  for _ in $(seq 1 50); do
    p=$(( (RANDOM * RANDOM % 40000) + 20000 ))
    port_in_use "$p" || { echo "$p"; return 0; }
  done
  echo 28080
}
detect_ip(){
  local ip=""
  for url in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
    ip=$(curl -fsS --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]') || true
    [ -n "$ip" ] && { echo "$ip"; return 0; }
  done
  hostname -I 2>/dev/null | awk '{print $1}'
}

# Download + extract + validate the latest binary into a temp staging dir,
# WITHOUT touching the installed binary (so a failed/corrupt download never
# disturbs a running service). On success sets $STAGED_BIN to the validated file.
STAGE_DIR=""; STAGED_BIN=""
cleanup_stage(){ [ -n "$STAGE_DIR" ] && rm -rf "$STAGE_DIR" 2>/dev/null || true; }
trap cleanup_stage EXIT

stage_binary(){
  echo "$(t downloading)"
  STAGE_DIR="$(mktemp -d)"
  curl -fSL --progress-bar "$DOWNLOAD_URL" -o "$STAGE_DIR/pkg.tgz"
  tar -tzf "$STAGE_DIR/pkg.tgz" >/dev/null 2>&1 || { err "$(t bad_archive)"; exit 1; }
  tar -xzf "$STAGE_DIR/pkg.tgz" -C "$STAGE_DIR"
  STAGED_BIN="$(find "$STAGE_DIR" -type f -name fluxgate-admin | head -n1)"
  [ -n "$STAGED_BIN" ] || { err "$(t no_bin)"; exit 1; }
  if command -v file >/dev/null 2>&1; then
    file "$STAGED_BIN" | grep -qi 'ELF' || { err "$(t bad_binary)"; exit 1; }
  fi
  chmod 0755 "$STAGED_BIN"
}

# Move the staged binary into place.
install_staged(){
  install -m 0755 "$STAGED_BIN" "$INSTALL_BIN"
  tp installed "$INSTALL_BIN"
}

act_stop(){ echo "$(t act_stopping)"; systemctl stop "$SVC_NAME"; ok "$(t act_stopped)"; }
act_restart(){
  echo "$(t act_restarting)"; systemctl restart "$SVC_NAME"
  local port; port="$(get_env FLUXGATE_ADMIN_ADDR)"; port="${port##*:}"
  wait_ready "${port:-0}" || true
  ok "$(t act_restarted)"; print_access ""
}

# (Re-)download the GeoIP database on every install/update. Non-fatal on failure.
download_geo(){
  echo "$(t geo_dl)"
  mkdir -p "$(dirname "$GEO_FILE")"
  if curl -fL --progress-bar --max-time 60 -o "${GEO_FILE}.tmp" "$GEO_URL"; then
    mv -f "${GEO_FILE}.tmp" "$GEO_FILE"
    id "$SVC_USER" >/dev/null 2>&1 && chown -R "$SVC_USER:$SVC_USER" "$(dirname "$GEO_FILE")" 2>/dev/null || true
    ok "$(t geo_done)"
  else
    rm -f "${GEO_FILE}.tmp"
    warn "$(t geo_fail)"
  fi
}

wait_ready(){ # $1 = port
  printf '%s' "$(t waiting)"
  local _
  for _ in $(seq 1 20); do
    curl -fsk --max-time 2 "https://127.0.0.1:$1/health" >/dev/null 2>&1 && { echo; return 0; }
    printf '.'; sleep 1
  done
  echo; return 1
}

# Print access info. $1 = plaintext password to show, or empty to mark unchanged.
print_access(){
  local pass="$1" port user ip
  port="$(get_env FLUXGATE_ADMIN_ADDR)"; port="${port##*:}"
  user="$(get_env FLUXGATE_ADMIN_USER)"; [ -n "$user" ] || user="admin"
  ip="$(detect_ip)"; [ -n "$ip" ] || ip="<server-ip>"
  echo
  ok "====================$(t done_banner)===================="
  echo "  $(t l_console) : $(b "https://${ip}:${port}/")"
  echo "  $(t l_account) : $(b "${user}")"
  if [ -n "$pass" ]; then
    echo "  $(t l_password) : $(b "${pass}")"
  else
    echo "  $(t l_password) : $(t pass_unchanged)"
  fi
  echo "  $(t l_proxy) : HTTP ${PROXY_HTTP}  /  HTTPS ${PROXY_HTTPS}"
  ok "==================================================="
  echo
  warn "$(t tips)"
  echo "$(t tip_tls)"
  tp tip_fw "$port"
  tp tip_env "$ENV_FILE"
  echo
  echo "$(t cmds)"
  tp c_status "$SVC_NAME"
  tp c_logs "$SVC_NAME"
  echo "$(t c_manage)"
  echo "$(t c_uninstall)"
}

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
do_uninstall(){
  systemctl disable --now "$SVC_NAME" 2>/dev/null || true
  rm -f "$SVC_FILE"; systemctl daemon-reload
  rm -f "$INSTALL_BIN"
  warn "$(t uni_done)"
  tp uni_keep "$DATA_DIR" "$ETC_DIR"
}

# Update = download+validate latest (service still up) → stop → swap → refresh
# GeoIP → start. The fallible download happens with ZERO downtime; if the new
# binary won't start, roll back to the previous one.
do_update(){
  echo "$(t act_updating)"
  stage_binary                                  # download + validate while running
  local port; port="$(get_env FLUXGATE_ADMIN_ADDR)"; port="${port##*:}"
  systemctl stop "$SVC_NAME" 2>/dev/null || true
  [ -f "$INSTALL_BIN" ] && cp -f "$INSTALL_BIN" "${INSTALL_BIN}.bak"   # rollback copy
  install_staged
  download_geo
  if systemctl start "$SVC_NAME" && wait_ready "${port:-0}"; then
    ok "$(t update_done)"
    print_access ""
    return 0
  fi
  # New version failed — roll back to the previous binary.
  warn "$(t rollback)"
  if [ -f "${INSTALL_BIN}.bak" ]; then
    install -m 0755 "${INSTALL_BIN}.bak" "$INSTALL_BIN"
    systemctl start "$SVC_NAME" 2>/dev/null || true
    wait_ready "${port:-0}" && ok "$(t rolled_back)" || true
  fi
  err "$(t not_ready)"; journalctl -u "$SVC_NAME" -n 25 --no-pager || true
  exit 1
}

manage_menu(){
  warn "$(t menu_title)"
  echo "$(t menu_stop)"
  echo "$(t menu_restart)"
  echo "$(t menu_update)"
  local c=""
  [ -n "$TTY" ] && { printf '%s' "$(t menu_prompt)" > "$TTY"; read -r c < "$TTY" || c=""; }
  case "$c" in
    1) act_stop;;
    2) act_restart;;
    3) do_update;;
    *) err "$(t menu_invalid)"; exit 1;;
  esac
}

do_install(){
  echo "$(t title)"

  # account (env override → prompt → default)
  local ADMIN_USER="${FLUXGATE_ADMIN_USER:-}"
  if [ -z "$ADMIN_USER" ] && [ -n "$TTY" ]; then
    printf '%s' "$(t ask_user)" > "$TTY"; read -r ADMIN_USER < "$TTY" || ADMIN_USER=""
  fi
  ADMIN_USER="${ADMIN_USER:-admin}"

  # password (env override → prompt+confirm → auto-generate)
  local ADMIN_PASS="${FLUXGATE_ADMIN_PASSWORD:-}"
  if [ -z "$ADMIN_PASS" ]; then
    if [ -n "$TTY" ]; then
      while :; do
        printf '%s' "$(t ask_pass)" > "$TTY"; read -rs ADMIN_PASS < "$TTY" || ADMIN_PASS=""; echo > "$TTY"
        if [ -z "$ADMIN_PASS" ]; then ADMIN_PASS="$(gen_password)"; ok "$(t pass_gen)"; break; fi
        local ADMIN_PASS2=""
        printf '%s' "$(t ask_pass2)" > "$TTY"; read -rs ADMIN_PASS2 < "$TTY" || ADMIN_PASS2=""; echo > "$TTY"
        [ "$ADMIN_PASS" = "$ADMIN_PASS2" ] && break
        warn "$(t pass_mismatch)"
      done
    else
      ADMIN_PASS="$(gen_password)"; ok "$(t pass_gen)"
    fi
  fi

  local ADMIN_PORT ADMIN_TOKEN
  ADMIN_PORT="$(pick_free_port)"
  ADMIN_TOKEN="$(gen_token)"

  # system user + dirs
  if ! id "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
      || useradd --system --no-create-home "$SVC_USER"
  fi
  mkdir -p "$DATA_DIR" "${DATA_DIR}/certs" "${DATA_DIR}/geoip" "$ETC_DIR"
  chown -R "$SVC_USER:$SVC_USER" "$DATA_DIR"

  stage_binary
  install_staged
  download_geo

  # env file (0600)
  umask 077
  cat > "$ENV_FILE" <<EOF
FLUXGATE_ADMIN_ADDR=0.0.0.0:${ADMIN_PORT}
FLUXGATE_PROXY_ADDR=${PROXY_HTTP}
FLUXGATE_PROXY_TLS_ADDR=${PROXY_HTTPS}
FLUXGATE_ADMIN_USER=${ADMIN_USER}
FLUXGATE_ADMIN_PASSWORD=${ADMIN_PASS}
FLUXGATE_ADMIN_TOKEN=${ADMIN_TOKEN}
FLUXGATE_CERT_DIR=${DATA_DIR}/certs
FLUXGATE_DATA_FILE=${DATA_DIR}/fluxgate-data.json
FLUXGATE_GEOIP_DB=${GEO_FILE}
EOF
  chmod 600 "$ENV_FILE"; chown root:root "$ENV_FILE"
  umask 022

  # systemd unit (non-root user + CAP_NET_BIND_SERVICE for 80/443)
  cat > "$SVC_FILE" <<EOF
[Unit]
Description=FluxGate reverse proxy + WAF admin console
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
WorkingDirectory=${DATA_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${INSTALL_BIN}
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${DATA_DIR}
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SVC_NAME" >/dev/null 2>&1 || true
  systemctl restart "$SVC_NAME"

  if ! wait_ready "$ADMIN_PORT"; then
    err "$(t not_ready)"; journalctl -u "$SVC_NAME" -n 25 --no-pager || true
    err "$(printf "$(t troubleshoot)" "$SVC_NAME")"; exit 1
  fi
  print_access "$ADMIN_PASS"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
select_language          # 1) language menu first

if [ "$DO_UNINSTALL" -eq 1 ]; then
  require_root
  do_uninstall
  exit 0
fi

require_root
command -v curl >/dev/null 2>&1 || { err "$(t need_curl)"; exit 1; }
command -v systemctl >/dev/null 2>&1 || { err "$(t need_systemd)"; exit 1; }

if is_installed; then        # 2) already installed → stop / restart / update
  case "$ACTION" in
    stop)    act_stop;;
    restart) act_restart;;
    update)  do_update;;
    *)
      if [ -n "$TTY" ]; then
        manage_menu          # interactive: show the 1/2/3 menu
      else
        warn "$(t menu_title)"; echo "$(t menu_noninteractive)"; exit 0
      fi
      ;;
  esac
else
  do_install
fi
