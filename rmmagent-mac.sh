#!/bin/bash
set -euo pipefail

###############################################
# TacticalRMM / Mesh Agent macOS Helper Script
# All output/messages are in English.
# Requires: curl, unzip, sqlite3, xattr, launchctl, installer
###############################################

# -----------------------
# Usage examples (how to call the script)
# -----------------------
# sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh) install 'APIURL' 'ClientID' 'SiteID' 'AuthKey' 'AgentType'"
# sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh) install 'https://api.tld.com/' '5' '9' 'xxxxxxxxxx' 'workstation'"
# sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh) auto_install"
# sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh) interactive_install"
# sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh) enablepermissions"
# sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh) sequoiafix"
# sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh) update"
# sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh) uninstall"

# -----------------------
# Global configuration
# -----------------------

# Toggle debug output (true|false)
DEBUG=${DEBUG:-false}

###############################################
# Preconfigured variables for auto_install (edit as needed)
API_URL="https://api.tld.com/"
CUSTOMER_ID="5"
GROUP_ID="9"
AGENT_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
AGENT_TYPE="workstation"   # server|workstation
###############################################

# Go download URLs
GO_URL_AMD64="https://go.dev/dl/go1.24.4.darwin-amd64.pkg"
GO_URL_ARM64="https://go.dev/dl/go1.24.4.darwin-arm64.pkg"

# Temp working dir (auto-cleaned)
WORKDIR="$(mktemp -d /tmp/trmm.XXXXXX)"
cleanup() { rm -rf "$WORKDIR" 2>/dev/null || true; }
trap cleanup EXIT

# -----------------------
# UI helpers
# -----------------------
banner() {
  local message="${1:-}"
  echo ""
  echo "###############################################"
  echo "#                                             #"
  printf "#  %-43s#\n" "$message"
  echo "#                                             #"
  echo "###############################################"
  echo ""
}

note() { echo "[*] $*"; }
ok()   { echo "[OK] $*"; }
err()  { echo "[!!] $*" >&2; }

wait_with_progress() {
  local seconds="${1:-30}"
  local message="${2:-Waiting for agent to initialize}"
  echo "$message..."
  for (( i=seconds; i>=1; i-- )); do
    printf "\r%s... %d seconds remaining" "$message" "$i"
    sleep 1
  done
  printf "\r%s... Complete!                    \n" "$message"
  echo ""
}

# -----------------------
# System checks/helpers
# -----------------------
check_root() {
  banner "Privilege Verification"
  if [[ "$(id -u)" -ne 0 ]]; then
    err "This script must be run with root privileges (sudo)."
    exit 1
  fi
  ok "Root privileges confirmed."
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    err "Required command not found: $cmd"
    exit 1
  fi
}

check_dependencies() {
  banner "Dependency Check"
  local deps=(curl unzip sqlite3 xattr launchctl installer codesign awk xxd tee)
  for c in "${deps[@]}"; do
    require_cmd "$c"
  done
  ok "All required commands are available."
}

get_macos_version() {
  sw_vers -productVersion 2>/dev/null | awk -F. '{print $1 "." $2}'
}

is_sequoia() {
  # macOS 15.x = Sequoia
  local v
  v="$(sw_vers -productVersion 2>/dev/null)"
  [[ "$v" =~ ^15\. ]]
}

check_rosetta() {
  if [[ "$(uname -m)" == "arm64" ]]; then
    banner "Rosetta Verification"
    if ! /usr/bin/pgrep oahd >/dev/null 2>&1; then
      note "Rosetta is not installed. Installing..."
      /usr/sbin/softwareupdate --install-rosetta --agree-to-license
      ok "Rosetta installed."
    else
      ok "Rosetta is already installed."
    fi
  fi
}

# -----------------------
# Go installation
# -----------------------
go_install() {
  banner "Installing/Upgrading Go"
  local pkg="/tmp/golang.pkg"
  
  case "$(uname -m)" in
    x86_64) curl -fsSL -o "$pkg" "$GO_URL_AMD64" ;;
    arm64)  curl -fsSL -o "$pkg" "$GO_URL_ARM64" ;;
    *)      err "Unsupported architecture: $(uname -m)"; exit 1 ;;
  esac
  
  # Ensure directory exists (harmless if already present)
  mkdir -p /usr/local/go || true
  
  # Correct target for macOS pkg installer: the root volume
  /usr/sbin/installer -pkg "$pkg" -target "/"
  rm -f "$pkg"
  
  # Avoid sourcing /etc/profile (breaks under set -u).
  # Make go available right away for the current process:
  export PATH="/usr/local/go/bin:$PATH"
  
  ok "Go installation completed."
}

# -----------------------
# External installer (rmmagent-mac.sh)
# -----------------------
download_install_script() {
  banner "Downloading Installation Script"
  cd "$WORKDIR"
  curl -fsSL -O "https://raw.githubusercontent.com/mattchis/MacRMM-Script/main/rmmagent-mac.sh"
  chmod +x "./rmmagent-mac.sh"
  ok "Installation script downloaded to $WORKDIR/rmmagent-mac.sh"
}

# -----------------------
# Build / install TRMM agent (from source)
# -----------------------
getCSREQBlob() {
  # Sign the MeshAgent binary to extract a designated requirement, then convert to hex
  /usr/bin/codesign --detached /opt/tacticalmesh/meshagent.sig -s - /opt/tacticalmesh/meshagent
  local req_str
  req_str="$(/usr/bin/codesign -d -r- --detached /opt/tacticalmesh/meshagent.sig /opt/tacticalmesh/meshagent 2>&1 | awk -F ' => ' '/designated/{print $2}')"
  echo "$req_str" | /usr/bin/csreq -r- -b /tmp/csreq.bin >/dev/null 2>&1
  local req_hex
  req_hex="X'$("/usr/bin/xxd" -p /tmp/csreq.bin | tr -d '\n')'"
  rm -f /tmp/csreq.bin
  echo "$req_hex"
}

agent_compile() {
  banner "Compiling TacticalRMM Agent"
  local zip="$WORKDIR/rmmagent.zip"
  curl -fsSL -o "$zip" "https://github.com/amidaware/rmmagent/archive/refs/heads/master.zip"
  unzip -q "$zip" -d "$WORKDIR"
  rm -f "$zip"
  pushd "$WORKDIR/rmmagent-master" >/dev/null
  case "$(uname -m)" in
    x86_64) env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o "$WORKDIR/temp_rmmagent" ;;
    arm64)  env CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o "$WORKDIR/temp_rmmagent" ;;
  esac
  popd >/dev/null
  ok "Agent compiled to $WORKDIR/temp_rmmagent"
}

install_agent() {
  banner "Installing TacticalRMM Agent"
  cp "$WORKDIR/temp_rmmagent" /usr/local/bin/rmmagent
  /usr/local/bin/rmmagent -m install \
    -meshdir /opt/tacticalmesh \
    -api "$RMM_URL" \
    -client-id "$RMM_CLIENT_ID" \
    -site-id "$RMM_SITE_ID" \
    -agent-type "$RMM_AGENT_TYPE" \
    -auth "$RMM_AUTH"
  rm -f "$WORKDIR/temp_rmmagent"
  /usr/bin/xattr -r -d com.apple.quarantine /opt/tacticalmesh/meshagent || true
  ok "TacticalRMM agent installed."
}

update_agent() {
  banner "Updating TacticalRMM Agent"
  if [[ ! -f "$WORKDIR/temp_rmmagent" ]]; then
    err "No built agent found. Run agent_compile first."
    exit 1
  fi
  /bin/launchctl bootout system /Library/LaunchDaemons/tacticalagent.plist || true
  cp "$WORKDIR/temp_rmmagent" /opt/tacticalagent/tacticalagent
  rm -f "$WORKDIR/temp_rmmagent"
  /bin/launchctl load -w /Library/LaunchDaemons/tacticalagent.plist
  /usr/bin/xattr -r -d com.apple.quarantine /opt/tacticalmesh/meshagent || true
  ok "Agent updated."
}

# -----------------------
# Privacy / TCC (Interactive control)
# -----------------------
config_securityandprivacy() {
  banner "Applying Security & Privacy Exceptions (TCC)"
  
  # Paths
  local MESH="/opt/tacticalmesh/meshagent"
  local TACT="/opt/tacticalagent/tacticalagent"
  
  # DB paths
  local SYSTEM_TCCDB="/Library/Application Support/com.apple.TCC/TCC.db"
  local CONSOLE_USER; CONSOLE_USER="$(stat -f%Su /dev/console)"
  
  # ---- Clean existing SYSTEM entries for MeshAgent & TacticalAgent (avoid stale rows)
  sqlite3 "$SYSTEM_TCCDB" "DELETE FROM access WHERE client='$MESH' AND service IN ('kTCCServiceAccessibility','kTCCServiceScreenCapture','kTCCServiceSystemPolicyAllFiles');" || true
  sqlite3 "$SYSTEM_TCCDB" "DELETE FROM access WHERE client='$TACT' AND service='kTCCServiceSystemPolicyAllFiles';" || true
  
  # ---- SYSTEM DB grants (path-only, csreq=NULL)
  # MeshAgent: Accessibility, Screen Recording, Full Disk Access
  sqlite3 "$SYSTEM_TCCDB" "REPLACE INTO access VALUES('kTCCServiceAccessibility','$MESH',1,2,4,1,NULL,NULL,0,'UNUSED',NULL,0,NULL,NULL,NULL,NULL,NULL);" || true
  sqlite3 "$SYSTEM_TCCDB" "REPLACE INTO access VALUES('kTCCServiceScreenCapture','$MESH',1,2,4,1,NULL,NULL,0,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL);" || true
  sqlite3 "$SYSTEM_TCCDB" "REPLACE INTO access VALUES('kTCCServiceSystemPolicyAllFiles','$MESH',1,2,4,1,NULL,NULL,0,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL);" || true
  
  # TacticalAgent: Full Disk Access
  sqlite3 "$SYSTEM_TCCDB" "REPLACE INTO access VALUES('kTCCServiceSystemPolicyAllFiles','$TACT',1,2,4,1,NULL,NULL,0,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL);" || true

  # ---- Refresh TCC & relaunch Mesh in user session
  /usr/bin/killall -HUP tccd 2>/dev/null || true
  if [[ -n "${CONSOLE_USER:-}" ]]; then
    sudo -u "$CONSOLE_USER" /usr/bin/killall -HUP tccd 2>/dev/null || true
  fi
  if [[ -f "/Library/LaunchAgents/meshagent.plist" ]]; then
    launchctl bootout gui/$(id -u "$CONSOLE_USER") /Library/LaunchAgents/meshagent.plist 2>/dev/null || true
    launchctl bootstrap gui/$(id -u "$CONSOLE_USER") /Library/LaunchAgents/meshagent.plist 2>/dev/null || true
  fi
  
  ok "TCC permissions applied (system & user DB) and services refreshed."
}

# -----------------------
# Uninstall (Agent / Mesh)
# -----------------------
uninstall_agent() {
  banner "Uninstalling TacticalRMM Agent"
  if [[ -f "/Library/LaunchDaemons/tacticalagent.plist" ]]; then
    /bin/launchctl bootout system /Library/LaunchDaemons/tacticalagent.plist || true
    rm -f /Library/LaunchDaemons/tacticalagent.plist
  fi
  rm -rf /opt/tacticalagent 2>/dev/null || true
  rm -f /etc/tacticalagent 2>/dev/null || true
  sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" "DELETE FROM access WHERE client='/opt/tacticalagent/tacticalagent';" || true
  ok "TacticalRMM Agent uninstalled."
}

uninstall_mesh() {
  banner "Uninstalling Mesh Agent"
  /bin/launchctl bootout system /Library/LaunchDaemons/meshagent.plist 2>/dev/null || true
  rm -f /Library/LaunchAgents/meshagent-agent.plist 2>/dev/null || true
  rm -f /Library/LaunchAgents/meshagent.plist 2>/dev/null || true
  if [[ -x "/opt/tacticalmesh/meshagent" ]]; then
    /opt/tacticalmesh/meshagent -fulluninstall || true
  fi
  rm -rf /opt/tacticalmesh 2>/dev/null || true
  sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" "DELETE FROM access WHERE client='/opt/tacticalmesh/meshagent';" || true
  ok "Mesh Agent uninstalled."
}

# -----------------------
# Sequoia (macOS 15) fix
# -----------------------
sequoia_fix() {
  banner "Applying Sequoia Fix"
  rm -f /Library/LaunchAgents/meshagent-agent.plist 2>/dev/null || true
  rm -f /Library/LaunchDaemons/meshagent.plist 2>/dev/null || true

  /usr/bin/tee /Library/LaunchAgents/meshagent.plist >/dev/null << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Disabled</key>
  <false/>
  <key>KeepAlive</key>
  <true/>
  <key>Label</key>
  <string>meshagent-agent</string>
  <key>LimitLoadToSessionType</key>
  <array>
    <string>Aqua</string>
    <string>LoginWindow</string>
  </array>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/tacticalmesh/meshagent</string>
    <string>--no-embedded=1</string>
    <string>--installedByUser=NaN</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>WorkingDirectory</key>
  <string>/opt/tacticalmesh</string>
</dict>
</plist>
EOF

  chown root:wheel /Library/LaunchAgents/meshagent.plist
  chmod 644 /Library/LaunchAgents/meshagent.plist
  chmod 666 /opt/tacticalmesh/meshagent.msh 2>/dev/null || true
  chmod 666 /opt/tacticalmesh/meshagent.db 2>/dev/null || true
  ok "Sequoia fix applied."
}

# -----------------------
# Post-install instructions (User-facing)
# -----------------------
show_post_install_instructions() {
  banner "Installation Complete"
  cat <<'TXT'
###############################################################
#                                                             #
#                    INSTALLATION COMPLETE                    #
#                                                             #
#  ✓ Security permissions applied                             #
#  ✓ macOS version-specific fixes applied (if needed)         #
#                                                             #
#  If you need to manually check permissions:                 #
#                                                             #
#  1. Accessibility:                                          #
#     -> /opt/tacticalmesh/MeshAgent                          #
#  2. Screen Recording:                                       #
#     -> /opt/tacticalmesh/MeshAgent                          #
#  3. Full Disk Access:                                       #
#     -> /opt/tacticalmesh/MeshAgent                          #
#     -> /opt/tacticalagent/TacticalAgent                     #
#                                                             #
#  ⚠️ IMPORTANT: Please reboot the Mac to ensure               #
#     all changes take full effect.                           #
#                                                             #
###############################################################
TXT
  echo ""
  echo "TacticalRMM Agent is now installed and configured!"
}

# -----------------------
# Install modes
# -----------------------
auto_install() {
  banner "Automatic Installation"
  check_rosetta
  download_install_script

  if [[ "$DEBUG" == "true" ]]; then
    banner "Installation Parameters (Debug Mode)"
    echo "API_URL     : $API_URL"
    echo "CUSTOMER_ID : $CUSTOMER_ID"
    echo "GROUP_ID    : $GROUP_ID"
    echo "AGENT_KEY   : $AGENT_KEY"
    echo "AGENT_TYPE  : $AGENT_TYPE"
  else
    banner "Installation Parameters"
  fi

  banner "Starting Installation"
  (cd "$WORKDIR" && ./rmmagent-mac.sh install \
      "$API_URL" \
      "$CUSTOMER_ID" \
      "$GROUP_ID" \
      "$AGENT_KEY" \
      "$AGENT_TYPE")

  banner "Installation Successful"
  wait_with_progress 30 "Waiting for agent to initialize"
  config_securityandprivacy
  show_post_install_instructions
}

manual_install() {
  # Args: <api_url> <client_id> <site_id> <auth_key> <agent_type>
  RMM_URL="$1"
  RMM_CLIENT_ID="$2"
  RMM_SITE_ID="$3"
  RMM_AUTH="$4"
  RMM_AGENT_TYPE="$5"

  banner "Manual Installation"
  echo "API_URL    : $RMM_URL"
  echo "CLIENT_ID  : $RMM_CLIENT_ID"
  echo "SITE_ID    : $RMM_SITE_ID"
  echo "AGENT_TYPE : $RMM_AGENT_TYPE"

  go_install
  agent_compile
  install_agent

  ok "Manual installation completed."
  wait_with_progress 30 "Waiting for agent to initialize"
  config_securityandprivacy
  show_post_install_instructions
}

interactive_install() {
  banner "Interactive Installation"
  echo "Please enter the following information:"
  echo ""
  read -rp "API URL: " RMM_URL
  [[ -n "${RMM_URL:-}" ]] || { err "API URL cannot be empty!"; exit 1; }

  read -rp "Client ID: " RMM_CLIENT_ID
  [[ -n "${RMM_CLIENT_ID:-}" ]] || { err "Client ID cannot be empty!"; exit 1; }

  read -rp "Site ID: " RMM_SITE_ID
  [[ -n "${RMM_SITE_ID:-}" ]] || { err "Site ID cannot be empty!"; exit 1; }

  read -rp "Authentication Key: " RMM_AUTH
  [[ -n "${RMM_AUTH:-}" ]] || { err "Authentication Key cannot be empty!"; exit 1; }

  while true; do
    read -rp "Agent Type (server/workstation): " RMM_AGENT_TYPE
    if [[ "$RMM_AGENT_TYPE" == "server" || "$RMM_AGENT_TYPE" == "workstation" ]]; then
      break
    else
      echo "Please enter 'server' or 'workstation'"
    fi
  done

  echo ""
  echo "Installation parameters:"
  echo "API_URL    : $RMM_URL"
  echo "CLIENT_ID  : $RMM_CLIENT_ID"
  echo "SITE_ID    : $RMM_SITE_ID"
  echo "AGENT_TYPE : $RMM_AGENT_TYPE"
  echo ""

  read -rp "Proceed with installation? (y/N): " confirm
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Installation cancelled."
    exit 0
  fi

  go_install
  agent_compile
  install_agent

  ok "Interactive installation completed."
  wait_with_progress 30 "Waiting for agent to initialize"
  config_securityandprivacy
  show_post_install_instructions
}

# -----------------------
# Help / usage
# -----------------------
show_help() {
  cat <<'HELP'
TacticalRMM Agent installation/management script for macOS

Usage:
  script.sh install <api_url> <client_id> <site_id> <auth_key> <agent_type>
                              Manual installation with parameters
  script.sh auto_install      Automatic installation using preconfigured variables
  script.sh interactive_install
                              Interactive installation (prompts for each parameter)
  script.sh update            Update the agent (build + deploy)
  script.sh uninstall         Complete uninstallation (agent + mesh)
  script.sh enablepermissions Apply Security & Privacy (TCC) permissions
  script.sh sequoiafix        Apply Sequoia (macOS 15) fix
  script.sh help              Show this help

Arguments for manual installation:
  api_url     : RMM API URL
  client_id   : Client ID
  site_id     : Site ID
  auth_key    : Authentication key
  agent_type  : 'server' or 'workstation'

More information: github.com/mattchis/rmmagent-macos
HELP
}

validate_args() {
  local cmd="${1:-}"
  [[ -n "$cmd" ]] || { err "First argument is missing!"; show_help; exit 1; }

  case "$cmd" in
    install|auto_install|interactive_install|update|uninstall|enablepermissions|sequoiafix|help) : ;;
    *) err "Invalid first argument: $cmd"; show_help; exit 1 ;;
  esac

  if [[ "$cmd" == "install" ]]; then
    if [[ "${2:-}" == "" || "${3:-}" == "" || "${4:-}" == "" || "${5:-}" == "" || "${6:-}" == "" ]]; then
      err "All arguments are required for manual installation!"
      echo "Usage: $0 install <api_url> <client_id> <site_id> <auth_key> <agent_type>"
      exit 1
    fi
    if [[ "${6}" != "server" && "${6}" != "workstation" ]]; then
      err "Agent type must be 'server' or 'workstation'!"
      exit 1
    fi
  fi
}

# -----------------------
# Main
# -----------------------
main() {
  validate_args "${@:-}"
  [[ "${1:-}" == "help" ]] && { show_help; exit 0; }

  check_root
  check_dependencies
  banner "Script Execution Started"

  case "$1" in
    install)
      manual_install "$2" "$3" "$4" "$5" "$6"
      ;;
    auto_install)
      auto_install
      ;;
    interactive_install)
      interactive_install
      ;;
    enablepermissions)
      local ver
      ver="$(get_macos_version)"
      echo "macOS version $ver detected"
      config_securityandprivacy
      echo "Security permissions configuration completed."
      ;;
    sequoiafix)
      local ver
      ver="$(get_macos_version)"
      echo "macOS version $ver detected"
      if is_sequoia; then
        echo "macOS Sequoia confirmed, applying Sequoia fix..."
      else
        echo "macOS Sequoia not detected (current: $ver). Applying fix anyway as requested..."
      fi
      sequoia_fix
      echo "Sequoia fix applied. A reboot may be required."
      ;;
    update)
      go_install
      agent_compile
      update_agent
      echo "Agent update completed."
      wait_with_progress 30 "Waiting for agent to initialize"
      config_securityandprivacy
      echo "Update process completed with automatic permission configuration."
      ;;
    uninstall)
      uninstall_agent
      uninstall_mesh
      banner "Uninstallation Complete"
      echo "TacticalRMM/Mesh Agent uninstallation completed."
      echo "You may need to manually remove orphaned agent connections on TacticalRMM and MeshCentral."
      ;;
  esac
}

main "$@"
