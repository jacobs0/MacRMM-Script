# MacRMM-Script

This script is designed to assist users in adding Mac agents to Tactical RMM without the need for upfront payment for code-signed agents. If you find this solution beneficial, please consider contributing to the Tactical RMM project!

> This script had a complete rewrite and now only supports MacOS 14 (Sonoma) and above.

# rmmagent-script

Script for one-line installation, updating, and management of the TacticalRMM agent.

> Currently, both amd64 and arm64 scripts are available and has been tested with MacOS 14 (Sonoma) and MacOS 15 (Sequoia).

Scripts for additional platforms will be developed and released as they are adapted. You are welcome to modify the script and contribute your improvements back to the project.

# Usage

Download the script that match your configuration, or use the one-line `curl` commands below.

### One-line examples (new)

```bash
# Manual install with explicit parameters
sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh)" install 'APIURL' 'ClientID' 'SiteID' 'AuthKey' 'AgentType'

# Auto install using preconfigured variables inside the script
sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh)" auto_install

# Interactive install (prompts for each value)
sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh)" interactive_install

# Permissions / Sequoia fix / update / uninstall
sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh)" enablepermissions
sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh)" sequoiafix
sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh)" update
sudo /bin/bash -c "$(curl -sSL https://raw.githubusercontent.com/SyNode-IT/MacRMM-Script/main/rmmagent-mac.sh)" uninstall
```

## Install
To install agent launch the script with this argument:

```bash
./rmmagent-mac.sh install 'API URL' 'Client ID' 'Site ID' 'Auth Key' 'Agent Type'
```

The compiling can be quite long, don't panic and wait few minutes... **USE THE 'SINGLE QUOTES' IN ALL FIELDS!**

The argument are:

1. **API URL**  
   Your api URL for agent communication usually `https://api.fqdn.com`.

2. **Client ID**  
   The ID of the client in which agent will be added.  
   Can be view by hovering the name of the client in the dashboard.

3. **Site ID**  
   The ID of the site in which agent will be added.  
   Can be view by hovering the name of the site in the dashboard.

4. **Auth Key**  
   Authentication key given by dashboard by going to `dashboard > Agents > Install agent (Windows) > Select manual and show`  
   Copy **ONLY** the key after `--auth`.

5. **Agent Type**  
   Can be `server` or `workstation` and define the type of agent.

### Example
```bash
./rmmagent-mac.sh install "https://api.fqdn.com" 3 1 "XXXXX" server
```

> **What happens during install (new script):**  
> - Installs/updates **Go** automatically (`/usr/local/go`) and sets `PATH` for the current process.  
> - Downloads sources and **compiles** the TacticalRMM agent locally for your arch (`amd64`/`arm64`).  
> - Installs the agent and Mesh under `/opt/tacticalagent` and `/opt/tacticalmesh`, loads launchd plists.  
> - Clears quarantine attributes on Mesh (`xattr`) to avoid prompts.  
> - **Automatically applies TCC permissions** and shows post-install guidance.  

---

## Auto Install (new)
Runs installation using **preconfigured variables** inside the script.

```bash
./rmmagent-mac.sh auto_install
```

Preconfigured block you can edit at the top of the script:
```bash
API_URL="https://api.tld.com/"
CUSTOMER_ID="5"
GROUP_ID="9"
AGENT_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
AGENT_TYPE="workstation"   # server|workstation
```

Tips:
- Set `DEBUG=true` (env var) to print parameters without secrets:
  ```bash
  DEBUG=true ./rmmagent-mac.sh auto_install
  ```

---

## Interactive Install (new)
Prompts you for each value and validates inputs:

```bash
./rmmagent-mac.sh interactive_install
```

> You’ll confirm parameters before proceeding. The script then installs Go, compiles, installs the agent, applies permissions, and prints post-install steps.

---

## Update
Simply launch the script that match your system with *update* as argument.

```bash
./rmmagent-mac.sh update
```

> **What happens during update (new script):**  
> - Installs/updates Go if needed, **rebuilds** the agent from source for the local arch.  
> - Safely stops the service, replaces the binary, and reloads launchd.  
> - Clears Mesh quarantine and **re-applies TCC permissions automatically**.

---

## Enable Permissions
This sets up all the permissions for screenrecording, file, and disk access for the meshagent.

```bash
./rmmagent-mac.sh enablepermissions
```

> **Details (new script):**  
> - Grants **Accessibility**, **Screen Recording**, and **Full Disk Access** to `/opt/tacticalmesh/meshagent`.  
> - Grants **Full Disk Access** to `/opt/tacticalagent/tacticalagent`.  
> - Updates the **system TCC database** directly and restarts `tccd`/Mesh in the user session.  
> - Useful if permissions were reset by macOS. (Install/Update already apply them automatically.)

---

## Sequoia Fix
This will fix issues with "Take Control" from the dashboard not displaying the screen. Credit goes to [PeetMcK](https://github.com/PeetMcK) and [si458](https://github.com/si458) for the solution <https://github.com/Ylianst/MeshCentral/issues/6402>

```bash
./rmmagent-mac.sh sequoiafix
```

> **Details (new script):**  
> - Installs a **LaunchAgent** plist for Mesh (`/Library/LaunchAgents/meshagent.plist`) suited to macOS 15.  
> - Sets safe permissions on `/opt/tacticalmesh/meshagent.msh` and `/opt/tacticalmesh/meshagent.db`.  
> - Applies regardless of detected version, but warns if not on 15.x.

---

## Uninstall
To uninstall the agent, execute the script with the following argument:

```bash
./rmmagent-mac.sh uninstall
```

> **Details (new script):**  
> - Stops and removes **TacticalRMM agent** (`/Library/LaunchDaemons/tacticalagent.plist`, `/opt/tacticalagent`, `/etc/tacticalagent`).  
> - Fully removes **Mesh** (bootout, `-fulluninstall`, delete `/opt/tacticalmesh`, and TCC cleanup).  

### WARNING
- You should **only** attempt this if the agent removal feature on TacticalRMM is not working.
- Running uninstall will **not** remove the connections from the TacticalRMM and MeshCentral Dashboard. You will need to manually remove them. It only forcefully removes the agents from your macOS box.

---

## Help (new)
Display inline help and command list:

```bash
./rmmagent-mac.sh help
```

Shows:
```
install <api_url> <client_id> <site_id> <auth_key> <agent_type>
auto_install
interactive_install
update
uninstall
enablepermissions
sequoiafix
help
```

---

## Requirements & Notes

- **Run as root** (`sudo` required).  
- Requires: `curl`, `unzip`, `sqlite3`, `xattr`, `launchctl`, `installer`, `codesign`, `awk`, `xxd`, `tee`.  
- On Apple Silicon, **Rosetta** is auto-installed if needed.  
- After install/update, the script shows a **post-install banner** and recommends a reboot to finalize changes.  
