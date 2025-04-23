#!/usr/bin/env bash

# Advanced Offensive Security Toolkit Installer
# Version: 1.1
# Author: Zubair Usman (Mr.Pop3y3)|zus3c@github.com
# Contact: https://github.com/zus3c
# Features: Enhanced error handling, credential management, parallel installations, and dependency resolution

# Configuration
TOOLS_DIR="${HOME}/Tools"
LOG_FILE="${TOOLS_DIR}/install.log"
LOCK_FILE="/tmp/offsec-toolkit.lock"
VENV_DIR="${TOOLS_DIR}/.venvs"
CONFIG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAX_PARALLEL_INSTALLS=5
GITHUB_CREDENTIALS_FILE="${HOME}/.offsec_github_creds"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global variables
declare -A INSTALL_RESULTS
declare -A INSTALL_TIMES
declare -A pids_tool_map  # Explicitly declared
GITHUB_USER=""
GITHUB_TOKEN=""
START_TIME=$(date +%s)

# Initialize logging
setup_logging() {
    if ! mkdir -p "${TOOLS_DIR}"; then
        echo "Failed to create tools directory ${TOOLS_DIR}" >&2
        exit 1
    fi
    exec 3>&1 4>&2
    trap 'exec 2>&4 1>&3' EXIT
    exec > >(tee -a "${LOG_FILE}") 2>&1
    echo -e "\n\n=== Installation started at $(date) ===" >> "${LOG_FILE}"
}

# Display functions
header() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
 ██████╗ ███████╗███████╗███████╗ ██████╗███████╗
██╔═══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝
██║   ██║█████╗  █████╗  █████╗  ██║     █████╗  
██║   ██║██╔══╝  ██╔══╝  ██╔══╝  ██║     ██╔══╝  
╚██████╔╝██║     ██║     ███████╗╚██████╗███████╗
 ╚═════╝ ╚═╝     ╚═╝     ╚══════╝ ╚═════╝╚══════╝
EOF
    echo -e "${NC}"
    echo -e "${CYAN}Offensive Security Toolkit Installer - GPL-3.0 License${NC}"
    echo -e "${YELLOW}Copyright (C) 2023 | Author: Zus3c (Mr.Pop3y3)|zus3c@github.com${NC}"
    echo -e "${YELLOW}This program comes with ABSOLUTELY NO WARRANTY; for details run `./script --warranty`.${NC}"
    echo -e "${YELLOW}Version 1.1 | https://github.com/zus3c/offsec-toolkit${NC}"
    echo -e "${BLUE}=====================================================${NC}"
    echo -e "${MAGENTA}"
    echo -e "* LinkedIn: @zus3c"
    echo -e "* Twitter/X: @zus3cu"
    echo -e "${BLUE}=====================================================${NC}"
    echo ""
}

progress_bar() {
    local duration=${1}
    local columns=$(tput cols)
    local space=$(( columns - 20 ))
    local increment=$(( duration / space ))
    
    printf "["
    for (( i = 0; i < space; i++ )); do
        printf "#"
        sleep "$increment"
    done
    printf "]\n"
}

status_msg() {
    local status=${1}
    local message=${2}
    
    case "${status}" in
        "info") echo -e "${BLUE}[*]${NC} ${message}" ;;
        "success") echo -e "${GREEN}[+]${NC} ${message}" ;;
        "warning") echo -e "${YELLOW}[!]${NC} ${message}" ;;
        "error") echo -e "${RED}[X]${NC} ${message}" ;;
        *) echo -e "[ ] ${message}" ;;
    esac
}

# Credential management
get_github_credentials() {
    if [[ -f "${GITHUB_CREDENTIALS_FILE}" ]]; then
        # shellcheck source=/dev/null
        source "${GITHUB_CREDENTIALS_FILE}"
        if [[ -n "${GITHUB_USER}" && -n "${GITHUB_TOKEN}" ]]; then
            status_msg "info" "Using saved GitHub credentials"
            return 0
        fi
    fi

    header
    echo -e "${YELLOW}GitHub credentials are required for tools that need authentication${NC}"
    echo -e "${YELLOW}You can generate a token at: https://github.com/settings/tokens (no scopes needed)${NC}"
    
    while true; do
        read -rp "GitHub Username: " GITHUB_USER
        read -rp "GitHub Token: " -s GITHUB_TOKEN
        echo
        
        if [[ -z "${GITHUB_USER}" || -z "${GITHUB_TOKEN}" ]]; then
            status_msg "error" "Username and token cannot be empty"
            continue
        fi
        
        # Test credentials
        if curl -s -u "${GITHUB_USER}:${GITHUB_TOKEN}" https://api.github.com/user | grep -q '"login"'; then
            {
                echo "GITHUB_USER=\"${GITHUB_USER}\""
                echo "GITHUB_TOKEN=\"${GITHUB_TOKEN}\""
            } > "${GITHUB_CREDENTIALS_FILE}"
            chmod 600 "${GITHUB_CREDENTIALS_FILE}"
            status_msg "success" "GitHub credentials validated and saved"
            break
        else
            status_msg "error" "Invalid credentials. Please try again."
        fi
    done
}

# System checks
check_system() {
    status_msg "info" "Performing comprehensive system checks..."
    
    # Check for root
    if [[ $EUID -eq 0 ]]; then
        status_msg "warning" "Running as root is not recommended. Some tools may not work properly."
        read -rp "Continue anyway? [y/N] " response
        if [[ ! "${response}" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            exit 1
        fi
    fi

    # Check dependencies
    local deps=("git" "curl" "wget" "python3" "pip3" "make" "gcc" "unzip" "tar" "xz-utils")
    local missing=()
    local optional_deps=("docker" "ruby" "go" "rustc" "cargo")
    local missing_optional=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "${dep}" &> /dev/null; then
            missing+=("${dep}")
        fi
    done
    
    for dep in "${optional_deps[@]}"; do
        if ! command -v "${dep}" &> /dev/null; then
            missing_optional+=("${dep}")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        status_msg "error" "Missing required dependencies: ${missing[*]}"
        return 1
    fi
    
    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        status_msg "warning" "Missing optional dependencies (some tools may not work): ${missing_optional[*]}"
    fi
    
    # Check disk space
    local min_disk_space=10 # 10GB
    local available_space
    available_space=$(df -BG "${TOOLS_DIR}" | awk 'NR==2 {gsub("G","",$4); print $4}')
    
    if [[ "${available_space}" -lt "${min_disk_space}" ]]; then
        status_msg "warning" "Low disk space (${available_space}GB available, ${min_disk_space}GB recommended)"
    fi
    
    # Check internet connectivity
    if ! curl -Is https://github.com | head -n 1 | grep -q "200"; then
        status_msg "error" "No internet connectivity or GitHub is unreachable"
        return 1
    fi
    
    status_msg "success" "System checks passed"
    return 0
}

# Setup environment
setup_environment() {
    status_msg "info" "Setting up environment..."
    
    # Create tools directory
    if ! mkdir -p "${TOOLS_DIR}"; then
        status_msg "error" "Failed to create tools directory"
        return 1
    fi
    
    # Create category directories
    for category in "${!CATEGORIES[@]}"; do
        if ! mkdir -p "${TOOLS_DIR}/${category}"; then
            status_msg "error" "Failed to create ${category} directory"
            continue
        fi
    done
    
    # Create virtual environments directory
    mkdir -p "${VENV_DIR}"
    
    # Add tools directory to PATH if not already present
    if ! grep -q "${TOOLS_DIR}" "${HOME}/.bashrc"; then
        echo "export PATH=\"${TOOLS_DIR}:\$PATH\"" >> "${HOME}/.bashrc"
        status_msg "info" "Added ${TOOLS_DIR} to PATH in .bashrc"
    fi
    
    status_msg "success" "Environment setup complete"
    return 0
}

# Clone repository with authentication if needed
clone_repository() {
    local repo_url=$1
    local target_dir=$2
    local tool_name=$3
    
    # Handle GitHub rate limits by using authenticated requests
    if [[ "${repo_url}" == *"github.com"* ]] && [[ -n "${GITHUB_USER}" && -n "${GITHUB_TOKEN}" ]]; then
        repo_url="${repo_url/https:\/\//https://${GITHUB_USER}:${GITHUB_TOKEN}@}"
    fi
    
    if [[ -d "${target_dir}" ]]; then
        status_msg "info" "Updating existing installation..."
        if (cd "${target_dir}" && git pull --quiet); then
            return 0
        else
            status_msg "error" "Failed to update ${tool_name}"
            return 1
        fi
    else
        status_msg "info" "Cloning repository..."
        if git clone --quiet --depth 1 "${repo_url}" "${target_dir}"; then
            return 0
        else
            status_msg "error" "Failed to clone ${tool_name}"
            return 1
        fi
    fi
}

# Install Python dependencies in isolated environment
install_python_deps() {
    local tool_dir=$1
    local venv_dir=$2
    local tool_name=$3
    
    if [[ -f "${tool_dir}/requirements.txt" || -f "${tool_dir}/setup.py" ]]; then
        status_msg "info" "Setting up Python environment..."
        
        if ! python3 -m venv "${venv_dir}"; then
            status_msg "error" "Failed to create virtual environment for ${tool_name}"
            return 1
        fi
        
        # shellcheck source=/dev/null
        if ! source "${venv_dir}/bin/activate"; then
            status_msg "error" "Failed to activate virtual environment for ${tool_name}"
            return 1
        fi
        
        if ! pip install --quiet --upgrade pip; then
            status_msg "error" "Failed to upgrade pip for ${tool_name}"
            deactivate
            return 1
        fi
        
        if [[ -f "${tool_dir}/requirements.txt" ]]; then
            if ! pip install --quiet -r "${tool_dir}/requirements.txt"; then
                status_msg "error" "Failed to install requirements for ${tool_name}"
                deactivate
                return 1
            fi
        fi
        
        if [[ -f "${tool_dir}/setup.py" ]]; then
            if ! pip install --quiet -e "${tool_dir}"; then
                status_msg "error" "Failed to run setup.py for ${tool_name}"
                deactivate
                return 1
            fi
        fi
        
        deactivate
    fi
    
    return 0
}

# Run custom install scripts
run_custom_install() {
    local tool_dir=$1
    local tool_name=$2
    
    if [[ -f "${tool_dir}/install.sh" ]]; then
        status_msg "info" "Running install script..."
        chmod +x "${tool_dir}/install.sh"
        if ! (cd "${tool_dir}" && ./install.sh); then
            status_msg "error" "Install script failed for ${tool_name}"
            return 1
        fi
    fi
    
    if [[ -f "${tool_dir}/Makefile" ]]; then
        status_msg "info" "Running make install..."
        if ! (cd "${tool_dir}" && make install); then
            status_msg "error" "Make install failed for ${tool_name}"
            return 1
        fi
    fi
    
    return 0
}

# Install tool (main function for each tool)
install_tool() {
    local category=$1
    local tool=$2
    local repo_url=$3
    
    local tool_dir="${TOOLS_DIR}/${category}/${tool}"
    local venv_dir="${VENV_DIR}/${category}_${tool}"
    local start_time=$(date +%s)
    
    {
        status_msg "info" "Processing ${tool}..."
        
        # Clone/update repository
        if ! clone_repository "${repo_url}" "${tool_dir}" "${tool}"; then
            return 1
        fi
        
        # Handle Python dependencies
        if ! install_python_deps "${tool_dir}" "${venv_dir}" "${tool}"; then
            return 1
        fi
        
        # Run custom install scripts
        if ! run_custom_install "${tool_dir}" "${tool}"; then
            return 1
        fi
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        INSTALL_TIMES["${tool}"]="${duration}"
        
        status_msg "success" "Successfully installed ${tool} (${duration}s)"
        return 0
    } || {
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        INSTALL_TIMES["${tool}"]="${duration}"
        return 1
    }
}

# Parallel installation manager
parallel_install_manager() {
    local -n tool_list=$1
    local -A pids
    local running=0
    local total=${#tool_list[@]}
    local completed=0
    
    status_msg "info" "Starting parallel installation of ${total} tools (max ${MAX_PARALLEL_INSTALLS} concurrent)"
    
    for tool_path in "${!tool_list[@]}"; do
        local category="${tool_path%%/*}"
        local tool="${tool_path#*/}"
        local repo_url="${tool_list[$tool_path]}"
        
        while [[ ${running} -ge ${MAX_PARALLEL_INSTALLS} ]]; do
            # Wait for any background process to finish
            for pid in "${!pids[@]}"; do
                if ! kill -0 "${pid}" 2>/dev/null; then
                    # Process finished
                    unset "pids[${pid}]"
                    ((running--))
                    ((completed++))
                    
                    local tool_name="${pids_tool_map[$pid]}"
                    if [[ "${INSTALL_RESULTS[$tool_name]}" == "success" ]]; then
                        status_msg "success" "Completed: ${tool_name}"
                    else
                        status_msg "error" "Failed: ${tool_name}"
                    fi
                    
                    # Update progress
                    status_msg "info" "Progress: ${completed}/${total} tools completed"
                fi
            done
            sleep 1
        done
        
        # Start new installation in background
        (install_tool "${category}" "${tool}" "${repo_url}" && 
         INSTALL_RESULTS["${tool}"]="success" || 
         INSTALL_RESULTS["${tool}"]="failed") &
        local pid=$!
        pids["${pid}"]=1
        pids_tool_map["${pid}"]="${tool}"
        ((running++))
        
        # Small delay to prevent overwhelming the system
        sleep 1
    done
    
    # Wait for remaining processes
    while [[ ${running} -gt 0 ]]; do
        for pid in "${!pids[@]}"; do
            if ! kill -0 "${pid}" 2>/dev/null; then
                unset "pids[${pid}]"
                ((running--))
                ((completed++))
                
                local tool_name="${pids_tool_map[$pid]}"
                if [[ "${INSTALL_RESULTS[$tool_name]}" == "success" ]]; then
                    status_msg "success" "Completed: ${tool_name}"
                else
                    status_msg "error" "Failed: ${tool_name}"
                fi
                
                # Update progress
                status_msg "info" "Progress: ${completed}/${total} tools completed"
            fi
        done
        sleep 1
    done
}

# Main installation process
install_tools() {
    # Comprehensive tool database (300+ tools organized by category)
    declare -A TOOLS=(
        # ======================
        # RECONNAISSANCE TOOLS
        # ======================
        ["recon/amass"]="https://github.com/OWASP/Amass"
        ["recon/subfinder"]="https://github.com/projectdiscovery/subfinder"
        ["recon/assetfinder"]="https://github.com/tomnomnom/assetfinder"
        ["recon/findomain"]="https://github.com/Findomain/Findomain"
        ["recon/massdns"]="https://github.com/blechschmidt/massdns"
        ["recon/altdns"]="https://github.com/infosec-au/altdns"
        ["recon/dnsrecon"]="https://github.com/darkoperator/dnsrecon"
        ["recon/sublist3r"]="https://github.com/aboul3la/Sublist3r"
        ["recon/knock"]="https://github.com/guelfoweb/knock"
        ["recon/theHarvester"]="https://github.com/laramies/theHarvester"
        ["recon/spiderfoot"]="https://github.com/smicallef/spiderfoot"
        ["recon/recon-ng"]="https://github.com/lanmaster53/recon-ng"
        ["recon/maltego"]="https://github.com/paterva/maltego"
        ["recon/httprobe"]="https://github.com/tomnomnom/httprobe"
        ["recon/waybackurls"]="https://github.com/tomnomnom/waybackurls"
        ["recon/gau"]="https://github.com/lc/gau"
        ["recon/ffuf"]="https://github.com/ffuf/ffuf"
        ["recon/gobuster"]="https://github.com/OJ/gobuster"
        ["recon/dirsearch"]="https://github.com/maurosoria/dirsearch"
        ["recon/arjun"]="https://github.com/s0md3v/Arjun"

        # ==============================
        # SCANNING & ENUMERATION TOOLS
        # ==============================
        ["scanning/nmap"]="https://github.com/nmap/nmap"
        ["scanning/rustscan"]="https://github.com/RustScan/RustScan"
        ["scanning/masscan"]="https://github.com/robertdavidgraham/masscan"
        ["scanning/naabu"]="https://github.com/projectdiscovery/naabu"
        ["scanning/autorecon"]="https://github.com/Tib3rius/AutoRecon"
        ["scanning/enum4linux"]="https://github.com/portcullislabs/enum4linux"
        ["scanning/onesixtyone"]="https://github.com/trailofbits/onesixtyone"
        ["scanning/smbmap"]="https://github.com/ShawnDEvans/smbmap"
        ["scanning/ldapdomaindump"]="https://github.com/dirkjanm/ldapdomaindump"
        ["scanning/eyewitness"]="https://github.com/FortyNorthSecurity/EyeWitness"
        ["scanning/nuclei"]="https://github.com/projectdiscovery/nuclei"
        ["scanning/httpx"]="https://github.com/projectdiscovery/httpx"
        ["scanning/dnsenum"]="https://github.com/fwaeytens/dnsenum"
        ["scanning/snmpwalk"]="https://github.com/rmusser01/SnmpWalk"
        ["scanning/ike-scan"]="https://github.com/royhills/ike-scan"
        ["scanning/testssl"]="https://github.com/drwetter/testssl.sh"
        ["scanning/sslyze"]="https://github.com/nabla-c0d3/sslyze"
        ["scanning/wfuzz"]="https://github.com/xmendez/wfuzz"
        ["scanning/feroxbuster"]="https://github.com/epi052/feroxbuster"
        ["scanning/chisel"]="https://github.com/jpillora/chisel"

        # ===========================
        # VULNERABILITY ANALYSIS TOOLS
        # ===========================
        ["vulnerability/nessus"]="https://github.com/tenable/nessus"
        ["vulnerability/openvas"]="https://github.com/greenbone/openvas"
        ["vulnerability/nexpose"]="https://github.com/rapid7/nexpose"
        ["vulnerability/vuls"]="https://github.com/future-architect/vuls"
        ["vulnerability/trivy"]="https://github.com/aquasecurity/trivy"
        ["vulnerability/grype"]="https://github.com/anchore/grype"
        ["vulnerability/syft"]="https://github.com/anchore/syft"
        ["vulnerability/joomscan"]="https://github.com/rezasp/joomscan"
        ["vulnerability/wpscan"]="https://github.com/wpscanteam/wpscan"
        ["vulnerability/droopescan"]="https://github.com/droope/droopescan"
        ["vulnerability/retire.js"]="https://github.com/RetireJS/retire.js"
        ["vulnerability/ysoserial"]="https://github.com/frohoff/ysoserial"
        ["vulnerability/commix"]="https://github.com/commixproject/commix"
        ["vulnerability/jexboss"]="https://github.com/joaomatosf/jexboss"
        ["vulnerability/xsstrike"]="https://github.com/s0md3v/XSStrike"
        ["vulnerability/ssrfmap"]="https://github.com/swisskyrepo/SSRFmap"
        ["vulnerability/fuxploider"]="https://github.com/almandin/fuxploider"
        ["vulnerability/ground-control"]="https://github.com/jobertabma/ground-control"
        ["vulnerability/raccoon"]="https://github.com/evyatarmeged/Raccoon"
        ["vulnerability/jaeles"]="https://github.com/jaeles-project/jaeles"

        # =====================
        # EXPLOITATION TOOLS
        # =====================
        ["exploitation/metasploit"]="https://github.com/rapid7/metasploit-framework"
        ["exploitation/sqlmap"]="https://github.com/sqlmapproject/sqlmap"
        ["exploitation/exploitdb"]="https://github.com/offensive-security/exploitdb"
        ["exploitation/ropgadget"]="https://github.com/JonathanSalwan/ROPgadget"
        ["exploitation/pwntools"]="https://github.com/Gallopsled/pwntools"
        ["exploitation/autoexploit"]="https://github.com/NullArray/AutoSploit"
        ["exploitation/beef"]="https://github.com/beefproject/beef"
        ["exploitation/zerodoor"]="https://github.com/Souhardya/Zerodoor"
        ["exploitation/weevely"]="https://github.com/epinna/weevely3"
        ["exploitation/crackmapexec"]="https://github.com/byt3bl33d3r/CrackMapExec"
        ["exploitation/impacket"]="https://github.com/SecureAuthCorp/impacket"
        ["exploitation/routersploit"]="https://github.com/threat9/routersploit"
        ["exploitation/ghostpack"]="https://github.com/GhostPack"
        ["exploitation/shellerator"]="https://github.com/ShutdownRepo/shellerator"
        ["exploitation/evilwinrm"]="https://github.com/Hackplayers/evil-winrm"
        ["exploitation/chimera"]="https://github.com/tokyoneon/chimera"
        ["exploitation/redteam"]="https://github.com/depthsecurity/armory"
        ["exploitation/shellpop"]="https://github.com/0x00-0x00/shellpop"
        ["exploitation/winpayloads"]="https://github.com/nccgroup/Winpayloads"
        ["exploitation/darkarmour"]="https://github.com/bats3c/DarkArmour"

        # ======================
        # POST-EXPLOITATION TOOLS
        # ======================
        ["postexp/bloodhound"]="https://github.com/BloodHoundAD/BloodHound"
        ["postexp/powersploit"]="https://github.com/PowerShellMafia/PowerSploit"
        ["postexp/mimikatz"]="https://github.com/gentilkiwi/mimikatz"
        ["postexp/sliver"]="https://github.com/BishopFox/sliver"
        ["postexp/nishang"]="https://github.com/samratashok/nishang"
        ["postexp/empire"]="https://github.com/BC-SECURITY/Empire"
        ["postexp/merlin"]="https://github.com/Ne0nd0g/merlin"
        ["postexp/coercer"]="https://github.com/p0dalirius/Coercer"
        ["postexp/peas"]="https://github.com/carlospolop/PEASS-ng"
        ["postexp/linenum"]="https://github.com/rebootuser/LinEnum"
        ["postexp/winpeas"]="https://github.com/carlospolop/PEASS-ng"
        ["postexp/seatbelt"]="https://github.com/GhostPack/Seatbelt"
        ["postexp/sharphound"]="https://github.com/BloodHoundAD/SharpHound"
        ["postexp/rubeus"]="https://github.com/GhostPack/Rubeus"
        ["postexp/safetykatz"]="https://github.com/GhostPack/SafetyKatz"
        ["postexp/whisker"]="https://github.com/eladshamir/Whisker"
        ["postexp/evilcli"]="https://github.com/outflanknl/EvilClippy"
        ["postexp/dumpert"]="https://github.com/outflanknl/Dumpert"
        ["postexp/inveigh"]="https://github.com/Kevin-Robertson/Inveigh"
        ["postexp/pspy"]="https://github.com/DominicBreuker/pspy"

        # ======================
        # CREDENTIAL ACCESS TOOLS
        # ======================
        ["credential/hashcat"]="https://github.com/hashcat/hashcat"
        ["credential/john"]="https://github.com/openwall/john"
        ["credential/hash-identifier"]="https://github.com/blackploit/hash-identifier"
        ["credential/kerbrute"]="https://github.com/ropnop/kerbrute"
        ["credential/sprayhound"]="https://github.com/Hackndo/sprayhound"
        ["credential/spraykatz"]="https://github.com/aas-n/spraykatz"
        ["credential/patator"]="https://github.com/lanjelot/patator"
        ["credential/hydra"]="https://github.com/vanhauser-thc/thc-hydra"
        ["credential/medusa"]="https://github.com/jmk-foofus/medusa"
        ["credential/ncrack"]="https://github.com/nmap/ncrack"
        ["credential/cewl"]="https://github.com/digininja/CeWL"
        ["credential/rsmangler"]="https://github.com/digininja/RSMangler"
        ["credential/pipal"]="https://github.com/digininja/pipal"
        ["credential/secretfinder"]="https://github.com/m4ll0k/SecretFinder"
        ["credential/gittools"]="https://github.com/internetwache/GitTools"
        ["credential/gitjacker"]="https://github.com/liamg/gitjacker"
        ["credential/gitdumper"]="https://github.com/arthaud/git-dumper"
        ["credential/cloudbrute"]="https://github.com/0xsha/CloudBrute"
        ["credential/brutespray"]="https://github.com/x90skysn3k/brutespray"
        ["credential/defaultcreds"]="https://github.com/denandz/defaultcreds"

        # =========================
        # WEB APPLICATION TOOLS
        # =========================
        ["web/burpsuite"]="https://github.com/PortSwigger/burp-suite-community-src"
        ["web/zap"]="https://github.com/zaproxy/zaproxy"
        ["web/arachni"]="https://github.com/Arachni/arachni"
        ["web/wapiti"]="https://github.com/wapiti-scanner/wapiti"
        ["web/w3af"]="https://github.com/andresriancho/w3af"
        ["web/xsser"]="https://github.com/epsylon/xsser"
        ["web/xsstrike"]="https://github.com/s0md3v/XSStrike"
        ["web/ssrfmap"]="https://github.com/swisskyrepo/SSRFmap"
        ["web/ysoserial"]="https://github.com/frohoff/ysoserial"
        ["web/gadgetprobe"]="https://github.com/BishopFox/GadgetProbe"
        ["web/jwt_tool"]="https://github.com/ticarpi/jwt_tool"
        ["web/noSQLmap"]="https://github.com/codingo/NoSQLMap"
        ["web/dalfox"]="https://github.com/hahwul/dalfox"
        ["web/katana"]="https://github.com/projectdiscovery/katana"
        ["web/hakrawler"]="https://github.com/hakluke/hakrawler"
        ["web/gobuster"]="https://github.com/OJ/gobuster"
        ["web/ffuf"]="https://github.com/ffuf/ffuf"
        ["web/nuclei"]="https://github.com/projectdiscovery/nuclei"
        ["web/httpx"]="https://github.com/projectdiscovery/httpx"
        ["web/subjs"]="https://github.com/lc/subjs"

        # =====================
        # NETWORK TOOLS
        # =====================
        ["network/responder"]="https://github.com/lgandx/Responder"
        ["network/bettercap"]="https://github.com/bettercap/bettercap"
        ["network/mitm6"]="https://github.com/fox-it/mitm6"
        ["network/ntlmrelayx"]="https://github.com/SecureAuthCorp/impacket"
        ["network/pret"]="https://github.com/RUB-NDS/PRET"
        ["network/yersinia"]="https://github.com/tomac/yersinia"
        ["network/scapy"]="https://github.com/secdev/scapy"
        ["network/dsniff"]="https://github.com/tecknicaltom/dsniff"
        ["network/arp-scan"]="https://github.com/royhills/arp-scan"
        ["network/networkminer"]="https://github.com/netresec/NetworkMiner"
        ["network/chaosreader"]="https://github.com/brendangregg/Chaosreader"
        ["network/tcpdump"]="https://github.com/the-tcpdump-group/tcpdump"
        ["network/tcpreplay"]="https://github.com/appneta/tcpreplay"
        ["network/ostinato"]="https://github.com/pstavirs/ostinato"
        ["network/kerbrute"]="https://github.com/ropnop/kerbrute"
        ["network/coercer"]="https://github.com/p0dalirius/Coercer"
        ["network/pkinittools"]="https://github.com/dirkjanm/PKINITtools"
        ["network/pywhisker"]="https://github.com/ShutdownRepo/pywhisker"

        # =====================
        # WIRELESS TOOLS
        # =====================
        ["wireless/aircrack"]="https://github.com/aircrack-ng/aircrack-ng"
        ["wireless/kismet"]="https://github.com/kismetwireless/kismet"
        ["wireless/wifite"]="https://github.com/derv82/wifite2"
        ["wireless/reaver"]="https://github.com/t6x/reaver-wps-fork-t6x"
        ["wireless/bully"]="https://github.com/aanarchyy/bully"
        ["wireless/hcxtools"]="https://github.com/ZerBea/hcxtools"
        ["wireless/hcxdumptool"]="https://github.com/ZerBea/hcxdumptool"
        ["wireless/pyrit"]="https://github.com/JPaulMora/Pyrit"
        ["wireless/fluxion"]="https://github.com/FluxionNetwork/fluxion"
        ["wireless/wifiphisher"]="https://github.com/wifiphisher/wifiphisher"
        ["wireless/eaphammer"]="https://github.com/s0lst1c3/eaphammer"
        ["wireless/airgeddon"]="https://github.com/v1s1t0r1sh3r3/airgeddon"
        ["wireless/hostapd-wpe"]="https://github.com/OpenSecurityResearch/hostapd-wpe"
        ["wireless/fern-wifi-cracker"]="https://github.com/savio-code/fern-wifi-cracker"
        ["wireless/wifijammer"]="https://github.com/DanMcInerney/wifijammer"
        ["wireless/roguehostapd"]="https://github.com/wifiphisher/roguehostapd"
        ["wireless/eviltwin"]="https://github.com/s0lst1c3/eviltwin"
        ["wireless/wifi-pumpkin"]="https://github.com/P0cL4bs/wifi-pumpkin"
        ["wireless/lorcon"]="https://github.com/tomwimmenhove/lorcon"
        ["wireless/gr-scan"]="https://github.com/ptrkrysik/gr-scan"

        # =====================
        # RED TEAMING TOOLS
        # =====================
        ["redteam/cobaltstrike"]="https://github.com/rsmudge/cobalt-strike-toolkit"
        ["redteam/mythic"]="https://github.com/its-a-feature/Mythic"
        ["redteam/caldera"]="https://github.com/mitre/caldera"
        ["redteam/sliver"]="https://github.com/BishopFox/sliver"
        ["redteam/merlin"]="https://github.com/Ne0nd0g/merlin"
        ["redteam/bruteratel"]="https://github.com/OPENCYBER-FR/BruteRatel"
        ["redteam/artemis"]="https://github.com/mitre/artemis"
        ["redteam/raven"]="https://github.com/0x09AL/raven"
        ["redteam/taowu"]="https://github.com/panda-re/taowu"
        ["redteam/viper"]="https://github.com/FunnyWolf/Viper"
        ["redteam/hoaxshell"]="https://github.com/t3l3machus/hoaxshell"
        ["redteam/offensive_notebook"]="https://github.com/jstrosch/offensive-notebook"
        ["redteam/redteam_automation"]="https://github.com/Endermanch/MalwareDatabase"
        ["redteam/atomic_red_team"]="https://github.com/redcanaryco/atomic-red-team"
        ["redteam/t-rex"]="https://github.com/trustedsec/trex"
        ["redteam/redteam_tactics"]="https://github.com/mantvydasb/RedTeam-Tactics-and-Techniques"
        ["redteam/redteam_scripts"]="https://github.com/infosecn1nja/Red-Teaming-Toolkit"
        ["redteam/redteam_docker"]="https://github.com/0x4D31/redteam-docker"
        ["redteam/redteam_vs"]="https://github.com/microsoft/Red-Teaming-Toolkit"
        ["redteam/redteam_cheatsheet"]="https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki"

        # =====================
        # OSINT TOOLS
        # =====================
        ["osint/spiderfoot"]="https://github.com/smicallef/spiderfoot"
        ["osint/maltego"]="https://github.com/paterva/maltego"
        ["osint/recon-ng"]="https://github.com/lanmaster53/recon-ng"
        ["osint/theharvester"]="https://github.com/laramies/theHarvester"
        ["osint/sherlock"]="https://github.com/sherlock-project/sherlock"
        ["osint/socialscan"]="https://github.com/iojw/socialscan"
        ["osint/ghunt"]="https://github.com/mxrch/GHunt"
        ["osint/maigret"]="https://github.com/soxoj/maigret"
        ["osint/holehe"]="https://github.com/megadose/holehe"
        ["osint/toutatis"]="https://github.com/megadose/toutatis"
        ["osint/whatsmyname"]="https://github.com/WebBreacher/WhatsMyName"
        ["osint/phoneinfoga"]="https://github.com/sundowndev/phoneinfoga"
        ["osint/email2phonenumber"]="https://github.com/martinvigo/email2phonenumber"
        ["osint/ignorant"]="https://github.com/megadose/ignorant"
        ["osint/linkedin2username"]="https://github.com/initstring/linkedin2username"
        ["osint/namechk"]="https://github.com/HA71/Namechk"
        ["osint/blackbird"]="https://github.com/p1ngul1n0/blackbird"
        ["osint/twint"]="https://github.com/twintproject/twint"
        ["osint/waymore"]="https://github.com/xnl-h4ck3r/waymore"
        ["osint/social_mapper"]="https://github.com/Greenwolf/social_mapper"

        # =====================
        # ANDROID SECURITY TOOLS
        # =====================
        ["android/mobsf"]="https://github.com/MobSF/Mobile-Security-Framework-MobSF"
        ["android/jadx"]="https://github.com/skylot/jadx"
        ["android/apktool"]="https://github.com/iBotPeaches/Apktool"
        ["android/frida"]="https://github.com/frida/frida"
        ["android/objection"]="https://github.com/sensepost/objection"
        ["android/drozer"]="https://github.com/FSecureLABS/drozer"
        ["android/qark"]="https://github.com/linkedin/qark"
        ["android/androbugs"]="https://github.com/AndroBugs/AndroBugs_Framework"
        ["android/bytecodeviewer"]="https://github.com/Konloch/bytecode-viewer"
        ["android/androidtamer"]="https://github.com/androidtamer"
        ["android/santoku"]="https://github.com/santoku/Santoku-Linux"
        ["android/r2frida"]="https://github.com/nowsecure/r2frida"
        ["android/ghidra"]="https://github.com/NationalSecurityAgency/ghidra"
        ["android/cutter"]="https://github.com/rizinorg/cutter"
        ["android/radare2"]="https://github.com/radareorg/radare2"
        ["android/dex2jar"]="https://github.com/pxb1988/dex2jar"
        ["android/enjarify"]="https://github.com/google/enjarify"
        ["android/smali"]="https://github.com/JesusFreke/smali"
        ["android/baksmali"]="https://github.com/JesusFreke/smali"
        ["android/androguard"]="https://github.com/androguard/androguard"

        # =====================
        # IOS SECURITY TOOLS
        # =====================
        ["ios/objection"]="https://github.com/sensepost/objection"
        ["ios/frida"]="https://github.com/frida/frida"
        ["ios/ios_deploy"]="https://github.com/ios-control/ios-deploy"
        ["ios/ipatool"]="https://github.com/majd/ipatool"
        ["ios/bfinject"]="https://github.com/BishopFox/bfinject"
        ["ios/cycript"]="https://github.com/cycript/cycript"
        ["ios/needle"]="https://github.com/mwrlabs/needle"
        ["ios/ios_ssl_kill_switch"]="https://github.com/nabla-c0d3/ssl-kill-switch2"
        ["ios/ios_reverse_engineering"]="https://github.com/iosre/iOSAppReverseEngineering"
        ["ios/class_dump"]="https://github.com/nygard/class-dump"
        ["ios/ios_hacking"]="https://github.com/Siguza/ios-resources"
        ["ios/ios_triage"]="https://github.com/NowSecure/ios-triage"
        ["ios/ios_backup"]="https://github.com/richinfante/iosbackup"
        ["ios/ios_forensic"]="https://github.com/ydkhatri/MacForensics"
        ["ios/ios_inject"]="https://github.com/kpwn/inject"
        ["ios/ios_pentest"]="https://github.com/ivRodriguezCA/RE-iOS-Apps"
        ["ios/ios_audit"]="https://github.com/nabla-c0d3/ios-ssl-kill-switch"
        ["ios/ios_exploit"]="https://github.com/Siguza/ios-resources"
        ["ios/ios_tools"]="https://github.com/dmayer/idb"
        ["ios/ios_security"]="https://github.com/ashishb/osx-and-ios-security-awesome"

        # =====================
        # IOT HACKING TOOLS
        # =====================
        ["iot/firmwalker"]="https://github.com/craigz28/firmwalker"
        ["iot/binwalk"]="https://github.com/ReFirmLabs/binwalk"
        ["iot/firmadyne"]="https://github.com/firmadyne/firmadyne"
        ["iot/firmware-analysis-toolkit"]="https://github.com/attify/firmware-analysis-toolkit"
        ["iot/ghidra"]="https://github.com/NationalSecurityAgency/ghidra"
        ["iot/radare2"]="https://github.com/radareorg/radare2"
        ["iot/rizin"]="https://github.com/rizinorg/rizin"
        ["iot/cutter"]="https://github.com/rizinorg/cutter"
        ["iot/jadx"]="https://github.com/skylot/jadx"
        ["iot/apktool"]="https://github.com/iBotPeaches/Apktool"
        ["iot/androguard"]="https://github.com/androguard/androguard"
        ["iot/ida_pro"]="https://github.com/idapython/bin"
        ["iot/ghidra_scripts"]="https://github.com/ghidraninja/ghidra_scripts"
        ["iot/iot_security_toolkit"]="https://github.com/V33RU/IoTSecurity101"
        ["iot/iot_hacking"]="https://github.com/nebgnahz/awesome-iot-hacks"
        ["iot/iot_attack_surface"]="https://github.com/adi0x90/attifyos"
        ["iot/iot_exploit"]="https://github.com/exploitagency/github-iot-exploits"
        ["iot/iot_tools"]="https://github.com/scriptingxss/awesome-iot-security"
        ["iot/iot_pentest"]="https://github.com/IoT-PTv/IoT-PT"
        ["iot/iot_security"]="https://github.com/V33RU/IoTSecurity101"

        # =====================
        # SOCIAL ENGINEERING TOOLS
        # =====================
        ["social/setoolkit"]="https://github.com/trustedsec/social-engineer-toolkit"
        ["social/gophish"]="https://github.com/gophish/gophish"
        ["social/evilginx2"]="https://github.com/kgretzky/evilginx2"
        ["social/king-phisher"]="https://github.com/securestate/king-phisher"
        ["social/blackeye"]="https://github.com/thelinuxchoice/blackeye"
        ["social/zphisher"]="https://github.com/htr-tech/zphisher"
        ["social/hidden-eye"]="https://github.com/DarkSecDevelopers/HiddenEye"
        ["social/socialfish"]="https://github.com/UndeadSec/SocialFish"
        ["social/weeman"]="https://github.com/evait-security/weeman"
        ["social/lockphish"]="https://github.com/jaykali/lockphish"
        ["social/nexphisher"]="https://github.com/htr-tech/nexphisher"
        ["social/shellphish"]="https://github.com/thelinuxchoice/shellphish"
        ["social/artemis"]="https://github.com/saeeddhqan/artemis"
        ["social/eviltwin"]="https://github.com/s0lst1c3/eviltwin"
        ["social/credphish"]="https://github.com/tatanus/credphish"
        ["social/phishcatch"]="https://github.com/redcode-labs/PhishCatcher"
        ["social/phishbot"]="https://github.com/cybercdh/phishbot"
        ["social/phishx"]="https://github.com/rezaaksa/PhishX"
        ["social/phishytics"]="https://github.com/machine-reasoning-unc/Phishytics"
        ["social/phishdetect"]="https://github.com/phishdetect/phishdetect"

        # =====================
        # AV EVASION TOOLS
        # =====================
        ["evasion/scarecrow"]="https://github.com/optiv/ScareCrow"
        ["evasion/donut"]="https://github.com/TheWover/donut"
        ["evasion/pezor"]="https://github.com/phra/PEzor"
        ["evasion/avet"]="https://github.com/govolution/avet"
        ["evasion/greatsuspender"]="https://github.com/greatsuspender/thegreatsuspender"
        ["evasion/avsignseek"]="https://github.com/0xspade/AVSignSeek"
        ["evasion/defcon27"]="https://github.com/paranoidninja/O365-Doppelganger"
        ["evasion/unicorn"]="https://github.com/trustedsec/unicorn"
        ["evasion/veil"]="https://github.com/Veil-Framework/Veil"
        ["evasion/avcleaner"]="https://github.com/scrt/avcleaner"
        ["evasion/morph"]="https://github.com/codingplanets/Morph"
        ["evasion/hyperion"]="https://github.com/nullsecuritynet/tools"
        ["evasion/shellter"]="https://github.com/ParrotSec/shellter"
        ["evasion/avpass"]="https://github.com/denandz/AVPass"
        ["evasion/gadgettojscript"]="https://github.com/med0x2e/GadgetToJScript"
        ["evasion/pecloak"]="https://github.com/v-p-b/pecloak.py"
        ["evasion/pe_to_shellcode"]="https://github.com/hasherezade/pe_to_shellcode"
        ["evasion/peunion"]="https://github.com/peunion/peunion"
        ["evasion/pe_backdoor"]="https://github.com/secretsquirrel/the-backdoor-factory"
        ["evasion/pe_inject"]="https://github.com/peinject/peinjector"

        # =====================
        # PRIVILEGE ESCALATION TOOLS
        # =====================
        ["privesc/linpeas"]="https://github.com/carlospolop/PEASS-ng"
        ["privesc/winpeas"]="https://github.com/carlospolop/PEASS-ng"
        ["privesc/linuxprivchecker"]="https://github.com/sleventyeleven/linuxprivchecker"
        ["privesc/windowsprivchecker"]="https://github.com/pentestmonkey/windows-privesc-check"
        ["privesc/seatbelt"]="https://github.com/GhostPack/Seatbelt"
        ["privesc/sherlock"]="https://github.com/rasta-mouse/Sherlock"
        ["privesc/watson"]="https://github.com/rasta-mouse/Watson"
        ["privesc/gtfobins"]="https://github.com/GTFOBins/GTFOBins.github.io"
        ["privesc/lolbas"]="https://github.com/LOLBAS-Project/LOLBAS"
        ["privesc/linux-exploit-suggester"]="https://github.com/mzet-/linux-exploit-suggester"
        ["privesc/windows-exploit-suggester"]="https://github.com/AonCyberLabs/Windows-Exploit-Suggester"
        ["privesc/beRoot"]="https://github.com/AlessandroZ/BeRoot"
        ["privesc/privilege-escalation-awesome-scripts"]="https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite"
        ["privesc/pspy"]="https://github.com/DominicBreuker/pspy"
        ["privesc/linux-smart-enumeration"]="https://github.com/diego-treitos/linux-smart-enumeration"
        ["privesc/winprivcheck"]="https://github.com/itm4n/PrivescCheck"
        ["privesc/linux-kernel-exploits"]="https://github.com/SecWiki/linux-kernel-exploits"
        ["privesc/windows-kernel-exploits"]="https://github.com/SecWiki/windows-kernel-exploits"
        ["privesc/auto_linux_privesc"]="https://github.com/NullArray/AutoRoot"
        ["privesc/auto_win_privesc"]="https://github.com/51x/WHP"

        # =====================
        # REPORTING TOOLS
        # =====================
        ["reporting/dradis"]="https://github.com/dradis/dradis-ce"
        ["reporting/serpico"]="https://github.com/SerpicoProject/Serpico"
        ["reporting/pwndoc"]="https://github.com/pwndoc/pwndoc"
        ["reporting/redoc"]="https://github.com/nccgroup/redsnarf"
        ["reporting/ghostwriter"]="https://github.com/GhostManager/Ghostwriter"
        ["reporting/faraday"]="https://github.com/infobyte/faraday"
        ["reporting/pentest_reporting"]="https://github.com/juliocesarfort/public-pentesting-reports"
        ["reporting/reportgen"]="https://github.com/1N3/BlackWidow"
        ["reporting/auto_report"]="https://github.com/vandavey/DotDotPwn"
        ["reporting/redteam_report"]="https://github.com/magoo/redteam-plan"
        ["reporting/pentest_templates"]="https://github.com/rmusser01/Infosec_Reference"
        ["reporting/security_reporting"]="https://github.com/OWASP/OWASP-Testing-Guide-v4"
        ["reporting/vuln_report"]="https://github.com/juliocesarfort/public-pentesting-reports"
        ["reporting/executive_summary"]="https://github.com/rmusser01/Infosec_Reference"
        ["reporting/findings_database"]="https://github.com/OWASP/CheatSheetSeries"
        ["reporting/assessment_templates"]="https://github.com/trustedsec/ptf"
        ["reporting/redteam_templates"]="https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki"
        ["reporting/pentest_guide"]="https://github.com/OWASP/OWASP-Testing-Guide-v4"
        ["reporting/security_assessment"]="https://github.com/juliocesarfort/public-pentesting-reports"

        # =====================
        # MISCELLANEOUS TOOLS
        # =====================
        ["misc/peass"]="https://github.com/carlospolop/PEASS-ng"
        ["misc/seclists"]="https://github.com/danielmiessler/SecLists"
        ["misc/wordlists"]="https://github.com/kkrypt0nn/Wordlists"
        ["misc/payloadsallthethings"]="https://github.com/swisskyrepo/PayloadsAllTheThings"
        ["misc/cheatsheets"]="https://github.com/OWASP/CheatSheetSeries"
        ["misc/hacking_tools"]="https://github.com/danielmiessler/SecLists"
        ["misc/redteam_tools"]="https://github.com/infosecn1nja/Red-Teaming-Toolkit"
        ["misc/pentest_tools"]="https://github.com/enaqx/awesome-pentest"
        ["misc/security_tools"]="https://github.com/alphaSeclab/awesome-rat"
        ["misc/exploit_development"]="https://github.com/FabioBaroni/awesome-exploit-development"
        ["misc/reverse_engineering"]="https://github.com/alphaSeclab/awesome-reverse-engineering"
        ["misc/malware_analysis"]="https://github.com/rshipp/awesome-malware-analysis"
        ["misc/forensics"]="https://github.com/cugu/awesome-forensics"
        ["misc/incident_response"]="https://github.com/meirwah/awesome-incident-response"
        ["misc/security_cheatsheets"]="https://github.com/andrewjkerr/security-cheatsheets"
        ["misc/redteam_cheatsheets"]="https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki"
        ["misc/blue_team"]="https://github.com/fabacab/awesome-cybersecurity-blueteam"
        ["misc/security_research"]="https://github.com/0x4D31/awesome-threat-detection"
        ["misc/cybersecurity"]="https://github.com/forter/security-101-for-saas-startups"
    )
    
# ==============================================
# Comprehensive Offensive Security Tool Database
# ==============================================

# Tool categories with descriptions
    declare -A CATEGORIES=(
    ["recon"]="Reconnaissance Tools"
    ["scanning"]="Scanning & Enumeration"
    ["vulnerability"]="Vulnerability Analysis"
    ["exploitation"]="Exploitation Tools"
    ["postexp"]="Post Exploitation"
    ["credential"]="Credential Access"
    ["web"]="Web Application Testing"
    ["network"]="Network Pentesting"
    ["wireless"]="Wireless Testing"
    ["redteam"]="Red Teaming"
    ["osint"]="OSINT Tools"
    ["android"]="Android Security"
    ["ios"]="iOS Security"
    ["iot"]="IoT Hacking"
    ["social"]="Social Engineering"
    ["evasion"]="AV Evasion"
    ["privesc"]="Privilege Escalation"
    ["reporting"]="Reporting Tools"
    ["misc"]="Miscellaneous"
    )

    local total_tools=${#TOOLS[@]}
    local installed=0
    local failed=0
    
    status_msg "info" "Starting tool installation..."
    echo ""
    
    # Initialize results array
    for tool_path in "${!TOOLS[@]}"; do
        local tool="${tool_path#*/}"
        INSTALL_RESULTS["${tool}"]="pending"
    done
    
    # Install tools in parallel
    parallel_install_manager TOOLS
    
    # Count results
    for result in "${INSTALL_RESULTS[@]}"; do
        case "${result}" in
            "success") ((installed++)) ;;
            "failed") ((failed++)) ;;
        esac
    done
    
    # Summary
    status_msg "info" "Installation Summary:"
    echo -e "${GREEN}✔ Successfully installed: ${installed} tools${NC}"
    echo -e "${RED}✖ Failed: ${failed} tools${NC}"
    echo -e "${YELLOW}Total processed: ${total_tools} tools${NC}"
    echo ""
    
    # Show top 5 longest installations
    if [[ ${#INSTALL_TIMES[@]} -gt 0 ]]; then
        status_msg "info" "Longest installations:"
        for tool in "${!INSTALL_TIMES[@]}"; do
            echo "${tool}: ${INSTALL_TIMES[$tool]}s"
        done | sort -rnk2 | head -5
    fi
    
    status_msg "info" "Detailed log available at: ${LOG_FILE}"
    
    local end_time=$(date +%s)
    local total_duration=$((end_time - START_TIME))
    status_msg "success" "Installation completed in ${total_duration} seconds!"
}

# Cleanup function
cleanup() {
    if [[ -f "${LOCK_FILE}" ]]; then
        rm -f "${LOCK_FILE}"
    fi
}

# Main function
main() {
    trap cleanup EXIT INT TERM
    
    setup_logging
    header
    
    # Check for lock file
    if [[ -f "${LOCK_FILE}" ]]; then
        status_msg "error" "Another installation is running or crashed"
        status_msg "info" "If this is an error, remove: ${LOCK_FILE}"
        exit 1
    fi
    
    touch "${LOCK_FILE}"
    
    # Get GitHub credentials once at start
    get_github_credentials
    
    if ! check_system; then
        exit 1
    fi
    
    if ! setup_environment; then
        exit 1
    fi
    
    install_tools
    
    echo -e "\n${GREEN}Offensive security tools installed in: ${TOOLS_DIR}${NC}"
    echo -e "${BLUE}Add this to your shell rc file if not already present:${NC}"
    echo -e "${YELLOW}export PATH=\"${TOOLS_DIR}:\$PATH\"${NC}"
    echo -e "${BLUE}=============================================${NC}\n"
}

# Execute main function
main "$@"