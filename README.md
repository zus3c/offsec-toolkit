# offsec-toolkit
A powerful, automated script that installs and configures 300+ offensive security tools across 20+ categories (recon, exploitation, post-exploitation, red teaming, etc.). Features parallel installations, GitHub API integration, dependency management, and isolated Python environments for clean tool setups.

# Offensive Security Toolkit Installer

![offsec-toolkit](https://github.com/user-attachments/assets/56fbdc33-753f-44df-8923-7ab5d84a0fa7)

A comprehensive, automated installer for offensive security tools with parallel installation capabilities, credential management, and robust error handling.

## Features

- **Automated Tool Installation**: 300+ security tools organized by category
- **Parallel Installations**: Up to 5 concurrent installations (configurable)
- **Credential Management**: GitHub credentials stored securely for authenticated access
- **Virtual Environments**: Automatic Python virtual environment creation
- **Comprehensive Logging**: Detailed installation logs with timestamps
- **System Checks**: Pre-installation dependency and resource verification
- **Error Handling**: Graceful failure and continuation on errors
- **Progress Tracking**: Real-time progress with time estimates

## Categories Supported

| Category              |  Description                          | Example Tools                     |
|-----------------------|--------------------------------------|-----------------------------------|
| Reconnaissance        | Information gathering                | Amass, Sublist3r, theHarvester    |
| Vulnerability Analysis| Vulnerability scanners               | Nessus, OpenVAS, Trivy            |
| Exploitation          | Exploit frameworks                   | Metasploit, SQLMap, CrackMapExec  |
| Post-Exploitation     | Post-exploitation tools              | BloodHound, Mimikatz, Sliver      |
| Credential Access     | Password cracking                    | Hashcat, John, Hydra              |
| Web Testing           | Web application tools                | Burp Suite, ZAP, Nuclei           |
| Red Teaming           | Red team infrastructure              | Cobalt Strike, Mythic, Caldera    |

## Prerequisites

- Linux/macOS (Windows via WSL2)
- Bash 4.0+
- Python 3.6+
- Git
- curl/wget
- 10GB+ free disk space

## Installation

1. Download the offsec-toolkit:
```bash
curl -L -o offsec-toolkit.sh https://raw.githubusercontent.com/offsec-toolkit/offsec-toolkit.sh
chmod +x offsec-toolkit.sh
```
## GitHub Token Requirements

- **Create a token with:**
- **No special permissions required (access public repos only)**
- **Token can be generated at:** https://github.com/settings/tokens
- **The token will be stored encrypted at:** `~/.offsec_github_creds`

## Usage

- **Basic Usage**
```bash
./offsec-toolkit.sh
```

- **Custom Installation Directory**

```bash
export TOOLS_DIR="/custom/path" && ./offsec-toolkit.sh
```

-**Max Parallel Installations**

```bash
export MAX_PARALLEL_INSTALLS=3 && ./offsec-toolkit.sh
```

- **Skip Credential Prompt**

```bash
GITHUB_USER="yourusername" GITHUB_TOKEN="yourtoken" ./offsec-toolkit.sh
```

## Automation Flow
- **System Checks**

Verify dependencies
Check disk space
Test internet connectivity

- **Environment Setup**

Create tool directories
Set up virtual environments
Configure PATH

- **Tool Installation**

Parallel downloads
Dependency resolution
Custom install scripts

- **Reporting**

Success/failure summary
Installation times
Log file generation

- **Error Handling**

The script handles:
Failed downloads
Missing dependencies
Authentication errors
Network issues
Disk space errors
Errors are logged to: `~/Tools/install.log`

## Technical Specifications
|Component	            |Details
|-----------------------|--------------------------------------|
|Language	            |Bash 4.0+
|Configuration	        |Environment variables
|Credential Storage	    |Encrypted local file
|Parallel Processing	|Background jobs with PID tracking
|Logging	            |Tee to console and file
|Exit Codes	            |0 (Success), 1-255 (Error codes)

## Sample Output


## Troubleshooting

- **Common Issues:**

- **Permission denied:**

```bash
chmod +x offsec-toolkit.sh
```

- **Unexpected end of file:**

```bash
dos2unix offsec-toolkit.sh
```

- **Missing dependencies:**

```bash
sudo apt install git curl python3 pip3
```

- **View logs:**

```bash
cat ~/Tools/install.log
```

## License
`MIT License - See LICENSE for details.`

## Author
`Zubair Usman (Mr.Pop3y3)`
`GitHub: @zus3c`
`Twitter: @zus3cu`
`LinkedIn: @zus3c`
`WhatsApp channel: https://whatsapp.com/channel/0029VahEpDoGZNCjNV0vXF1B`
