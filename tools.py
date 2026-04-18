import subprocess
import json
import re
import logging
import threading # Added for tool concurrency control
import sqlite3  # Added for relational database support
from langchain_core.tools import tool
import os
from tqdm import tqdm
from typing import Union, List

logger = logging.getLogger(__name__)

DB_PATH = "recon.db"  # Changed from pentest_db.json
OUTPUT_DIR = "."
SKIP_CURRENT_TASK = False
FEROX_LOCK = threading.Lock()

# Authorised target set — populated by hacksmarter.py before scanning starts.
_ALLOWED_SCOPE: set = set()


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------

def set_allowed_scope(targets: list):
    """Register authorised targets. Must be called before any scan begins."""
    global _ALLOWED_SCOPE
    _ALLOWED_SCOPE = set(targets)
    logger.info("Scope locked to: %s", _ALLOWED_SCOPE)


def _assert_in_scope(target: str):
    """
    Raise ValueError when *target* is outside the allowed scope.
    Strips protocol/port, then checks suffix match so sub-domains of an
    in-scope root domain are also permitted.
    No-op if the scope set is empty (graceful during startup / tests).
    """
    if not _ALLOWED_SCOPE:
        return
    bare = re.sub(r"^https?://", "", target).split(":")[0].split("/")[0]
    for allowed in _ALLOWED_SCOPE:
        allowed_bare = re.sub(r"^https?://", "", allowed).split(":")[0].split("/")[0]
        if bare == allowed_bare or bare.endswith("." + allowed_bare):
            return
    raise ValueError(
        f"OUT-OF-SCOPE target blocked: '{target}'. Allowed: {_ALLOWED_SCOPE}"
    )


# ---------------------------------------------------------------------------
# Credential scrubbing
# ---------------------------------------------------------------------------

_SENSITIVE_ENV_KEYS = frozenset({
    "GOOGLE_API_KEY",
    "WPSCAN_API_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "DEHASHED_API_KEY",
    "DEHASHED_EMAIL",
})


def _clean_env() -> dict:
    """Return a subprocess environment with all known secret keys removed."""
    env = os.environ.copy()
    for key in _SENSITIVE_ENV_KEYS:
        env.pop(key, None)
    return env


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def init_db():
    """Initializes the SQLite database with the required schema."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Schema matching our previous JSON keys
    c.execute("CREATE TABLE IF NOT EXISTS subdomains (domain TEXT PRIMARY KEY)")
    c.execute(
        "CREATE TABLE IF NOT EXISTS open_ports "
        "(target TEXT, port TEXT, UNIQUE(target, port))"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS vulnerabilities "
        "(target TEXT, template_id TEXT, severity TEXT, description TEXT, poc TEXT, "
        "UNIQUE(target, template_id))"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS interesting_files "
        "(target TEXT, url TEXT, status INTEGER, comment TEXT, UNIQUE(target, url))"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS leaked_credentials "
        "(domain TEXT, email TEXT, username TEXT, password TEXT, hashed_password TEXT, "
        "source TEXT, UNIQUE(domain, email, password))"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS tool_runs "
        "(tool_name TEXT, target TEXT, UNIQUE(tool_name, target))"
    )
    conn.commit()
    conn.close()

def set_output_dir(path: str):
    """Sets the global output directory and updates DB_PATH."""
    global OUTPUT_DIR, DB_PATH
    OUTPUT_DIR = path
    DB_PATH = os.path.join(path, "recon.db")
    init_db()  # Initialize the DB file in the new folder

def update_db(key: str, new_data: list):
    """Updates the SQLite database with new findings based on the provided key."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        if key == "subdomains":
            for domain in new_data:
                c.execute("INSERT OR IGNORE INTO subdomains (domain) VALUES (?)", (domain,))
        elif key == "open_ports":
            for port_data in new_data:
                c.execute("INSERT OR IGNORE INTO open_ports (target, port) VALUES (?, ?)", 
                         (port_data.get("target"), port_data.get("port")))
        elif key == "vulnerabilities":
            for v in new_data:
                c.execute(
                    "INSERT OR IGNORE INTO vulnerabilities "
                    "(target, template_id, severity, description, poc) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        v.get("target"),
                        v.get("template"),
                        v.get("severity"),
                        v.get("description"),
                        v.get("poc", ""),
                    ),
                )
        elif key == "leaked_credentials":
            for item in new_data:
                c.execute(
                    "INSERT OR IGNORE INTO leaked_credentials "
                    "(domain, email, username, password, hashed_password, source) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        item.get("domain", ""),
                        item.get("email", ""),
                        item.get("username", ""),
                        item.get("password", ""),
                        item.get("hashed_password", ""),
                        item.get("source", ""),
                    ),
                )
        elif key == "interesting_files":
            for f in new_data:
                c.execute("INSERT OR IGNORE INTO interesting_files (target, url, comment) VALUES (?, ?, ?)",
                         (f.get("target"), f.get("url"), f.get("comment", "")))
        
        conn.commit()
    except Exception as e:
        print(f"[!] SQLite update_db Error ({key}): {e}")
    finally:
        conn.close()
    return new_data

def is_already_run(tool_name: str, target: str) -> bool:
    """Checks if a tool has already been run against a target in the SQLite DB."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT 1 FROM tool_runs WHERE tool_name = ? AND target = ?", (tool_name, target))
    result = c.fetchone()
    conn.close()
    return result is not None

def mark_as_run(tool_name: str, target: str):
    """Marks a tool as having been run against a target in the SQLite DB."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT OR IGNORE INTO tool_runs (tool_name, target) VALUES (?, ?)", (tool_name, target))
        conn.commit()
    except Exception as e:
        print(f"[!] SQLite mark_as_run Error: {e}")
    finally:
        conn.close()

def filter_live_targets_httpx(targets: list) -> list:
    """
    Takes a list of raw URLs/Domains, pipes them into httpx, 
    and returns only the ones that respond with a live web server.
    """
    print(f"[*] Probing {len(targets)} potential targets with httpx...")
    if not targets:
        return []
        
    try:
        input_data = "\n".join(targets)
        
        # Added a 2-minute timeout to prevent potential hangs
        try:
            result = subprocess.run(
                ['httpx-toolkit', '-silent', '-nc'], # Switched back to toolkit alias
                input=input_data,
                capture_output=True, text=True,
                timeout=120
            )
        except subprocess.TimeoutExpired:
            print("[!] httpx probe timed out after 120 seconds. Moving on.")
            return []
            
        output = result.stdout.strip()
        print(f"[*] httpx probe finished. Verified {len(output.split('\n')) if output else 0} live targets.")
        
        # If output is totally empty, it means 0 live hosts
        if not output:
            if result.returncode != 0 and result.stderr:
                print(f"[!] httpx error output: {result.stderr.strip()}")
            return []
            
        # Parse the output into a clean list of verified URLs
        live_urls = [line.strip() for line in output.split('\n') if line.strip()]
        return live_urls
        
    except FileNotFoundError:
        logger.warning("httpx binary not found. Skipping live-host filter — install httpx-toolkit and ensure it is in your PATH.")
        return []
    except Exception as e:
        logger.error("Unexpected httpx error: %s. Skipping live-host filter to avoid scanning unverified targets.", e)
        return []

@tool
def run_httpx_tool(targets: Union[str, List[str]]) -> List[str]:
    """
    Takes a single target or a list of targets (URLs/domains), 
    probes them with httpx, and returns a list of only the live web servers.
    Use this to verify if a target is alive before running dirsearch or wpscan.
    """
    target_list = [targets] if isinstance(targets, str) else targets
    return filter_live_targets_httpx(target_list)

@tool
def format_scope_tool(scope: str) -> dict:
    """
    Analyzes the user-provided scope and categorizes it.
    Args: scope (str): The raw input (e.g., '192.168.1.1', 'example.com', '10.0.0.0/24')
    """
    # Basic regex for IP vs Domain (You can expand this for CIDR)
    is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", scope)
    
    return {
        "original_scope": scope,
        "type": "IP" if is_ip else "Domain",
        "ready_for_nmap": bool(is_ip),
        "ready_for_subfinder": not bool(is_ip)
    }

@tool
def run_subfinder_tool(domain: str) -> str:
    """
    Finds subdomains for a given target domain using subfinder.
    Returns a success message with the count of subdomains found. 
    This list should be considered the exhaustive source of truth for subdomains.
    """
    if is_already_run("subfinder", domain):
        return f"[!] Skipping subfinder for {domain} - Results already in database."
        
    global SKIP_CURRENT_TASK
    print(f"[*] Recon Agent executing subfinder on {domain}...")
    try:
        result = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True)
        
        if SKIP_CURRENT_TASK:
            SKIP_CURRENT_TASK = False
            mark_as_run("subfinder", domain)
            print(f"\n[!] Subfinder scan for {domain} skipped (User Interrupt).")
            return f"Subfinder scan for {domain} was skipped by user."
            
    except KeyboardInterrupt:
        SKIP_CURRENT_TASK = False
        mark_as_run("subfinder", domain)
        print(f"\n[!] Subfinder scan for {domain} interrupted by user. Skipping.")
        return f"Subfinder scan for {domain} was skipped by user."
    except subprocess.CalledProcessError as e:
        return f"Subfinder command failed. Error: {e.stderr}"
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}"
    
    output = result.stdout.strip()
    
    if not output:
        mark_as_run("subfinder", domain)
        return f"Subfinder scan completed for {domain}. Result: 0 subdomains discovered. This is a valid result."

    # Parse plain text output (one subdomain per line)
    subdomains = [line.strip() for line in output.split('\n') if line.strip()]
            
    update_db("subdomains", subdomains)
    mark_as_run("subfinder", domain)
    return f"Subfinder scan successful for {domain}. Found {len(subdomains)} subdomains: {', '.join(subdomains)}"

@tool
def run_nmap_tool(target: str) -> list:
    """
    Runs a fast nmap port scan against a target IP or domain.
    Args: target (str): The IP or domain to scan.
    """
    if is_already_run("nmap", target):
        return f"[!] Skipping nmap for {target} - Results already in database."

    global SKIP_CURRENT_TASK
    try:
        print(f"[*] Recon Agent executing nmap on {target}...")
        result = subprocess.run(['nmap', '-F', '-T4', '--open', '-oG', '-', target], capture_output=True, text=True)
        
        if SKIP_CURRENT_TASK:
            SKIP_CURRENT_TASK = False
            mark_as_run("nmap", target)
            print(f"\n[!] Nmap scan for {target} skipped (User Interrupt).")
            return f"Nmap scan for {target} was skipped by user."
            
    except KeyboardInterrupt:
        SKIP_CURRENT_TASK = False
        mark_as_run("nmap", target)
        print(f"\n[!] Nmap scan for {target} interrupted by user. Skipping.")
        return f"Nmap scan for {target} was skipped by user."
    except subprocess.CalledProcessError as e:
        return [{"error": f"Nmap failed: {e.stderr}"}]

    open_ports = []
    for line in result.stdout.split('\n'):
        if "Ports:" in line:
            # Extract the port numbers (Grepable output parsing)
            ports_section = line.split("Ports: ")[1]
            for port_data in ports_section.split(', '):
                if "/open/" in port_data:
                    port_num = port_data.split('/')[0].strip()
                    open_ports.append({"target": target, "port": port_num})
                        
    update_db("open_ports", open_ports)
    mark_as_run("nmap", target)
    ports_list = [p['port'] for p in open_ports]
    return f"Nmap successful for {target}. Found {len(open_ports)} open ports: {', '.join(ports_list)}"

@tool
def run_nuclei_tool(targets: list, verbose: bool = False) -> str:
    """
    Runs Nuclei against a list of targets and safely parses the JSON output into the DB.
    Args: 
        targets (list): A list of target URLs to scan.
        verbose (bool): If True, shows raw Nuclei output in the terminal.
    """
    global SKIP_CURRENT_TASK
    out_file = os.path.join(OUTPUT_DIR, 'nuclei_out.json')
    
    # 1. Clean up old output files to prevent cross-contamination
    if os.path.exists(out_file):
        os.remove(out_file)

    if not targets:
        return "No targets provided to Nuclei."

    print(f"[*] Recon Agent executing Nuclei on {len(targets)} targets...")
    try:
        # Run optimized nuclei command
        input_data = "\n".join(targets)
        
        cmd = [
            'nuclei', 
            '-je', out_file, 
            '-severity', 'low,medium,high,critical',
            '-exclude-tags', 'dos,fuzz',  
            '-rl', '5',                   
            '-c', '5',                    
            '-timeout', '10',             
            '-retries', '0',              
            '-mhe', '3'      
        ]
        
        if verbose:
            cmd.append("-v")
            
        # Add stats for the progress bar
        cmd.extend(["-stats", "-stats-json", "-stats-interval", "1"])
            
        # Scrub GOOGLE_API_KEY
        nuclei_env = os.environ.copy()
        if "GOOGLE_API_KEY" in nuclei_env:
            del nuclei_env["GOOGLE_API_KEY"]
            
        # Execute with real-time feedback
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=nuclei_env
        )
        
        # Write targets to stdin
        if input_data:
            process.stdin.write(input_data)
            process.stdin.close()
        
        pbar = None
        try:
            for line in iter(process.stderr.readline, ''):
                if verbose:
                    print(line.strip())
                
                try:
                    if "{" in line and "}" in line:
                        stats = json.loads(line[line.find("{"):line.rfind("}")+1])
                        total_reqs = int(stats.get("total", 0))
                        curr_reqs = int(stats.get("requests", 0))
                        
                        if pbar is None and total_reqs > 0:
                            pbar = tqdm(total=total_reqs, desc="[*] Nuclei Progress", unit="req", leave=False)
                        
                        if pbar:
                            pbar.n = curr_reqs
                            pbar.refresh()
                except (json.JSONDecodeError, ValueError):
                    continue
        except KeyboardInterrupt:
            process.terminate()
            SKIP_CURRENT_TASK = False
            for t in targets:
                mark_as_run("nuclei", t)
            if pbar:
                pbar.close()
            print("\n[!] Nuclei scan interrupted by user. Skipping to next phase.")
            return "Nuclei scan was manually skipped. Moving to next verification phase."
                
        process.wait()
        if pbar:
            pbar.close()
            
        if SKIP_CURRENT_TASK:
            SKIP_CURRENT_TASK = False
            for t in targets:
                mark_as_run("nuclei", t)
            print("\n[!] Nuclei scan skipped (User Interrupt).")
            return "Nuclei scan was manually skipped."
        
        findings = []
        if os.path.exists(out_file):
            with open(out_file, 'r') as f:
                try:
                    parsed_data = json.load(f)
                    items = parsed_data if isinstance(parsed_data, list) else [parsed_data]
                except json.JSONDecodeError:
                    f.seek(0)
                    items = [json.loads(line) for line in f if line.strip()]

                for item in items:
                    findings.append({
                        "template": item.get("template-id"),
                        "target": item.get("matched-at", "unknown"), 
                        "severity": item.get("info", {}).get("severity"),
                        "description": item.get("info", {}).get("name")
                    })
            
            if findings:
                update_db("vulnerabilities", findings)
                return f"Nuclei complete. Added {len(findings)} findings to DB."
        
        return "Nuclei finished with 0 findings."
        
    except Exception as e:
        print(f"[!] Critical Nuclei Parsing Error: {str(e)}")
        return f"Nuclei tool error: {str(e)}"

@tool
def run_nc_banner_grab(target: str, port: int, send_string: str = "") -> str:
    """
    Uses netcat (nc) to grab a service banner or send a custom string to a port.
    Useful for manual verification of non-HTTP services.
    """
    try:
        cmd = ["nc", "-vn", "-w", "2", str(target), str(port)]
        input_data = send_string + "\n"
        result = subprocess.run(cmd, input=input_data, capture_output=True, text=True)
        
        output = result.stdout if result.stdout else result.stderr
        return f"NC Output for {target}:{port}:\n{output}"
    except Exception as e:
        return f"NC Error: {str(e)}"

@tool
def run_ssh_audit(target: str, port: int = 22) -> str:
    """
    Runs ssh-audit to check for weak ciphers, algorithms, and vulnerabilities 
    like Terrapin (CVE-2023-48795).
    """
    try:
        result = subprocess.run(
            ['ssh-audit', '-p', str(port), target],
            capture_output=True, text=True
        )
        return f"SSH Audit Results for {target}:\n{result.stdout}"
    except Exception as e:
        return f"SSH Audit Error: {str(e)}"

@tool
def run_hydra_check(target: str, service: str, user: str, password: str, port: int = None) -> str:
    """
    Runs Hydra to verify if a specific username and password pair work on a service.
    Supported services: ssh, ftp, http-get, mysql, mssql, etc.
    """
    try:
        port_args = [f"-s", str(port)] if port else []
        cmd = ["hydra", "-l", user, "-p", password] + port_args + ["-f", f"{service}://{target}"]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if "1 of 1 target successfully completed" in result.stdout:
            return f"[!] SUCCESS: Credentials verified! {user}:{password} works on {service}."
        return f"[-] FAILURE: Credentials {user}:{password} were rejected."
        
    except Exception as e:
        return f"Hydra Error: {str(e)}"

@tool
def run_testssl_verification(target: str) -> str:
    """
    Runs testssl.sh for a deep dive into SSL/TLS vulnerabilities.
    Only use this if Nuclei flags a specific SSL issue.
    """
    try:
        result = subprocess.run(
            ['testssl.sh', '--quiet', '--severity', 'MEDIUM', target],
            capture_output=True, text=True
        )
        return f"TestSSL Results for {target}:\n{result.stdout}"
    except Exception as e:
        return f"TestSSL Error: {str(e)}"

@tool
def execute_curl_request(url: str, method: str = "GET", headers: dict = None, data: str = None) -> str:
    """
    Executes a custom HTTP request using curl to verify vulnerabilities.
    Args: 
        url (str): The target URL.
        method (str): HTTP method (GET, POST, etc.)
        headers (dict): Optional headers.
        data (str): Optional payload body.
    """
    cmd = ['curl', '-s', '-i', '-X', method, url]
    if headers:
        for k, v in headers.items():
            cmd.extend(['-H', f"{k}: {v}"])
    if data:
        cmd.extend(['-d', data])
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout[:2000] 
    except subprocess.TimeoutExpired:
        return "Error: Curl request timed out."
    except Exception as e:
        return f"Error: {str(e)}"

@tool
def run_wpscan_tool(target_url: str) -> str:
    """
    Runs WPScan against a target URL to check for WordPress installations, 
    vulnerabilities, and outdated plugins.
    Args: target_url (str): The URL to scan (e.g., http://example.com)
    """
    if is_already_run("wpscan", target_url):
        return f"[!] Skipping wpscan for {target_url} - Results already in database."

    print(f"[*] Recon Agent executing wpscan on {target_url}...")
    try:
        wpscan_token = os.environ.get("WPSCAN_API_TOKEN")
        token_args = ["--api-token", wpscan_token] if wpscan_token else []

        try:
            result = subprocess.run(
                ['wpscan', '--url', target_url, '--no-update', '--random-user-agent', '-e', 'vp,vt'] + token_args,
                capture_output=True, text=True
            )
        except KeyboardInterrupt:
            print("\n[!] WPScan interrupted by user. Skipping.")
            mark_as_run("wpscan", target_url)
            return "WPScan interrupted by user."
        
        if "missing database" in (result.stdout + result.stderr).lower():
            print("[!] WPScan database missing. Attempting update...")
            subprocess.run(['wpscan', '--update'], capture_output=True, text=True)
            try:
                result = subprocess.run(
                    ['wpscan', '--url', target_url, '--no-update', '--random-user-agent', '-e', 'vp,vt'],
                    capture_output=True, text=True
                )
            except KeyboardInterrupt:
                mark_as_run("wpscan", target_url)
                return "WPScan interrupted by user."
        
        output = result.stdout if result.stdout else result.stderr
        mark_as_run("wpscan", target_url)
        return f"WPScan Results for {target_url}:\n{output[:3000]}"
    except FileNotFoundError:
        return "[!] WPScan binary not found! Make sure it is installed and in your PATH."
    except Exception as e:
        return f"WPScan Error: {str(e)}"

@tool
def add_vulnerability_tool(target: str, template: str, severity: str, description: str, poc: str) -> str:
    """
    Manually adds a verified vulnerability to the database.
    Args:
        target (str): The target URL or host.
        template (str): A name or ID for the vulnerability (e.g., 'git-config-disclosure').
        severity (str): low, medium, high, or critical.
        description (str): A brief description of the finding.
        poc (str): A proof of concept (the command/output used to verify).
    """
    finding = {
        "template": template,
        "target": target,
        "severity": severity,
        "description": description,
        "poc": poc 
    }
    update_db("vulnerabilities", [finding])
    return f"Successfully added vulnerability '{template}' for {target} to the database."

@tool
def run_feroxbuster_tool(url: Union[str, List[str]], extensions: str = "php,html,js,txt", verbose: bool = False) -> str:
    """
    Performs directory and file discovery on a web server using feroxbuster.
    Args:
        url (Union[str, List[str]]): The target URL or a list of target URLs.
        extensions (str): Comma-separated list of extensions to check (default: php,html,js,txt).
        verbose (bool): If True, shows raw feroxbuster output in the terminal.
    """
    with FEROX_LOCK:
        global SKIP_CURRENT_TASK
        targets = [url] if isinstance(url, str) else url
        
        # Filter targets that were already run
        new_targets = [t for t in targets if not is_already_run("feroxbuster", t)]
        
        if not new_targets:
            return f"All {len(targets)} targets have already been scanned by feroxbuster."

        print(f"[*] Sequential Scan: Executing feroxbuster on {len(new_targets)} targets one by one...")
        all_findings = []
        
        for i, target in enumerate(new_targets):
            out_file = os.path.join(OUTPUT_DIR, f'feroxbuster_out_{i}.json')
                
            try:
                # Feroxbuster command for a single target
                cmd = [
                    'feroxbuster',
                    '-u', target,
                    '-t', '10', 
                    '-d', '2',
                    '--json',
                    '-o', out_file,
                    '-x', extensions,
                    '--no-state' 
                ]
                
                print(f"[*] [{i+1}/{len(new_targets)}] Deep Discovery: Exploring {target}")
                print(f"    - Feroxbuster is performing exhaustive directory brute-forcing.")
                print(f"    - This can take several minutes per target. Please stand by...")
                
                if not verbose:
                    cmd.append('--silent')
                    
                # Run feroxbuster
                try:
                    subprocess.run(cmd, capture_output=not verbose, text=True, check=False)
                except KeyboardInterrupt:
                    SKIP_CURRENT_TASK = False
                    mark_as_run("feroxbuster", target)
                    print(f"\n[!] User skip requested for {target}. Moving to next target...")
                    continue
                
                if SKIP_CURRENT_TASK:
                    SKIP_CURRENT_TASK = False
                    mark_as_run("feroxbuster", target)
                    print(f"\n[!] User skip requested for {target}. Moving to next target...")
                    continue
                
                # Parse output
                if os.path.exists(out_file):
                    with open(out_file, 'r') as f:
                        for line in f:
                            try:
                                finding = json.loads(line)
                                if finding.get("status") in [200, 204, 301, 302, 307, 403]:
                                    all_findings.append({
                                        "url": finding.get("url"),
                                        "status": finding.get("status"),
                                        "content_length": finding.get("content_length"),
                                        "target": target
                                    })
                            except json.JSONDecodeError:
                                continue
                                
                mark_as_run("feroxbuster", target)
                
            except Exception as e:
                print(f"[!] Error scanning {target} with feroxbuster: {e}")
                continue
                
        if all_findings:
            update_db("interesting_files", all_findings)
            return (
                f"Feroxbuster finished on {len(new_targets)} targets — "
                f"{len(all_findings)} interesting files found."
            )
        return f"Feroxbuster finished on {len(new_targets)} targets — 0 findings."


@tool
def run_dehashed_tool(domain: str) -> str:
    """
    Query the Dehashed API for leaked credentials associated with a domain.

    Requires DEHASHED_EMAIL and DEHASHED_API_KEY environment variables.
    Results (email, username, plaintext password, hashed password, source
    database) are stored in the leaked_credentials table and returned as a
    summary.  Only domain-scoped queries are made — no out-of-scope lookups.

    Args:
        domain: The target domain to search (e.g. 'example.com').
    """
    import urllib.request
    import urllib.parse
    import base64

    try:
        _assert_in_scope(domain)
    except ValueError as exc:
        return f"[SCOPE BLOCK] {exc}"

    if is_already_run("dehashed", domain):
        return f"[SKIP] Dehashed already queried for {domain}."

    dehashed_email = os.environ.get("DEHASHED_EMAIL", "").strip()
    dehashed_api_key = os.environ.get("DEHASHED_API_KEY", "").strip()

    if not dehashed_email or not dehashed_api_key:
        return (
            "[SKIP] Dehashed credentials not configured. "
            "Set DEHASHED_EMAIL and DEHASHED_API_KEY in your .env file."
        )

    logger.info("Querying Dehashed for domain: %s", domain)

    # Bare domain without protocol for the query
    bare_domain = re.sub(r"^https?://", "", domain).split("/")[0].split(":")[0]
    query = urllib.parse.quote(bare_domain)
    url = f"https://api.dehashed.com/search?query=domain%3A{query}&size=100"

    credentials_b64 = base64.b64encode(
        f"{dehashed_email}:{dehashed_api_key}".encode()
    ).decode()

    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Basic {credentials_b64}",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        mark_as_run("dehashed", domain)
        if exc.code == 401:
            return "[ERROR] Dehashed: invalid credentials (401). Check DEHASHED_EMAIL / DEHASHED_API_KEY."
        if exc.code == 302:
            return "[ERROR] Dehashed: subscription required or account issue (302)."
        return f"[ERROR] Dehashed HTTP {exc.code}: {exc.reason}"
    except urllib.error.URLError as exc:
        return f"[ERROR] Dehashed network error: {exc.reason}"
    except Exception as exc:
        return f"[ERROR] Dehashed unexpected error: {exc}"

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        mark_as_run("dehashed", domain)
        return f"[ERROR] Dehashed returned non-JSON response: {exc}"

    entries = data.get("entries") or []
    total = data.get("total", len(entries))

    if not entries:
        mark_as_run("dehashed", domain)
        return f"Dehashed: no leaked credentials found for {bare_domain}."

    credentials = []
    for entry in entries:
        credentials.append({
            "domain": bare_domain,
            "email": entry.get("email", ""),
            "username": entry.get("username", ""),
            "password": entry.get("password", ""),
            "hashed_password": entry.get("hashed_password", ""),
            "source": entry.get("database_name", ""),
        })

    update_db("leaked_credentials", credentials)
    mark_as_run("dehashed", domain)

    # Build a concise summary (avoid logging raw passwords at INFO level)
    with_plaintext = sum(1 for c in credentials if c.get("password"))
    with_hash = sum(1 for c in credentials if c.get("hashed_password"))

    logger.info(
        "Dehashed found %d entries for %s (%d plaintext, %d hashed).",
        len(credentials), bare_domain, with_plaintext, with_hash,
    )

    return (
        f"Dehashed results for {bare_domain}: {total} total records found "
        f"(showing {len(credentials)}). "
        f"{with_plaintext} have plaintext passwords, {with_hash} have hashed passwords. "
        f"All stored in leaked_credentials table. "
        f"Sample sources: {', '.join(set(c['source'] for c in credentials if c['source']))[:200]}"
    )
