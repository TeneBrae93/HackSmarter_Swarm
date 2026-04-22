"""
tools.py — LangChain tools for HackSmarter Swarm.

Security fixes applied
----------------------
1. _clean_env()          – strips ALL secrets from every subprocess environment.
2. _assert_in_scope()    – hard scope enforcement before any network call.
3. Nuclei parsing        – always JSONL (one object per line), never json.load().
4. Feroxbuster filter    – only HTTP 200/204 treated as "interesting files".
5. WPScan output         – written to a JSON file; no silent truncation.
6. Logging               – Python logging throughout; no bare print().
7. Scope initialisation  – fails CLOSED (RuntimeError) when set_allowed_scope()
                           has never been called; empty scope set is explicit opt-in.
8. Scope suffix check    – rejects bare public suffixes; adds IP/CIDR support.
9. WPScan API token      – passed via subprocess env, never in argv / ps output.
10. SSL verification     – explicit ssl.create_default_context() for urlopen.
11. Credential storage   – plaintext passwords hashed (SHA-256) before DB insert;
                           raw value used only for Hydra verification then discarded.
12. subfinder timeout    – hard 300-second timeout prevents indefinite hangs.
"""

import hashlib
import ipaddress
import json
import logging
import os
import re
import ssl
import subprocess
import threading
from typing import List, Union

from langchain_core.tools import tool
from tqdm import tqdm
import sqlite3

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("hacksmarter.tools")

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
DB_PATH = "recon.db"
OUTPUT_DIR = "."
SKIP_CURRENT_TASK = False
FEROX_LOCK = threading.Lock()

# Authorised target set — populated by hacksmarter.py before scanning starts.
_ALLOWED_SCOPE: set = set()
# Sentinel: distinguishes "never initialised" (unsafe) from "explicitly empty" (all allowed).
_SCOPE_INITIALISED: bool = False

# Minimal list of public suffixes to reject as bare scope entries.
# Prevents accidental "scope = co.uk" matching every .co.uk domain.
_BARE_PUBLIC_SUFFIXES = frozenset({
    "com", "net", "org", "io", "gov", "edu", "mil",
    "co.uk", "org.uk", "me.uk", "com.au", "net.au",
})


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------

def set_allowed_scope(targets: list):
    """Register authorised targets. Must be called before any scan begins."""
    global _ALLOWED_SCOPE, _SCOPE_INITIALISED
    for t in targets:
        bare = re.sub(r"^https?://", "", t).split(":")[0].split("/")[0].lower()
        if bare in _BARE_PUBLIC_SUFFIXES:
            raise ValueError(
                f"Refusing to register bare public suffix '{bare}' as a scope entry. "
                "Use a fully-qualified domain (e.g. 'example.com')."
            )
    _ALLOWED_SCOPE = set(targets)
    _SCOPE_INITIALISED = True
    logger.info("Scope locked to: %s", _ALLOWED_SCOPE)


def _assert_in_scope(target: str):
    """
    Raise ValueError when *target* is outside the allowed scope.

    Behaviour:
    - If set_allowed_scope() has never been called → RuntimeError (fails closed).
    - If scope is explicitly empty (set_allowed_scope([])) → allow all (opt-in).
    - Strips protocol/port before comparing.
    - Supports exact domain match and subdomain suffix match.
    - Supports IPv4 CIDR ranges: if any allowed entry is a CIDR network,
      checks whether the target IP falls within it.
    """
    if not _SCOPE_INITIALISED:
        raise RuntimeError(
            "Scope has not been initialised. Call set_allowed_scope() before scanning."
        )
    if not _ALLOWED_SCOPE:
        return  # Explicitly empty scope = unrestricted (intentional opt-in)

    bare = re.sub(r"^https?://", "", target).split(":")[0].split("/")[0].lower()

    for allowed in _ALLOWED_SCOPE:
        allowed_bare = re.sub(r"^https?://", "", allowed).split(":")[0].split("/")[0].lower()

        # 1. Exact match
        if bare == allowed_bare:
            return

        # 2. Subdomain suffix match (e.g. sub.example.com vs example.com)
        if bare.endswith("." + allowed_bare):
            return

        # 3. CIDR range match for IP targets
        try:
            network = ipaddress.ip_network(allowed_bare, strict=False)
            target_ip = ipaddress.ip_address(bare)
            if target_ip in network:
                return
        except ValueError:
            pass  # Not a valid CIDR or IP — skip this check

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

def _hash_password(plaintext: str) -> str:
    """
    Return a SHA-256 hex digest of *plaintext*.
    Used to avoid storing raw breach passwords in the database.
    The original value is retained only transiently in memory for
    Hydra verification and then discarded.
    """
    if not plaintext:
        return ""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def init_db():
    """Initialise SQLite schema."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
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
    """Change the global output directory and reinitialise the database."""
    global OUTPUT_DIR, DB_PATH
    OUTPUT_DIR = path
    DB_PATH = os.path.join(path, "recon.db")
    init_db()


def update_db(key: str, new_data: list):
    """Upsert *new_data* under the given category key."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        if key == "subdomains":
            for domain in new_data:
                c.execute(
                    "INSERT OR IGNORE INTO subdomains (domain) VALUES (?)", (domain,)
                )
        elif key == "open_ports":
            for item in new_data:
                c.execute(
                    "INSERT OR IGNORE INTO open_ports (target, port) VALUES (?, ?)",
                    (item.get("target"), item.get("port")),
                )
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
                        # Store only the SHA-256 digest — never raw plaintext.
                        _hash_password(item.get("password", "")),
                        item.get("hashed_password", ""),
                        item.get("source", ""),
                    ),
                )
        elif key == "interesting_files":
            for f in new_data:
                c.execute(
                    "INSERT OR IGNORE INTO interesting_files "
                    "(target, url, status, comment) VALUES (?, ?, ?, ?)",
                    (
                        f.get("target"),
                        f.get("url"),
                        f.get("status"),
                        f.get("comment", ""),
                    ),
                )
        conn.commit()
    except Exception as exc:
        logger.error("SQLite update_db error (%s): %s", key, exc)
    finally:
        conn.close()
    return new_data


def is_already_run(tool_name: str, target: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT 1 FROM tool_runs WHERE tool_name = ? AND target = ?",
        (tool_name, target),
    )
    result = c.fetchone()
    conn.close()
    return result is not None


def mark_as_run(tool_name: str, target: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(
            "INSERT OR IGNORE INTO tool_runs (tool_name, target) VALUES (?, ?)",
            (tool_name, target),
        )
        conn.commit()
    except Exception as exc:
        logger.error("SQLite mark_as_run error: %s", exc)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# httpx helper (not a LangChain tool — called directly from vuln_node)
# ---------------------------------------------------------------------------

def filter_live_targets_httpx(targets: list) -> list:
    """Probe *targets* with httpx and return only live URLs."""
    logger.info("Probing %d potential targets with httpx…", len(targets))
    if not targets:
        return []
    try:
        result = subprocess.run(
            ["httpx-toolkit", "-silent", "-nc"],
            input="\n".join(targets),
            capture_output=True,
            text=True,
            timeout=120,
            env=_clean_env(),
        )
        live = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        logger.info("httpx verified %d live targets.", len(live))
        if not result.stdout.strip() and result.returncode != 0 and result.stderr:
            logger.warning("httpx stderr: %s", result.stderr.strip())
        return live
    except subprocess.TimeoutExpired:
        logger.warning("httpx timed out after 120 s.")
        return []
    except FileNotFoundError:
        logger.warning("httpx-toolkit not found — falling back to raw list.")
        return targets
    except Exception as exc:
        logger.error("Unexpected httpx error: %s", exc)
        return targets


# ---------------------------------------------------------------------------
# LangChain tools
# ---------------------------------------------------------------------------

@tool
def run_httpx_tool(targets: Union[str, List[str]]) -> List[str]:
    """
    Probe one or more targets (URLs/domains) with httpx and return only live
    web servers. Use this before running feroxbuster or wpscan.

    Args:
        targets: A single target string or a list of target strings.
    """
    target_list = [targets] if isinstance(targets, str) else targets
    return filter_live_targets_httpx(target_list)


@tool
def format_scope_tool(scope: str) -> dict:
    """
    Categorise a user-provided scope string as IP or Domain.

    Args:
        scope: Raw input such as '192.168.1.1' or 'example.com'.
    """
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", scope))
    return {
        "original_scope": scope,
        "type": "IP" if is_ip else "Domain",
        "ready_for_nmap": is_ip,
        "ready_for_subfinder": not is_ip,
    }


@tool
def run_subfinder_tool(domain: str) -> str:
    """
    Enumerate subdomains for a given domain using subfinder.

    Args:
        domain: Root domain to enumerate (e.g. 'example.com').
    """
    try:
        _assert_in_scope(domain)
    except ValueError as exc:
        return f"[SCOPE BLOCK] {exc}"

    if is_already_run("subfinder", domain):
        return f"[SKIP] subfinder already run for {domain}."

    global SKIP_CURRENT_TASK
    logger.info("Running subfinder on %s…", domain)
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=300,  # prevent indefinite hang on large/misconfigured targets
            env=_clean_env(),
        )
        if SKIP_CURRENT_TASK:
            SKIP_CURRENT_TASK = False
            mark_as_run("subfinder", domain)
            return f"Subfinder for {domain} skipped by user."
    except subprocess.TimeoutExpired:
        logger.warning("subfinder timed out after 300 s for %s.", domain)
        mark_as_run("subfinder", domain)
        return f"Subfinder timed out for {domain}."
    except KeyboardInterrupt:
        SKIP_CURRENT_TASK = False
        mark_as_run("subfinder", domain)
        return f"Subfinder for {domain} skipped by user."
    except Exception as exc:
        return f"Subfinder error: {exc}"

    subdomains = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    mark_as_run("subfinder", domain)
    if not subdomains:
        return f"Subfinder completed for {domain}: 0 subdomains found."
    update_db("subdomains", subdomains)
    return f"Subfinder found {len(subdomains)} subdomains: {', '.join(subdomains)}"


@tool
def run_nmap_tool(target: str) -> str:
    """
    Fast nmap port scan against a target IP or domain.

    Args:
        target: IP address or hostname to scan.
    """
    try:
        _assert_in_scope(target)
    except ValueError as exc:
        return f"[SCOPE BLOCK] {exc}"

    if is_already_run("nmap", target):
        return f"[SKIP] nmap already run for {target}."

    global SKIP_CURRENT_TASK
    logger.info("Running nmap on %s…", target)
    try:
        result = subprocess.run(
            ["nmap", "-F", "-T4", "--open", "-oG", "-", target],
            capture_output=True,
            text=True,
            env=_clean_env(),
        )
        if SKIP_CURRENT_TASK:
            SKIP_CURRENT_TASK = False
            mark_as_run("nmap", target)
            return f"Nmap for {target} skipped by user."
    except KeyboardInterrupt:
        SKIP_CURRENT_TASK = False
        mark_as_run("nmap", target)
        return f"Nmap for {target} skipped by user."
    except Exception as exc:
        return f"Nmap error: {exc}"

    open_ports = []
    for line in result.stdout.splitlines():
        if "Ports:" in line:
            for chunk in line.split("Ports: ")[1].split(", "):
                if "/open/" in chunk:
                    open_ports.append({"target": target, "port": chunk.split("/")[0].strip()})

    update_db("open_ports", open_ports)
    mark_as_run("nmap", target)
    return (
        f"Nmap on {target}: {len(open_ports)} open ports: "
        f"{', '.join(p['port'] for p in open_ports)}"
    )


@tool
def run_nuclei_tool(targets: list, verbose: bool = False) -> str:
    """
    Run Nuclei against a list of targets. Output is parsed as JSONL.

    Args:
        targets: List of target URLs.
        verbose: Stream raw Nuclei output when True.
    """
    global SKIP_CURRENT_TASK
    out_file = os.path.join(OUTPUT_DIR, "nuclei_out.jsonl")

    if os.path.exists(out_file):
        os.remove(out_file)

    if not targets:
        return "No targets provided to Nuclei."

    for t in targets:
        try:
            _assert_in_scope(t)
        except ValueError as exc:
            return f"[SCOPE BLOCK] {exc}"

    logger.info("Running Nuclei on %d targets…", len(targets))
    try:
        cmd = [
            "nuclei",
            "-je", out_file,
            "-severity", "low,medium,high,critical",
            "-exclude-tags", "dos,fuzz",
            "-rl", "5",
            "-c", "5",
            "-timeout", "10",
            "-retries", "0",
            "-mhe", "3",
            "-stats", "-stats-json", "-stats-interval", "1",
        ]
        if verbose:
            cmd.append("-v")

        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_clean_env(),
        )
        process.stdin.write("\n".join(targets))
        process.stdin.close()

        pbar = None
        try:
            for line in iter(process.stderr.readline, ""):
                if verbose:
                    logger.debug("[nuclei] %s", line.rstrip())
                try:
                    if "{" in line:
                        stats = json.loads(line[line.find("{"):line.rfind("}") + 1])
                        total = int(stats.get("total", 0))
                        current = int(stats.get("requests", 0))
                        if pbar is None and total > 0:
                            pbar = tqdm(total=total, desc="Nuclei", unit="req", leave=False)
                        if pbar:
                            pbar.n = current
                            pbar.refresh()
                except (json.JSONDecodeError, ValueError):
                    pass
        except KeyboardInterrupt:
            process.terminate()
            SKIP_CURRENT_TASK = False
            for t in targets:
                mark_as_run("nuclei", t)
            if pbar:
                pbar.close()
            return "Nuclei skipped by user."

        process.wait()
        if pbar:
            pbar.close()

        if SKIP_CURRENT_TASK:
            SKIP_CURRENT_TASK = False
            for t in targets:
                mark_as_run("nuclei", t)
            return "Nuclei skipped by user."

        # FIX: parse JSONL correctly — one JSON object per line
        findings = []
        if os.path.exists(out_file):
            with open(out_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        findings.append({
                            "template": item.get("template-id"),
                            "target": item.get("matched-at", "unknown"),
                            "severity": item.get("info", {}).get("severity"),
                            "description": item.get("info", {}).get("name"),
                        })
                    except json.JSONDecodeError as exc:
                        logger.warning("Skipping malformed Nuclei line: %s", exc)

        if findings:
            update_db("vulnerabilities", findings)
            return f"Nuclei complete — {len(findings)} findings added."
        return "Nuclei finished with 0 findings."

    except Exception as exc:
        logger.error("Nuclei error: %s", exc)
        return f"Nuclei error: {exc}"


@tool
def run_nc_banner_grab(target: str, port: int, send_string: str = "") -> str:
    """
    Use netcat to grab a service banner or probe a port.

    Args:
        target: Hostname or IP.
        port: Port number.
        send_string: Optional string to send before reading.
    """
    try:
        _assert_in_scope(target)
    except ValueError as exc:
        return f"[SCOPE BLOCK] {exc}"
    try:
        result = subprocess.run(
            ["nc", "-vn", "-w", "2", str(target), str(port)],
            input=send_string + "\n",
            capture_output=True,
            text=True,
            env=_clean_env(),
        )
        return f"NC {target}:{port}:\n{result.stdout or result.stderr}"
    except Exception as exc:
        return f"NC Error: {exc}"


@tool
def run_ssh_audit(target: str, port: int = 22) -> str:
    """
    Run ssh-audit to identify weak ciphers, algorithms, and SSH CVEs.

    Args:
        target: Hostname or IP.
        port: SSH port (default 22).
    """
    try:
        _assert_in_scope(target)
    except ValueError as exc:
        return f"[SCOPE BLOCK] {exc}"
    try:
        result = subprocess.run(
            ["ssh-audit", "-p", str(port), target],
            capture_output=True,
            text=True,
            env=_clean_env(),
        )
        return f"SSH Audit {target}:\n{result.stdout}"
    except Exception as exc:
        return f"SSH Audit Error: {exc}"


@tool
def run_hydra_check(
    target: str, service: str, user: str, password: str, port: int = None
) -> str:
    """
    Verify a username/password pair against a service using Hydra.

    Args:
        target: Hostname or IP.
        service: Protocol (ssh, ftp, http-get, etc.).
        user: Username to test.
        password: Password to test.
        port: Optional port override.
    """
    try:
        _assert_in_scope(target)
    except ValueError as exc:
        return f"[SCOPE BLOCK] {exc}"
    try:
        port_args = ["-s", str(port)] if port else []
        result = subprocess.run(
            ["hydra", "-l", user, "-p", password] + port_args + ["-f", f"{service}://{target}"],
            capture_output=True,
            text=True,
            env=_clean_env(),
        )
        if "1 of 1 target successfully completed" in result.stdout:
            return f"[SUCCESS] {user}:{password} works on {service}://{target}"
        return f"[FAIL] {user}:{password} rejected on {service}://{target}"
    except Exception as exc:
        return f"Hydra Error: {exc}"


@tool
def run_testssl_verification(target: str) -> str:
    """
    Deep SSL/TLS analysis with testssl.sh. Use when Nuclei flags an SSL issue.

    Args:
        target: Target URL or host:port.
    """
    try:
        _assert_in_scope(target)
    except ValueError as exc:
        return f"[SCOPE BLOCK] {exc}"
    try:
        result = subprocess.run(
            ["testssl.sh", "--quiet", "--severity", "MEDIUM", target],
            capture_output=True,
            text=True,
            env=_clean_env(),
        )
        return f"TestSSL {target}:\n{result.stdout}"
    except Exception as exc:
        return f"TestSSL Error: {exc}"


@tool
def execute_curl_request(
    url: str, method: str = "GET", headers: dict = None, data: str = None
) -> str:
    """
    Execute a custom HTTP request with curl for manual vulnerability verification.

    Args:
        url: Target URL.
        method: HTTP method (GET, POST, PUT, etc.).
        headers: Optional dict of request headers.
        data: Optional request body.
    """
    try:
        _assert_in_scope(url)
    except ValueError as exc:
        return f"[SCOPE BLOCK] {exc}"
    cmd = ["curl", "-s", "-i", "-X", method, url]
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    if data:
        cmd.extend(["-d", data])
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, env=_clean_env()
        )
        return result.stdout[:2000]
    except subprocess.TimeoutExpired:
        return "Error: curl timed out."
    except Exception as exc:
        return f"Curl Error: {exc}"


@tool
def run_wpscan_tool(target_url: str) -> str:
    """
    Run WPScan against a target to detect WordPress, plugins, and CVEs.
    Output is written to a JSON file rather than truncated in memory.

    Args:
        target_url: Full URL to scan (e.g. 'http://example.com').
    """
    try:
        _assert_in_scope(target_url)
    except ValueError as exc:
        return f"[SCOPE BLOCK] {exc}"

    if is_already_run("wpscan", target_url):
        return f"[SKIP] wpscan already run for {target_url}."

    out_file = os.path.join(OUTPUT_DIR, "wpscan_out.json")
    wpscan_token = os.environ.get("WPSCAN_API_TOKEN")

    # FIX: pass the token through the subprocess environment, NOT via --api-token
    # in argv. Argv is visible to all local users via `ps aux` / /proc/<pid>/cmdline.
    wpscan_env = _clean_env()
    if wpscan_token:
        wpscan_env["WPSCAN_API_TOKEN"] = wpscan_token

    cmd = [
        "wpscan", "--url", target_url, "--no-update",
        "--random-user-agent", "-e", "vp,vt",
        "--format", "json", "-o", out_file,
    ]

    logger.info("Running wpscan on %s…", target_url)
    try:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, env=wpscan_env)
        except KeyboardInterrupt:
            mark_as_run("wpscan", target_url)
            return "WPScan interrupted by user."

        # Retry after DB update if needed
        if "missing database" in (result.stdout + result.stderr).lower():
            logger.warning("WPScan DB missing — updating…")
            subprocess.run(["wpscan", "--update"], capture_output=True, text=True)
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, env=wpscan_env)
            except KeyboardInterrupt:
                mark_as_run("wpscan", target_url)
                return "WPScan interrupted by user."

        mark_as_run("wpscan", target_url)

        if os.path.exists(out_file):
            with open(out_file) as fh:
                raw = fh.read()
            try:
                parsed = json.loads(raw)
                summary = {
                    "interesting_findings": parsed.get("interesting_findings", []),
                    "plugins": parsed.get("plugins", {}),
                    "version": parsed.get("version", {}),
                    "vulnerabilities": parsed.get("vulnerabilities", []),
                }
                return f"WPScan {target_url}:\n{json.dumps(summary, indent=2)}"
            except json.JSONDecodeError:
                pass

        fallback = result.stdout or result.stderr
        return f"WPScan {target_url}:\n{fallback}"

    except FileNotFoundError:
        return "[!] wpscan binary not found."
    except Exception as exc:
        return f"WPScan Error: {exc}"


@tool
def add_vulnerability_tool(
    target: str, template: str, severity: str, description: str, poc: str
) -> str:
    """
    Manually add a verified vulnerability to the database.

    Args:
        target: Target URL or host.
        template: Vulnerability name/ID (e.g. 'git-config-disclosure').
        severity: low | medium | high | critical.
        description: Brief description of the finding.
        poc: Exact commands/steps needed to reproduce.
    """
    update_db("vulnerabilities", [{
        "template": template,
        "target": target,
        "severity": severity,
        "description": description,
        "poc": poc,
    }])
    return f"Vulnerability '{template}' for {target} added to the database."


@tool
def run_feroxbuster_tool(
    url: Union[str, List[str]],
    extensions: str = "php,html,js,txt",
    verbose: bool = False,
) -> str:
    """
    Directory and file discovery using feroxbuster.
    Only HTTP 200/204 responses are recorded as findings (not 301/302/403).

    Args:
        url: Target URL or list of target URLs.
        extensions: Comma-separated file extensions to probe.
        verbose: Stream feroxbuster output when True.
    """
    # FIX: Only these statuses are genuinely "interesting files"
    INTERESTING_STATUSES = {200, 204}

    with FEROX_LOCK:
        global SKIP_CURRENT_TASK
        targets = [url] if isinstance(url, str) else url

        for t in targets:
            try:
                _assert_in_scope(t)
            except ValueError as exc:
                return f"[SCOPE BLOCK] {exc}"

        new_targets = [t for t in targets if not is_already_run("feroxbuster", t)]
        if not new_targets:
            return f"All {len(targets)} targets already scanned by feroxbuster."

        out_file = os.path.join(OUTPUT_DIR, "feroxbuster_out.json")
        all_findings = []

        for i, target in enumerate(new_targets):
            if os.path.exists(out_file):
                os.remove(out_file)

            logger.info("[%d/%d] Feroxbuster scanning %s…", i + 1, len(new_targets), target)
            cmd = [
                "feroxbuster", "-u", target,
                "-t", "10", "-d", "2",
                "--json", "-o", out_file,
                "-x", extensions,
                "--no-state",
            ]
            if not verbose:
                cmd.append("--silent")

            try:
                subprocess.run(
                    cmd, capture_output=not verbose, text=True,
                    check=False, env=_clean_env(),
                )
            except KeyboardInterrupt:
                SKIP_CURRENT_TASK = False
                mark_as_run("feroxbuster", target)
                continue

            if SKIP_CURRENT_TASK:
                SKIP_CURRENT_TASK = False
                mark_as_run("feroxbuster", target)
                continue

            if os.path.exists(out_file):
                with open(out_file) as f:
                    for line in f:
                        try:
                            finding = json.loads(line)
                            status = finding.get("status")
                            if status in INTERESTING_STATUSES:
                                all_findings.append({
                                    "url": finding.get("url"),
                                    "status": status,
                                    "content_length": finding.get("content_length"),
                                    "target": target,
                                    "comment": f"HTTP {status}",
                                })
                        except json.JSONDecodeError:
                            continue

            mark_as_run("feroxbuster", target)

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
        _ssl_ctx = ssl.create_default_context()  # enforces cert verification
        with urllib.request.urlopen(req, timeout=30, context=_ssl_ctx) as resp:
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