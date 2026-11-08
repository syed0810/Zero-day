#!/usr/bin/env python3
"""
Project Zero-Day: Target Validation & Authorization Architecture
Module: app/target_validator.py
Objective: Robust validation, scheme/host/port checking, redirect safety,
           and Docker container-to-host address mapping for local targets.
"""

import ipaddress
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple


# ==============================================================================
# Custom Exceptions for Target Architecture
# ==============================================================================

class TargetValidationError(ValueError):
    """Raised when target URL format, scheme, host, or port violates policy."""
    pass


class TargetUnreachableError(ConnectionError):
    """Raised when target endpoint cannot be reached on the host."""
    pass


class BlockedRedirectError(PermissionError):
    """Raised when an HTTP redirect attempts to route to an unauthorized destination."""
    pass


class DockerConnectivityError(RuntimeError):
    """Raised when Docker daemon is down or container cannot reach the host target."""
    pass


# ==============================================================================
# Loopback & Scope Constants
# ==============================================================================

LOOPBACK_HOSTNAMES: Set[str] = {
    "localhost",
    "127.0.0.1",
    "::1",
    "[::1]",
    "host.docker.internal",
}

SUPPORTED_SCHEMES: Set[str] = {"http", "https"}


def is_loopback_host(hostname: str) -> bool:
    """
    Determines whether a hostname or IP represents a local loopback target.
    Prevents subdomain spoofing (e.g. localhost.evil.com, 127.0.0.1.nip.io)
    and userinfo spoofing.
    """
    if not hostname or not isinstance(hostname, str):
        return False

    clean = hostname.strip().lower()

    # Direct match on known loopback hostnames
    if clean in LOOPBACK_HOSTNAMES:
        return True

    # Strip bracket notation for IPv6 if present
    if clean.startswith("[") and clean.endswith("]"):
        clean = clean[1:-1]

    # Try parsing as IPv4 or IPv6 IP address
    try:
        ip = ipaddress.ip_address(clean)
        return ip.is_loopback
    except ValueError:
        pass

    return False


# ==============================================================================
# Target Parsing & Validation
# ==============================================================================

def parse_and_validate_target(
    target_url: str,
    enforce_local: bool = True,
) -> Dict[str, Any]:
    """
    Validates URL format, scheme, host, and port.
    Enforces local loopback constraints when enforce_local is True.
    Returns normalized target metadata dictionary.
    """
    if not target_url or not isinstance(target_url, str):
        raise TargetValidationError("Target URL cannot be empty or null.")

    clean_url = target_url.strip()

    # Reject userinfo bypass attempts (e.g. http://localhost:3000@evil.com)
    # Check before and after urllib parsing
    if "@" in clean_url:
        raise TargetValidationError(
            f"Target URL '{clean_url}' rejected: userinfo (@) syntax is prohibited for security."
        )

    parsed = urllib.parse.urlparse(clean_url)

    # 1. Scheme Validation
    scheme = (parsed.scheme or "").lower()
    if not scheme:
        raise TargetValidationError(
            f"Target URL '{clean_url}' missing URL scheme. Please specify 'http://' or 'https://'."
        )
    if scheme not in SUPPORTED_SCHEMES:
        raise TargetValidationError(
            f"Unsupported scheme '{scheme}' in '{clean_url}'. Only HTTP and HTTPS are supported."
        )

    # 2. Host Validation
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise TargetValidationError(f"Target URL '{clean_url}' missing valid hostname.")

    is_loopback = is_loopback_host(hostname)
    if enforce_local and not is_loopback:
        raise TargetValidationError(
            f"Target host '{hostname}' rejected: only local loopback targets "
            f"(localhost, 127.0.0.1, ::1) are authorized under local target policy."
        )

    # 3. Port Validation
    try:
        raw_port = parsed.port
    except ValueError as val_err:
        raise TargetValidationError(
            f"Invalid port in '{clean_url}': {val_err}. Port must be an integer between 1 and 65535."
        ) from val_err

    if raw_port is None:
        port = 443 if scheme == "https" else 80
    else:
        port = raw_port

    if not isinstance(port, int) or port < 1 or port > 65535:
        raise TargetValidationError(
            f"Invalid port '{port}' in '{clean_url}'. Port must be an integer between 1 and 65535."
        )

    # Construct canonical normalized base URL
    is_standard_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc_str = hostname if is_standard_port else f"{hostname}:{port}"
    path_str = parsed.path or "/"

    normalized_url = urllib.parse.urlunparse((
        scheme,
        netloc_str,
        path_str,
        parsed.params,
        parsed.query,
        "",  # drop fragment
    ))

    return {
        "raw_url": target_url,
        "normalized_url": normalized_url,
        "scheme": scheme,
        "host": hostname,
        "port": port,
        "path": path_str,
        "query": parsed.query,
        "is_loopback": is_loopback,
    }


# ==============================================================================
# Docker Address Mapping (Windows-host loopback -> Container-reachable)
# ==============================================================================

def map_to_container_target(target_url: str) -> str:
    """
    Automatically maps Windows-host loopback URLs (localhost, 127.0.0.1, ::1)
    to addresses reachable from Docker scanner containers (host.docker.internal).
    Preserves scheme, port, path, query, and non-loopback hosts.
    """
    if not target_url or not isinstance(target_url, str):
        return target_url

    parsed = urllib.parse.urlparse(target_url.strip())
    hostname = (parsed.hostname or "").lower()

    if is_loopback_host(hostname) and hostname != "host.docker.internal":
        port_suffix = f":{parsed.port}" if parsed.port is not None else ""
        new_netloc = f"host.docker.internal{port_suffix}"
        mapped = parsed._replace(netloc=new_netloc)
        return urllib.parse.urlunparse(mapped)

    return target_url.strip()


def map_container_to_host_target(raw_url: str, canonical_host: Optional[str] = None) -> str:
    """
    Translates container-internal aliases (host.docker.internal) back to
    host-accessible addresses (localhost) for consistent asset inventory.
    Preserves port and paths.
    """
    if not raw_url or not isinstance(raw_url, str):
        return raw_url or ""

    try:
        parsed = urllib.parse.urlparse(raw_url.strip())
        netloc = parsed.netloc.lower()
        if "host.docker.internal" in netloc or "127.0.0.1" in netloc:
            if canonical_host:
                new_netloc = canonical_host
            else:
                port_suffix = f":{parsed.port}" if parsed.port is not None else ""
                new_netloc = f"localhost{port_suffix}"
            return urllib.parse.urlunparse(parsed._replace(netloc=new_netloc))
    except Exception:
        pass
    return raw_url.strip()


# ==============================================================================
# Reachability & Redirect Verification
# ==============================================================================

class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Custom HTTP redirect handler that enforces policy constraints on redirect destinations.
    Blocks redirects escaping the authorized local scope.
    """

    def __init__(self, enforce_local: bool = True, max_redirects: int = 5):
        super().__init__()
        self.enforce_local = enforce_local
        self.max_redirects = max_redirects
        self.redirect_history: List[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_history.append(newurl)
        if len(self.redirect_history) > self.max_redirects:
            raise BlockedRedirectError(
                f"Exceeded maximum redirect limit of {self.max_redirects} hops."
            )

        parsed_new = urllib.parse.urlparse(newurl)
        new_scheme = (parsed_new.scheme or "").lower()
        if new_scheme not in SUPPORTED_SCHEMES:
            raise BlockedRedirectError(
                f"Blocked redirect to unsupported scheme '{new_scheme}' ({newurl})."
            )

        new_host = (parsed_new.hostname or "").lower()
        if self.enforce_local and not is_loopback_host(new_host):
            raise BlockedRedirectError(
                f"Blocked redirect: Target attempted to redirect to unauthorized remote destination "
                f"'{newurl}'. All redirect hops must remain within local scope."
            )

        return super().redirect_request(req, fp, code, msg, headers, newurl)


def verify_target_reachability(
    target_url: str,
    timeout: float = 3.0,
    max_redirects: int = 5,
    enforce_local: bool = True,
) -> Tuple[bool, str, str]:
    """
    Verifies that the target endpoint is reachable via HTTP/HTTPS.
    Inspects and validates redirect destinations against authorized scope.
    Returns: (is_reachable, status_message, final_effective_url)
    Raises: TargetValidationError, BlockedRedirectError, or TargetUnreachableError
    """
    meta = parse_and_validate_target(target_url, enforce_local=enforce_local)
    clean_url = meta["normalized_url"]

    redirect_handler = SafeRedirectHandler(enforce_local=enforce_local, max_redirects=max_redirects)
    opener = urllib.request.build_opener(redirect_handler)

    req = urllib.request.Request(
        clean_url,
        headers={"User-Agent": "ProjectZeroDay-TargetValidator/2.0"},
        method="GET",
    )

    try:
        with opener.open(req, timeout=timeout) as resp:
            status = resp.status
            effective_url = resp.geturl()
            # Verify final effective URL against scope
            final_parsed = urllib.parse.urlparse(effective_url)
            final_host = (final_parsed.hostname or "").lower()
            if enforce_local and not is_loopback_host(final_host):
                raise BlockedRedirectError(
                    f"Blocked redirect: Final destination '{effective_url}' is not a permitted local loopback host."
                )

            msg = f"Target '{clean_url}' reachable (HTTP {status})"
            if effective_url != clean_url:
                msg += f" -> redirected to '{effective_url}'"
            return True, msg, effective_url

    except urllib.error.HTTPError as http_err:
        # HTTP errors like 401, 403, 404, 500 still prove the target service is alive and listening!
        effective_url = http_err.geturl() if hasattr(http_err, "geturl") else clean_url
        msg = f"Target '{clean_url}' responded with HTTP {http_err.code}"
        return True, msg, effective_url

    except BlockedRedirectError:
        raise

    except urllib.error.URLError as url_err:
        raise TargetUnreachableError(
            f"Target '{clean_url}' is unreachable: {url_err.reason}. "
            "Please ensure the application is running and listening on the specified port."
        )

    except Exception as exc:
        raise TargetUnreachableError(
            f"Target '{clean_url}' reachability check failed: {exc}."
        )


# ==============================================================================
# Docker Scanner Connectivity Verification
# ==============================================================================

def check_docker_daemon_status() -> Tuple[bool, str]:
    """
    Verifies that the Docker CLI is present and the Docker daemon is responsive.
    """
    try:
        proc = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
        )
        if proc.returncode == 0:
            version = proc.stdout.strip() or "active"
            return True, f"Docker daemon is responsive (Server Engine: {version})"
        err = (proc.stderr or proc.stdout).strip()[:200]
        return False, f"Docker daemon is not running or unreachable: {err}"
    except FileNotFoundError:
        return False, "Docker CLI executable not found on PATH."
    except subprocess.TimeoutExpired:
        return False, "Docker daemon response timed out."
    except Exception as exc:
        return False, f"Unexpected error checking Docker: {exc}"


def verify_docker_container_connectivity(
    container_target_url: str,
    timeout: float = 5.0,
    curl_image: str = "curlimages/curl:latest",
) -> Tuple[bool, str]:
    """
    Verifies that a Docker scanner container can connect to the mapped host address
    (e.g. http://host.docker.internal:8000).
    Runs a lightweight curl test container before initiating full scans.
    """
    # 1. Check Docker daemon first
    daemon_ok, daemon_msg = check_docker_daemon_status()
    if not daemon_ok:
        raise DockerConnectivityError(daemon_msg)

    # 2. Run curl container to verify host reachability from container network
    cmd = [
        "docker", "run", "--rm",
        curl_image,
        "-s", "-I",
        "-o", "/dev/null",
        "-w", "%{http_code}",
        "--connect-timeout", str(int(timeout)),
        container_target_url,
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(25.0, timeout + 15.0),
        )
        http_code_str = proc.stdout.strip()

        # If HTTP response code was received (even 200, 301, 404, etc.)
        if http_code_str and http_code_str != "000":
            return True, (
                f"Docker container connectivity verified: '{container_target_url}' "
                f"is reachable from containers (HTTP {http_code_str})."
            )

        err_out = (proc.stderr or proc.stdout).strip()[:250]
        raise DockerConnectivityError(
            f"Docker container cannot reach target at '{container_target_url}'. "
            f"Output: {err_out or 'Connection timed out or refused inside container.'} "
            "Please ensure the application on Windows is listening on all interfaces (0.0.0.0 or 127.0.0.1) "
            "and not blocked by firewall rules."
        )

    except subprocess.TimeoutExpired:
        raise DockerConnectivityError(
            f"Docker container connectivity check timed out connecting to '{container_target_url}'."
        )
    except DockerConnectivityError:
        raise
    except Exception as exc:
        raise DockerConnectivityError(
            f"Failed to execute Docker container connectivity probe: {exc}"
        )
