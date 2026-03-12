"""
Local system inventory tools — scans the Ubuntu host to determine what
software, services, and ports are present so the analyzer can assess
which CVEs are relevant to THIS specific system.

All scans are read-only — no modifications to the system.
"""

import json
import subprocess
from datetime import datetime, timezone
from typing import Optional

from langchain_core.tools import tool

from config import DATA_DIR


def _run_cmd(cmd: list[str], timeout: int = 15) -> str:
    """Run a system command and return stdout. Returns empty string on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return ""


@tool
def scan_local_packages() -> str:
    """Scan installed packages on the local Ubuntu system.

    Collects:
    - apt/dpkg packages (system packages)
    - pip packages (Python)
    - npm global packages (Node.js, if installed)

    Returns:
        JSON string with categorized package lists.
    """
    packages = {"apt": [], "pip": [], "npm": []}

    # ─── APT / dpkg packages ─────────────────────────────────────────────────
    dpkg_output = _run_cmd(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n"])
    if dpkg_output:
        for line in dpkg_output.split("\n"):
            parts = line.split("\t")
            if len(parts) >= 3 and "installed" in parts[2].lower():
                packages["apt"].append({"name": parts[0], "version": parts[1]})

    # ─── pip packages ─────────────────────────────────────────────────────────
    pip_output = _run_cmd(["pip", "list", "--format=json"])
    if not pip_output:
        pip_output = _run_cmd(["pip3", "list", "--format=json"])
    if pip_output:
        try:
            pip_pkgs = json.loads(pip_output)
            packages["pip"] = [{"name": p["name"], "version": p["version"]} for p in pip_pkgs]
        except json.JSONDecodeError:
            pass

    # ─── npm global packages ──────────────────────────────────────────────────
    npm_output = _run_cmd(["npm", "list", "-g", "--json", "--depth=0"])
    if npm_output:
        try:
            npm_data = json.loads(npm_output)
            deps = npm_data.get("dependencies", {})
            packages["npm"] = [
                {"name": name, "version": info.get("version", "?")}
                for name, info in deps.items()
            ]
        except json.JSONDecodeError:
            pass

    result = {
        "source": "local_packages",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "counts": {k: len(v) for k, v in packages.items()},
        "packages": packages,
    }

    outpath = DATA_DIR / "local_packages.json"
    outpath.write_text(json.dumps(result, indent=2))

    return json.dumps(result, indent=2)


@tool
def scan_docker_images() -> str:
    """Scan Docker images and running containers on the local system.

    Returns:
        JSON string with Docker images, running containers, and Dockerfile inventory.
    """
    docker_info = {"images": [], "containers": [], "available": False}

    # Check if Docker is available
    docker_check = _run_cmd(["docker", "version", "--format", "{{.Server.Version}}"])
    if not docker_check:
        return json.dumps({
            "source": "docker",
            "available": False,
            "message": "Docker is not installed or not accessible.",
        })

    docker_info["available"] = True

    # ─── Images ───────────────────────────────────────────────────────────────
    images_output = _run_cmd([
        "docker", "images", "--format",
        "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedAt}}"
    ])
    if images_output:
        for line in images_output.split("\n"):
            parts = line.split("\t")
            if len(parts) >= 4:
                docker_info["images"].append({
                    "repository": parts[0],
                    "tag": parts[1],
                    "id": parts[2],
                    "size": parts[3],
                })

    # ─── Running containers ───────────────────────────────────────────────────
    containers_output = _run_cmd([
        "docker", "ps", "--format",
        "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
    ])
    if containers_output:
        for line in containers_output.split("\n"):
            parts = line.split("\t")
            if len(parts) >= 3:
                docker_info["containers"].append({
                    "name": parts[0],
                    "image": parts[1],
                    "status": parts[2],
                    "ports": parts[3] if len(parts) > 3 else "",
                })

    result = {
        "source": "docker",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "available": True,
        "image_count": len(docker_info["images"]),
        "running_containers": len(docker_info["containers"]),
        **docker_info,
    }

    outpath = DATA_DIR / "docker_inventory.json"
    outpath.write_text(json.dumps(result, indent=2))

    return json.dumps(result, indent=2)


@tool
def scan_open_ports() -> str:
    """Scan network ports with listening services on the local system.

    Uses 'ss' (socket statistics) to find open TCP/UDP ports.

    Returns:
        JSON string with list of listening ports and associated processes.
    """
    ports = []

    # ss -tlnp: TCP listening, numeric, show process
    ss_output = _run_cmd(["ss", "-tlnp"])
    if ss_output:
        for line in ss_output.split("\n")[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 5:
                local_addr = parts[3]
                process_info = parts[-1] if "users:" in parts[-1] else ""
                ports.append({
                    "proto": "tcp",
                    "local_address": local_addr,
                    "state": parts[0],
                    "process": process_info,
                })

    # ss -ulnp: UDP listening
    ss_udp = _run_cmd(["ss", "-ulnp"])
    if ss_udp:
        for line in ss_udp.split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 5:
                local_addr = parts[3]
                process_info = parts[-1] if "users:" in parts[-1] else ""
                ports.append({
                    "proto": "udp",
                    "local_address": local_addr,
                    "state": parts[0],
                    "process": process_info,
                })

    result = {
        "source": "open_ports",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_listening": len(ports),
        "ports": ports,
    }

    outpath = DATA_DIR / "open_ports.json"
    outpath.write_text(json.dumps(result, indent=2))

    return json.dumps(result, indent=2)


@tool
def scan_system_services() -> str:
    """Scan active systemd services on the local Ubuntu system.

    Returns:
        JSON string with list of running services and their status.
    """
    services = []

    output = _run_cmd([
        "systemctl", "list-units",
        "--type=service", "--state=running",
        "--no-pager", "--plain", "--no-legend",
    ])
    if output:
        for line in output.split("\n"):
            parts = line.split(None, 4)
            if len(parts) >= 4:
                services.append({
                    "unit": parts[0],
                    "load": parts[1],
                    "active": parts[2],
                    "sub": parts[3],
                    "description": parts[4] if len(parts) > 4 else "",
                })

    result = {
        "source": "systemd_services",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "running_services": len(services),
        "services": services,
    }

    outpath = DATA_DIR / "system_services.json"
    outpath.write_text(json.dumps(result, indent=2))

    return json.dumps(result, indent=2)


@tool
def get_full_system_inventory() -> str:
    """Collect a comprehensive system inventory combining all local scan tools.

    Runs all local scans (packages, Docker, ports, services) and combines
    results into a single inventory snapshot. Use this for a complete
    picture of the system's attack surface.

    Returns:
        JSON string with complete system inventory.
    """
    # Collect all inventory data
    packages = json.loads(scan_local_packages.invoke({}))
    docker = json.loads(scan_docker_images.invoke({}))
    ports = json.loads(scan_open_ports.invoke({}))
    services = json.loads(scan_system_services.invoke({}))

    # System info
    hostname = _run_cmd(["hostname"])
    kernel = _run_cmd(["uname", "-r"])
    os_release = _run_cmd(["lsb_release", "-ds"])
    uptime = _run_cmd(["uptime", "-p"])

    inventory = {
        "source": "full_system_inventory",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": {
            "hostname": hostname,
            "kernel": kernel,
            "os": os_release,
            "uptime": uptime,
        },
        "summary": {
            "apt_packages": packages.get("counts", {}).get("apt", 0),
            "pip_packages": packages.get("counts", {}).get("pip", 0),
            "npm_packages": packages.get("counts", {}).get("npm", 0),
            "docker_images": docker.get("image_count", 0),
            "running_containers": docker.get("running_containers", 0),
            "listening_ports": ports.get("total_listening", 0),
            "running_services": services.get("running_services", 0),
        },
        "packages": packages.get("packages", {}),
        "docker": docker,
        "ports": ports.get("ports", []),
        "services": services.get("services", []),
    }

    outpath = DATA_DIR / "full_inventory.json"
    outpath.write_text(json.dumps(inventory, indent=2))

    return json.dumps(inventory, indent=2)
