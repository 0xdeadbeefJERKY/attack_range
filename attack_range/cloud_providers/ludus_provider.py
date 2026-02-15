"""
Ludus cloud provider implementation.

This module contains Ludus-specific operations for managing attack ranges
on a Ludus (ludus.cloud) server. Ludus is a self-hosted cyber range platform
built on Proxmox that manages VM provisioning, networking, and WireGuard VPN.

Unlike cloud providers (AWS, Azure, GCP), Ludus does not use Terraform.
Instead, it uses its own REST API and CLI for all infrastructure operations.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from typing import Optional

import yaml

from .base_provider import BaseCloudProvider


class LudusProvider(BaseCloudProvider):
    """Ludus provider implementation.

    Ludus manages its own infrastructure through its REST API/CLI.
    Backend, SSH key, and Terraform-related methods are no-ops since
    Ludus handles these concerns internally.
    """

    def __init__(self, config: dict, logger):
        """Initialize Ludus provider."""
        super().__init__(config, logger)

    # ------------------------------------------------------------------ #
    #  BaseCloudProvider interface (mostly no-ops for Ludus)
    # ------------------------------------------------------------------ #

    def get_region(self, required: bool = True) -> Optional[str]:
        """Return the Ludus API URL as the 'region'.

        For Ludus the concept of a cloud region does not apply.  We reuse
        the ``get_region`` slot to return the API URL so the rest of the
        framework can pass it around when a *region* string is expected.
        """
        url = self.config.get("ludus", {}).get("ludus_url", "https://198.51.100.1:8080")
        return url

    def check_backend_exists(self, backend_name: str) -> bool:
        """Ludus does not use a remote Terraform backend."""
        return True  # always "exists" so no creation is attempted

    def create_backend(self, backend_name: str, region: str) -> None:
        """No-op -- Ludus does not need a Terraform backend."""
        self.logger.info("Ludus: no remote backend required")

    def delete_backend(self, backend_name: str, region: str) -> None:
        """No-op -- nothing to clean up."""
        self.logger.info("Ludus: no remote backend to delete")

    def sanitize_name(self, name: str) -> str:
        """Sanitize a name for Ludus (lowercase, alphanumeric + hyphens)."""
        sanitized = re.sub(r"[^a-z0-9-]", "-", name.lower())
        sanitized = re.sub(r"-{2,}", "-", sanitized).strip("-")
        if len(sanitized) < 1:
            sanitized = "ludus"
        return sanitized[:63]

    def import_ssh_key(self, key_name: str, public_key_content: str, region: str) -> None:
        """Ludus manages SSH access internally -- no upload needed."""
        self.logger.info("Ludus: SSH keys are managed by the Ludus server")

    def delete_ssh_key(self, key_name: str, region: str) -> None:
        """No-op -- Ludus manages SSH keys internally."""
        self.logger.info("Ludus: no cloud SSH keys to delete")

    def update_backend_config(self, backend_params: dict, backend_file_path: str) -> None:
        """Write a local-only backend.tf so Terraform paths resolve (not actively used)."""
        attack_range_id = backend_params.get("attack_range_id", "unknown")
        config_source = backend_params.get("config_source", "template/config file")

        backend_config = f"""# This file is AUTO-GENERATED -- Ludus does not use Terraform.
# Generated from: {config_source}
# Attack Range ID: {attack_range_id}
#
terraform {{
  backend "local" {{
    path = "terraform.tfstate"
  }}
}}
"""
        with open(backend_file_path, "w") as f:
            f.write(backend_config)
        self.logger.info(f"Ludus: wrote placeholder backend.tf to {backend_file_path}")

    # ------------------------------------------------------------------ #
    #  Ludus-specific helpers
    # ------------------------------------------------------------------ #

    def _run_ludus_cli(self, args: list, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess:
        """Run a ``ludus`` CLI command and return the result.

        :param args: Arguments to pass *after* ``ludus`` (e.g. ``["range", "status"]``).
        :param check: Raise on non-zero exit code.
        :param timeout: Timeout in seconds.
        :returns: ``CompletedProcess`` instance.
        """
        cmd = ["ludus"] + args

        # Propagate Ludus URL from config if set
        ludus_url = self.config.get("ludus", {}).get("ludus_url")
        if ludus_url:
            cmd = ["ludus", "--url", ludus_url] + args

        self.logger.info(f"Ludus CLI: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if check and result.returncode != 0:
                self.logger.error(f"Ludus CLI failed (exit {result.returncode}): {result.stderr or result.stdout}")
                raise RuntimeError(f"ludus {' '.join(args)} failed: {result.stderr or result.stdout}")
            return result
        except FileNotFoundError:
            self.logger.error("Ludus CLI ('ludus') not found on PATH. Please install it: https://docs.ludus.cloud")
            raise RuntimeError("ludus CLI not found")

    # -- config conversion ------------------------------------------------

    def convert_to_ludus_config(self, config: dict) -> dict:
        """Convert an attack_range configuration dict to a Ludus range config.

        The Ludus range config format is documented at
        https://docs.ludus.cloud/docs/configuration/.

        :param config: Full attack_range configuration dictionary.
        :returns: A dict suitable for writing as YAML and passing to
                  ``ludus range config set``.
        """
        attack_range_servers = config.get("attack_range", [])
        ludus_config = {"ludus": []}
        ludus_section = config.get("ludus", {})
        default_vlan = ludus_section.get("vlan", 20)

        for server in attack_range_servers:
            name = server.get("name", "server")
            vm_entry: dict = {
                "vm_name": "{{ range_id }}-" + self.sanitize_name(name),
                "hostname": "{{ range_id }}-" + self.sanitize_name(name),
                "template": server.get("template", self._default_template(server)),
                "vlan": server.get("vlan", default_vlan),
                "ip_last_octet": server.get("ip_last_octet", 10),
            }

            # Resource allocation
            ram_gb = server.get("ram_gb")
            cpus = server.get("cpus")
            if ram_gb:
                vm_entry["ram_gb"] = int(ram_gb)
            if cpus:
                vm_entry["cpus"] = int(cpus)

            # OS type
            if server.get("windows"):
                vm_entry["windows"] = {"sysprep": True}
            else:
                vm_entry["linux"] = True

            # Ansible roles -- extract role names and vars
            roles = server.get("roles", [])
            role_names = []
            role_vars: dict = {}
            for role_entry in roles:
                if isinstance(role_entry, dict):
                    role_name = role_entry.get("role", "")
                    # Ludus expects lowercase role names
                    role_names.append(role_name.lower())
                    # Merge role vars
                    entry_vars = role_entry.get("vars", {})
                    if entry_vars:
                        role_vars.update(entry_vars)
                elif isinstance(role_entry, str):
                    role_names.append(role_entry.lower())

            if role_names:
                vm_entry["roles"] = role_names
            if role_vars:
                vm_entry["role_vars"] = role_vars

            ludus_config["ludus"].append(vm_entry)

        return ludus_config

    @staticmethod
    def _default_template(server: dict) -> str:
        """Infer a Ludus template name from server config hints."""
        if server.get("windows"):
            return "win2022-server-x64-template"
        # Default to Ubuntu 22.04
        return "debian-12-x64-server-template"

    # -- range lifecycle ---------------------------------------------------

    def set_range_config(self, ludus_config: dict) -> str:
        """Write a Ludus range config file and set it via the CLI.

        :param ludus_config: Ludus range configuration dictionary.
        :returns: Path to the temporary config file (kept for debugging).
        """
        # Write temp YAML file
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", prefix="ludus_range_", delete=False
        )
        yaml.dump(ludus_config, tmp, default_flow_style=False, sort_keys=False)
        tmp.close()

        self.logger.info(f"Ludus: setting range config from {tmp.name}")
        self._run_ludus_cli(["range", "config", "set", "-f", tmp.name])
        return tmp.name

    def deploy_range(self) -> None:
        """Kick off a Ludus range deployment."""
        self.logger.info("Ludus: starting range deployment")
        self._run_ludus_cli(["range", "deploy"])

    def get_range_status(self) -> str:
        """Return the current range status string.

        Ludus statuses include: ``SUCCESS``, ``DEPLOYING``, ``DESTROYING``,
        ``ERROR``, ``NEVER DEPLOYED``, etc.
        """
        result = self._run_ludus_cli(["range", "status", "--json"], check=False)
        if result.returncode != 0:
            return "UNKNOWN"
        try:
            data = json.loads(result.stdout)
            # The status field varies by Ludus version; try common locations
            if isinstance(data, dict):
                return data.get("result", {}).get("status", data.get("status", "UNKNOWN"))
            return "UNKNOWN"
        except (json.JSONDecodeError, KeyError):
            # Fall back to text parsing
            stdout = result.stdout.strip()
            for keyword in ("SUCCESS", "DEPLOYING", "ERROR", "NEVER DEPLOYED", "DESTROYING", "ABORTED"):
                if keyword in stdout.upper():
                    return keyword
            return "UNKNOWN"

    def wait_for_deployment(self, timeout: int = 3600, poll_interval: int = 30) -> None:
        """Poll ``ludus range status`` until deployment completes or times out.

        :param timeout: Maximum seconds to wait.
        :param poll_interval: Seconds between status checks.
        :raises RuntimeError: If deployment fails or times out.
        """
        self.logger.info(f"Ludus: waiting for range deployment (timeout={timeout}s)")
        elapsed = 0
        while elapsed < timeout:
            status = self.get_range_status()
            self.logger.info(f"Ludus: range status = {status} (elapsed {elapsed}s)")

            if status == "SUCCESS":
                self.logger.info("Ludus: range deployment completed successfully")
                return
            if status in ("ERROR", "ABORTED"):
                raise RuntimeError(f"Ludus range deployment failed with status: {status}")
            if status not in ("DEPLOYING", "UNKNOWN"):
                # Unexpected status -- keep waiting but warn
                self.logger.warning(f"Ludus: unexpected range status '{status}', continuing to wait")

            time.sleep(poll_interval)
            elapsed += poll_interval

        raise RuntimeError(f"Ludus range deployment timed out after {timeout}s (last status: {status})")

    def get_wireguard_config(self) -> Optional[str]:
        """Retrieve the user's WireGuard configuration from Ludus.

        :returns: WireGuard config string or ``None`` on failure.
        """
        result = self._run_ludus_cli(["user", "wireguard"], check=False)
        if result.returncode != 0:
            self.logger.warning(f"Ludus: failed to retrieve WireGuard config: {result.stderr}")
            return None
        config_text = result.stdout.strip()
        if not config_text or "Interface" not in config_text:
            self.logger.warning("Ludus: WireGuard config appears empty or invalid")
            return None
        return config_text

    def destroy_range(self) -> None:
        """Destroy the Ludus range (remove all VMs)."""
        self.logger.info("Ludus: destroying range")
        # Use --force to skip interactive confirmation (added in recent Ludus versions)
        result = self._run_ludus_cli(["range", "rm", "--force"], check=False)
        if result.returncode != 0:
            # Try without --force for older Ludus versions (pipe 'y' to stdin)
            self.logger.info("Ludus: retrying range rm with stdin confirmation")
            cmd = ["ludus", "range", "rm"]
            ludus_url = self.config.get("ludus", {}).get("ludus_url")
            if ludus_url:
                cmd = ["ludus", "--url", ludus_url, "range", "rm"]
            proc = subprocess.run(
                cmd,
                input="y\n",
                capture_output=True,
                text=True,
                timeout=300,
            )
            if proc.returncode != 0:
                self.logger.error(f"Ludus: range rm failed: {proc.stderr or proc.stdout}")
                raise RuntimeError(f"Failed to destroy Ludus range: {proc.stderr or proc.stdout}")
        self.logger.info("Ludus: range destroyed successfully")

    def install_ansible_roles(self, roles: list) -> None:
        """Install Ansible roles on the Ludus server.

        :param roles: List of role names (e.g. ``["p4t12ick.ludus_ar_splunk"]``).
        """
        for role in roles:
            self.logger.info(f"Ludus: installing Ansible role '{role}'")
            self._run_ludus_cli(["ansible", "roles", "add", role], check=False)

    def get_range_ips(self) -> dict:
        """Get a mapping of VM names to their IPs from Ludus.

        :returns: Dict of ``{vm_name: ip_address}`` or empty dict on failure.
        """
        result = self._run_ludus_cli(["range", "status", "--json"], check=False)
        if result.returncode != 0:
            return {}
        try:
            data = json.loads(result.stdout)
            vms = {}
            # Navigate the Ludus status JSON structure
            range_vms = []
            if isinstance(data, dict):
                range_vms = data.get("result", {}).get("vms", data.get("vms", []))
            if isinstance(data, list):
                range_vms = data
            for vm in range_vms:
                name = vm.get("name", vm.get("vm_name", ""))
                ip = vm.get("ip", vm.get("ip_address", ""))
                if name and ip:
                    vms[name] = ip
            return vms
        except (json.JSONDecodeError, KeyError, TypeError):
            return {}

    def get_ludus_url(self) -> str:
        """Return the Ludus API URL / WireGuard endpoint IP."""
        return self.config.get("ludus", {}).get("ludus_url", "https://198.51.100.1:8080")
