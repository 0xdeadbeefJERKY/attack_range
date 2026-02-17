"""
Attack Range Controller - Main orchestrator for Attack Range infrastructure.

This module provides the main controller class that orchestrates all Attack Range
operations using modular managers for different responsibilities.
"""

import os
import sys
import time
import uuid
from typing import Callable, Optional
from .logger import setup_logging

# Import managers
from .managers.config_manager import ConfigManager
from .managers.terraform_manager import TerraformManager
from .managers.ansible_manager import AnsibleManager
from .managers.ssh_manager import SSHManager
from .managers.backend_manager import BackendManager

# Import cloud providers
from .cloud_providers.aws_provider import AWSProvider
from .cloud_providers.azure_provider import AzureProvider
from .cloud_providers.gcp_provider import GCPProvider
from .cloud_providers.ludus_provider import LudusProvider

# Import utilities
from .utils import get_wireguard_config, get_wireguard_config_for_client


class AttackRangeController:
    """Controller for managing attack range infrastructure using Terraform and Ansible."""

    def __init__(self, config: dict, config_path: str = None):
        """
        Initialize the AttackRangeController.

        :param config: Configuration dictionary containing terraform and ansible settings
        :param config_path: Optional path to the config file (used for hash checking)
        """
        self.config = config
        self.config_path = config_path
        self.logger = setup_logging(
            os.path.join(os.path.dirname(__file__), "../attack_range.log"), "INFO"
        )

        # Detect cloud provider from config
        self.cloud_provider_name = config.get("general", {}).get("cloud_provider", "aws").lower()
        if self.cloud_provider_name not in ["aws", "azure", "gcp", "ludus"]:
            self.logger.error(f"Unsupported cloud provider: {self.cloud_provider_name}. Supported providers: aws, azure, gcp, ludus")
            sys.exit(1)

        # Set up directory paths
        self._setup_directories()

        # Initialize cloud provider
        self._init_cloud_provider()

        # Initialize managers
        self._init_managers()

    def _setup_directories(self) -> None:
        """Set up directory paths based on cloud provider."""
        # Set up terraform working directory based on cloud provider
        if self.cloud_provider_name == "azure":
            self.terraform_dir = os.path.join(os.path.dirname(__file__), "../terraform/azure")
        elif self.cloud_provider_name == "gcp":
            self.terraform_dir = os.path.join(os.path.dirname(__file__), "../terraform/gcp")
        elif self.cloud_provider_name == "ludus":
            self.terraform_dir = os.path.join(os.path.dirname(__file__), "../terraform/ludus")
        else:  # aws
            self.terraform_dir = os.path.join(os.path.dirname(__file__), "../terraform/aws")

        # Set up ansible directory
        self.ansible_dir = os.path.join(os.path.dirname(__file__), "../terraform/ansible")

        # Path to inventory file
        self.inventory_path = os.path.join(self.ansible_dir, "inventory.yaml")

        # Path to config folder for storing config files
        self.attack_range_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")

        # Path to ssh_keys folder
        self.ssh_keys_dir = os.path.join(os.path.dirname(__file__), "../ssh_keys")
        
        # Path to wireguard_config folder
        self.wireguard_config_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wireguard_config")

    def _init_cloud_provider(self) -> None:
        """Initialize the appropriate cloud provider."""
        if self.cloud_provider_name == "azure":
            self.cloud_provider = AzureProvider(self.config, self.logger)
        elif self.cloud_provider_name == "gcp":
            self.cloud_provider = GCPProvider(self.config, self.logger)
        elif self.cloud_provider_name == "ludus":
            self.cloud_provider = LudusProvider(self.config, self.logger)
        else:  # aws
            self.cloud_provider = AWSProvider(self.config, self.logger)

    def _init_managers(self) -> None:
        """Initialize all manager instances."""
        # Config manager
        self.config_manager = ConfigManager(
            self.config,
            self.config_path,
            self.attack_range_dir,
            self.logger
        )

        # Terraform manager
        self.terraform_manager = TerraformManager(
            self.terraform_dir,
            self.config,
            self.logger
        )

        # Ansible manager
        self.ansible_manager = AnsibleManager(
            self.ansible_dir,
            self.inventory_path,
            self.config,
            self.cloud_provider_name,
            self.logger
        )

        # SSH manager
        self.ssh_manager = SSHManager(
            self.ssh_keys_dir,
            self.config,
            self.cloud_provider,
            self.logger
        )

        # Backend manager
        self.backend_manager = BackendManager(
            self.terraform_dir,
            self.config,
            self.config_path,
            self.cloud_provider,
            self.logger
        )

    def build(self, two_phase: bool = False) -> None:
        """
        Build the attack range infrastructure.
        
        For CLI: builds everything in one go (two_phase=False)
        For API: builds in two phases - VPN first, then lab after VPN connection (two_phase=True)

        :param two_phase: If True, only build VPN phase and wait. If False, build everything.
        """
        self.logger.info("[action] > build\n")

        # Check if config file path is provided
        if not self.config_path:
            self.logger.error("Config file path not provided. Cannot proceed with build.")
            sys.exit(1)

        # Get or generate attack_range_id (preserve if already exists)
        attack_range_id = self.config_manager.get_or_create_attack_range_id()
        if attack_range_id == self.config.get("general", {}).get("attack_range_id"):
            # ID already existed, log that we're using it
            self.logger.info(f"Using existing attack_range_id: {attack_range_id}")
        else:
            # New ID was generated
            self.logger.info(f"Generated new attack_range_id: {attack_range_id}")

        # Update terraform variables with the updated config (including attack_range_id)
        self.terraform_manager.update_variables()

        # Validate zeek + Azure combination (must be called before other validations)
        self.config_manager.validate_zeek_azure_combination()

        # Validate zeek_monitor configuration
        self.config_manager.validate_zeek_monitor_config()

        # Check if attack range with this attack_range_id is already deployed
        config_file_path = os.path.join(self.attack_range_dir, f"{attack_range_id}.yml")
        if os.path.exists(config_file_path):
            # Load the existing config to check its status
            try:
                import yaml
                with open(config_file_path, 'r', encoding='utf-8') as f:
                    existing_config = yaml.safe_load(f)
                existing_status = existing_config.get("general", {}).get("status", "")
                
                # Only skip if status indicates infrastructure is already deployed
                if existing_status in ["running", "completed"]:
                    self.logger.warning(
                        f"An attack range with attack_range_id '{attack_range_id}' already exists "
                        f"with status '{existing_status}'. Skipping build to avoid duplicate infrastructure."
                    )
                    sys.exit(0)
                elif existing_status in ["error", "failed"]:
                    self.logger.info(
                        f"Found existing config with status '{existing_status}'. "
                        "Proceeding with new build attempt."
                    )
            except Exception as e:
                # If we can't read the config, log warning but continue
                self.logger.warning(
                    f"Could not read existing config file {config_file_path}: {e}. "
                    "Proceeding with build."
                )

        # Ludus uses its own build path (no Terraform)
        if self.cloud_provider_name == "ludus":
            router_public_ip, wireguard_config = self._build_ludus(attack_range_id)

            if two_phase:
                self.logger.info("\n" + "="*80)
                self.logger.info("Ludus deployment completed.")
                self.logger.info("="*80)
                self.logger.info(f"Attack Range ID: {attack_range_id}")
                self.logger.info(f"Ludus URL: {router_public_ip}")
                self.logger.info("="*80 + "\n")
                return router_public_ip, wireguard_config

            config_file_path = os.path.join(self.attack_range_dir, f"{attack_range_id}.yml")
            self.logger.info("\n" + "="*80)
            self.logger.info("Attack range built successfully via Ludus!")
            self.logger.info("="*80)
            self.logger.info(f"Attack Range ID: {attack_range_id}")
            self.logger.info(f"Ludus URL: {router_public_ip}")
            self.logger.info(f"Configuration saved to: {config_file_path}")
            self.logger.info("="*80 + "\n")
            return

        # Build VPN phase
        router_public_ip, wireguard_config = self.build_vpn_phase(attack_range_id)

        if two_phase:
            # For API: stop here and wait for VPN connection
            self.logger.info("\n" + "="*80)
            self.logger.info("VPN phase completed. Waiting for VPN connection...")
            self.logger.info("="*80)
            self.logger.info(f"Attack Range ID: {attack_range_id}")
            self.logger.info(f"Router Public IP: {router_public_ip}")
            self.logger.info(f"WireGuard config saved in config file: {self.config_path}")
            self.logger.info("="*80 + "\n")
            return router_public_ip, wireguard_config
        else:
            # For CLI: prompt user to connect to VPN, then continue with lab phase
            self.ansible_manager.prompt_vpn_connection()
            self.build_lab_phase(attack_range_id, router_public_ip)
            
            self.logger.info("\n" + "="*80)
            self.logger.info("Attack range built successfully!")
            self.logger.info("="*80)
            self.logger.info(f"Attack Range ID: {attack_range_id}")
            self.logger.info(f"Router Public IP: {router_public_ip}")
            self.logger.info(f"Configuration saved to: {config_file_path}")
            self.logger.info("="*80 + "\n")

    def build_vpn_phase(self, attack_range_id: str, abort_check: Optional[Callable[[], bool]] = None) -> tuple:
        """
        Build VPN infrastructure (Phase 1).
        
        :param attack_range_id: Attack range ID
        :param abort_check: Optional callable(); if it returns True, build is aborted (raises RuntimeError).
        :return: Tuple of (router_public_ip, wireguard_config)
        """
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")
        # Update status to build_vpn
        self.config_manager.update_status("build_vpn")

        # Setup SSH keys (generate locally, upload to cloud provider, update config)
        self.ssh_manager.setup_ssh_keys()
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        # Update terraform variables again after SSH key setup (config was updated)
        self.terraform_manager.update_variables()

        # Save config to config folder with attack_range_id as filename
        self.config_manager.save_config_to_attack_range(attack_range_id)

        # Dynamically extract and force install ansible galaxy roles from config.yml
        self.ansible_manager.update_ansible_galaxy_roles()
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        # Setup remote backend (S3/Azure Storage/GCS) if needed
        backend_was_created = self.backend_manager.setup_remote_backend()

        # If backend was just created, wait for AWS eventual consistency
        if backend_was_created:
            self.logger.info("Waiting 30 seconds for AWS backend resources to become fully available...")
            time.sleep(30)
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        # Initialize terraform
        self.terraform_manager.init(backend_was_created)
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        # Apply terraform
        self.terraform_manager.apply()
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        # Get router public IP from terraform output
        self.logger.info("Retrieving router public IP from terraform...")
        router_public_ip = self.terraform_manager.get_output("router_public_ip")

        if not router_public_ip:
            self.config_manager.update_status("error", error="Failed to get router public IP from terraform output", error_phase="build_vpn")
            self.logger.error("Failed to get router public IP from terraform output")
            raise RuntimeError("Failed to get router public IP from terraform output")

        self.logger.info(f"Router public IP: {router_public_ip}")

        # Update inventory.yaml with the public IP
        self.ansible_manager.update_inventory(router_public_ip)

        # Update VPN playbook with router public IP and physical interface
        self.ansible_manager.update_vpn_playbook(router_public_ip)

        # Wait for SSH to become available on the router
        if not self.ansible_manager.wait_for_ssh(router_public_ip):
            self.config_manager.update_status("error", error="SSH is not available on router", error_phase="build_vpn")
            self.logger.error("SSH is not available on router. Cannot proceed with VPN setup.")
            raise RuntimeError("SSH is not available on router")
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        # Run VPN ansible playbook (vpn.yaml) to configure WireGuard server
        self.logger.info("Running VPN setup playbook...")
        self.ansible_manager.run_ansible_playbook("vpn.yaml")
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")
        # Generate and run VPN config playbook (vpn_config.yaml) to generate WireGuard client config
        self.ansible_manager.update_vpn_config_playbook()
        self.logger.info("Running VPN config generation playbook...")
        self.ansible_manager.run_ansible_playbook("vpn_config.yaml")

        # Read WireGuard config and save to wireguard_config folder
        wireguard_config = get_wireguard_config(self.ansible_dir, attack_range_id, self.wireguard_config_dir)

        # Store wireguard_config in the config file (in general section as multiline YAML)
        if wireguard_config:
            self.config_manager.update_wireguard_config(wireguard_config)

        # Persist initial vpn_clients for idempotent sharing
        self.config_manager.update_vpn_clients([{"name": "client1", "address": "10.0.1.11/32"}])

        # Update status to wait_for_vpn
        self.config_manager.update_status("wait_for_vpn", router_public_ip=router_public_ip)

        return router_public_ip, wireguard_config

    def build_lab_phase(self, attack_range_id: str, router_public_ip: str = None, abort_check: Optional[Callable[[], bool]] = None) -> None:
        """
        Build lab infrastructure (Phase 2) - after VPN connection.
        
        :param attack_range_id: Attack range ID
        :param router_public_ip: Router public IP (if None, will be retrieved from terraform)
        :param abort_check: Optional callable(); if it returns True, build is aborted (raises RuntimeError).
        """
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")
        # Update status to build_lab
        self.config_manager.update_status("build_lab")

        # Get router public IP if not provided
        if not router_public_ip:
            router_public_ip = self.terraform_manager.get_output("router_public_ip")
            if not router_public_ip:
                self.config_manager.update_status("error", error="Failed to get router public IP from terraform output", error_phase="build_lab")
                self.logger.error("Failed to get router public IP from terraform output")
                raise RuntimeError("Failed to get router public IP from terraform output")
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        # Update inventory with attack_range servers
        self.ansible_manager.update_inventory_attack_range_servers()

        # Update lab.yaml playbook based on config
        self.ansible_manager.update_lab_playbook()

        # Update inventory password for Windows hosts
        self.ansible_manager.update_inventory_password()

        # Run lab ansible playbook (lab.yaml) to configure attack range servers
        self.logger.info("Running lab deployment playbook...")
        self.ansible_manager.run_ansible_playbook("lab.yaml")
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        # Update status to running
        self.config_manager.update_status("running", router_public_ip=router_public_ip)

    def _build_ludus(self, attack_range_id: str, abort_check: Optional[Callable[[], bool]] = None) -> tuple:
        """
        Build attack range using Ludus (bypasses Terraform entirely).

        Ludus handles VM provisioning, networking, WireGuard VPN, and
        Ansible role deployment through its own API/CLI.

        :param attack_range_id: Attack range ID
        :param abort_check: Optional abort callable
        :return: Tuple of (ludus_url, wireguard_config)
        """
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        self.config_manager.update_status("build_vpn")

        # Save config to config folder
        self.config_manager.save_config_to_attack_range(attack_range_id)
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        # Convert attack_range config to Ludus range config format
        self.logger.info("Converting attack_range config to Ludus range config...")
        ludus_config = self.cloud_provider.convert_to_ludus_config(self.config)
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        # Install required Ansible roles on Ludus server
        attack_range_servers = self.config.get("attack_range", [])
        roles_to_install = set()
        for server in attack_range_servers:
            for role_entry in server.get("roles", []):
                if isinstance(role_entry, dict):
                    role_name = role_entry.get("role", "")
                    if role_name:
                        roles_to_install.add(role_name.lower())
                elif isinstance(role_entry, str):
                    roles_to_install.add(role_entry.lower())
        if roles_to_install:
            self.logger.info(f"Installing {len(roles_to_install)} Ansible role(s) on Ludus server...")
            self.cloud_provider.install_ansible_roles(list(roles_to_install))
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        # Set range config in Ludus
        self.logger.info("Setting Ludus range configuration...")
        self.cloud_provider.set_range_config(ludus_config)
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        # Deploy the range
        self.logger.info("Deploying Ludus range...")
        self.config_manager.update_status("build_lab")
        self.cloud_provider.deploy_range()
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        # Wait for deployment to complete
        self.cloud_provider.wait_for_deployment()
        if abort_check and abort_check():
            raise RuntimeError("Build aborted")

        # Get WireGuard config from Ludus
        self.logger.info("Retrieving WireGuard configuration from Ludus...")
        wireguard_config = self.cloud_provider.get_wireguard_config()
        ludus_url = self.cloud_provider.get_ludus_url()

        # Store wireguard_config in the config file
        if wireguard_config:
            self.config_manager.update_wireguard_config(wireguard_config)

        # Update status to running
        self.config_manager.update_status("running", router_public_ip=ludus_url)

        return ludus_url, wireguard_config

    def import_ludus_range(self) -> dict:
        """
        Import an already-deployed Ludus range into attack_range management.

        Queries the Ludus server for the current range config, status, and
        WireGuard configuration, then constructs and saves an attack_range
        config file so the range appears in the dashboard and can be
        destroyed / used for simulations.

        :returns: Dict with ``attack_range_id``, ``status``, ``ludus_url``,
                  and ``wireguard_config``.
        :raises RuntimeError: If the Ludus range is not in a usable state.
        """
        self.logger.info("[action] > import ludus range\n")

        if self.cloud_provider_name != "ludus":
            raise RuntimeError("import_ludus_range is only supported for the Ludus provider")

        # 1. Verify the range is deployed
        status = self.cloud_provider.get_range_status()
        if status != "SUCCESS":
            raise RuntimeError(
                f"Cannot import Ludus range: current status is '{status}'. "
                "The range must be in SUCCESS state (fully deployed)."
            )
        self.logger.info(f"Ludus range status: {status}")

        # 2. Get the live range config from Ludus
        ludus_range_config = self.cloud_provider.get_range_config()

        # 3. If we don't already have attack_range servers from the template,
        #    reverse-map from the Ludus config
        if not self.config.get("attack_range") and ludus_range_config:
            self.logger.info("Reverse-mapping Ludus range config to attack_range format...")
            self.config["attack_range"] = self.cloud_provider.convert_ludus_config_to_attack_range(
                ludus_range_config
            )

        # 4. Ensure we have an attack_range_id
        attack_range_id = self.config.get("general", {}).get("attack_range_id")
        if not attack_range_id:
            attack_range_id = str(uuid.uuid4())
            if "general" not in self.config:
                self.config["general"] = {}
            self.config["general"]["attack_range_id"] = attack_range_id
        self.logger.info(f"Attack range ID: {attack_range_id}")

        # 5. Get WireGuard config
        wireguard_config = self.cloud_provider.get_wireguard_config()
        ludus_url = self.cloud_provider.get_ludus_url()

        # 6. Save the config as "running"
        self.config["general"]["status"] = "running"
        self.config["general"]["cloud_provider"] = "ludus"
        if ludus_url:
            self.config["general"]["router_public_ip"] = ludus_url
        if wireguard_config:
            self.config["general"]["wireguard_config"] = wireguard_config

        self.config_manager.save_config_to_attack_range(attack_range_id)
        self.logger.info(f"Ludus range imported as attack_range_id={attack_range_id}")

        return {
            "attack_range_id": attack_range_id,
            "status": "running",
            "ludus_url": ludus_url,
            "wireguard_config": wireguard_config,
        }

    def destroy(self) -> None:
        """
        Destroy the attack range infrastructure using terraform destroy (or Ludus CLI).
        """
        self.logger.info("[action] > destroy\n")

        if self.cloud_provider_name == "ludus":
            # Ludus: destroy the range via the Ludus CLI
            self.cloud_provider.destroy_range()
            self.logger.info("Ludus range destroyed successfully")
            if self.config_path:
                self.config_manager.remove_config()
            return

        # Setup remote backend (S3/Azure Storage/GCS) if needed
        self.backend_manager.setup_remote_backend()

        # Initialize terraform for destroy
        self.terraform_manager.init_for_destroy()

        # Destroy terraform infrastructure
        self.terraform_manager.destroy()

        self.logger.info("Attack range destroyed successfully")

        # Clean up SSH keys (delete from cloud provider)
        self.ssh_manager.cleanup_ssh_keys()

        # Clean up remote backend resources
        self.backend_manager.cleanup_remote_backend()

        # Remove config file with attack_range_id from config folder
        if self.config_path:
            self.config_manager.remove_config()

    def simulate(self, target: str, techniques: list) -> dict:
        """
        Run Atomic Red Team techniques against a target server.
        
        :param target: Target server name (must match a server name in attack_range config)
        :param techniques: List of MITRE ATT&CK technique IDs (e.g., ["T1003.001", "T1059.003"])
        :raises ValueError: If validation fails
        :raises RuntimeError: If simulation execution fails
        """
        self.logger.info(f"[action] > simulate on target: {target} with techniques: {techniques}\n")
        
        # Validate that attack range is running
        status = self.config.get("general", {}).get("status", "")
        if status not in ["running", "completed"]:
            error_msg = f"Cannot run simulation. Attack range status is: {status}. Must be 'running' or 'completed'."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Find the target server in config
        attack_range_config = self.config.get("attack_range", [])
        target_server = None
        for server in attack_range_config:
            if server.get("name") == target:
                target_server = server
                break
        
        if not target_server:
            available_servers = [s.get("name") for s in attack_range_config if s.get("name")]
            error_msg = f"Target server '{target}' not found in attack_range configuration."
            self.logger.error(error_msg)
            self.logger.info("Available servers:")
            for server in attack_range_config:
                self.logger.info(f"  - {server.get('name')}")
            raise ValueError(f"{error_msg} Available servers: {', '.join(available_servers) if available_servers else 'None'}")
        
        # Ensure inventory is up to date with attack range servers
        # We use private IPs from the inventory, so no terraform/router IP needed
        self.ansible_manager.update_inventory_attack_range_servers()
        self.ansible_manager.update_inventory_password()
        
        # Determine target host - use server name as inventory group
        # The target server name should match an inventory group name
        # Verify the inventory group exists
        import yaml
        with open(self.ansible_manager.inventory_path, 'r') as f:
            inventory = yaml.safe_load(f)
        
        if target not in inventory or 'hosts' not in inventory.get(target, {}):
            available_groups = [k for k, v in inventory.items() if isinstance(v, dict) and 'hosts' in v]
            error_msg = f"Inventory group '{target}' not found. Available groups: {', '.join(available_groups) if available_groups else 'None'}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Run the simulation playbook
        self.logger.info(f"Running Atomic Red Team simulation on {target}...")
        self.logger.info(f"Techniques: {', '.join(techniques)}")
        
        extra_vars = {
            "target_host": target,  # Use server name as inventory group
            "techniques": techniques
        }
        
        # Ensure the p4t12ick.ar_atomic_red_team role is installed
        if not self.ansible_manager._is_role_installed("p4t12ick.ar_atomic_red_team"):
            self.logger.info("Installing p4t12ick.ar_atomic_red_team role from Ansible Galaxy...")
            if not self.ansible_manager.install_ansible_galaxy_role("p4t12ick.ar_atomic_red_team"):
                error_msg = "Failed to install p4t12ick.ar_atomic_red_team role"
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)
        
        # Run the playbook using the safe method that raises exceptions instead of calling sys.exit
        execution_output = self.ansible_manager.run_ansible_playbook_safe("simulate_atomic_red_team.yml", extra_vars=extra_vars)
        
        self.logger.info(f"\nSimulation completed successfully on {target}")
        
        # Log execution output for debugging
        if execution_output:
            self.logger.info(f"Execution output captured: {execution_output}")
        else:
            self.logger.warning("No execution output was captured from the playbook")
        
        # Return execution output for API response
        return execution_output

    def share(self, name: str) -> str:
        """
        Share the attack range by generating a new WireGuard client config for the given name.
        Runs the VPN playbooks with updated vpn_clients (existing + new), fetches the new
        client's config, persists it in general.sharing and general.vpn_clients, and returns it.

        :param name: Share name (used as client name, e.g. "alice")
        :return: WireGuard config string for the new client
        :raises ValueError: If validation fails (status, duplicate name, missing router IP)
        :raises RuntimeError: If playbook or file read fails
        """
        self.logger.info(f"[action] > share with name: {name}\n")

        status = self.config.get("general", {}).get("status", "")
        if status not in ["wait_for_vpn", "running"]:
            raise ValueError(
                f"Cannot share. Attack range status is '{status}'. Must be 'wait_for_vpn' or 'running'."
            )

        if not name or not str(name).strip():
            raise ValueError("Share name is required and must be non-empty.")

        name = str(name).strip()

        vpn_clients = self.config.get("general", {}).get("vpn_clients")
        if not vpn_clients:
            vpn_clients = [{"name": "client1", "address": "10.0.1.11/32"}]

        if any(c.get("name") == name for c in vpn_clients):
            raise ValueError(f"A share with the name '{name}' already exists.")

        router_public_ip = self.config.get("general", {}).get("router_public_ip")
        if not router_public_ip:
            raise ValueError("Router public IP not available. Cannot run VPN playbooks.")

        next_octet = 11 + len(vpn_clients)
        new_client = {"name": name, "address": f"10.0.1.{next_octet}/32"}
        new_vpn_clients = list(vpn_clients) + [new_client]

        self.ansible_manager.update_inventory(router_public_ip)
        self.ansible_manager.update_vpn_playbook(router_public_ip)
        self.ansible_manager.update_vpn_config_playbook()

        extra_vars = {"vpn_clients": new_vpn_clients}

        self.logger.info("Running VPN deploy playbook with updated vpn_clients...")
        self.ansible_manager.run_ansible_playbook_safe("vpn.yaml", extra_vars=extra_vars)

        self.logger.info("Running VPN get_config playbook...")
        self.ansible_manager.run_ansible_playbook_safe("vpn_config.yaml", extra_vars=extra_vars)

        config_content = get_wireguard_config_for_client(self.ansible_dir, name)
        if not config_content:
            raise RuntimeError(f"WireGuard config for client '{name}' was not generated.")

        self.config_manager.update_sharing(name, config_content)
        self.config_manager.update_vpn_clients(new_vpn_clients)

        self.logger.info(f"Share '{name}' created successfully. Config saved to general.sharing.")
        return config_content
